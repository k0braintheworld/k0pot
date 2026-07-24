package trampa

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// MySQL finge un servidor MySQL abierto.
//
// Es de los puertos de base de datos mas escaneados: los bots buscan MySQL
// con contrasena floja o sin ella para robar datos o dejar una tarea que
// mine. La contrasena viaja cifrada con la sal que mandamos, asi que no se
// puede recuperar en claro; lo que si se captura es el usuario que prueban
// y la base de datos a la que apuntan, que ya dice a que vienen.
type MySQL struct{}

func (*MySQL) ID() string            { return "mysql" }
func (*MySQL) Nombre() string        { return "MySQL" }
func (*MySQL) PuertoPorDefecto() int { return 3306 }
func (*MySQL) Descripcion() string {
	return "Finge una base de datos MySQL abierta. Captura el usuario y la base " +
		"que prueban los bots que buscan bases de datos mal protegidas."
}

func (t *MySQL) Servir(ctx context.Context, direccion string, reg Registrar) error {
	return servirTCP(ctx, direccion, func(conn net.Conn) {
		reg(evento(t.ID(), "mysql", ipDe(conn), model.Conexion,
			map[string]string{"puerto": puertoDe(direccion)}))

		// Saludo del servidor (HandshakeV10): sin el, ningun cliente MySQL
		// llega a mandar su login.
		if _, err := conn.Write(saludoMySQL()); err != nil {
			return
		}

		lector := bufio.NewReader(&lectorLimitado{r: conn, quedan: maxPorConexion})
		carga, err := leerPaqueteMySQL(lector)
		if err != nil {
			return
		}

		usuario, bd := loginMySQL(carga)
		if usuario != "" || bd != "" {
			det := map[string]string{"usuario": recortar(usuario, 128)}
			if bd != "" {
				det["base_datos"] = recortar(bd, 128)
			}
			reg(evento(t.ID(), "mysql", ipDe(conn), model.LoginFallido, det))
		}

		// "Access denied": el bot se va sabiendo que la credencial no valia,
		// que es justo lo que un MySQL real le diria.
		conn.Write(errMySQL())
	})
}

// saludoMySQL arma el paquete de bienvenida que espera cualquier cliente.
// La sal es fija a proposito: la contrasena resultante es irrecuperable de
// todos modos, y no complicar el codigo con aleatoriedad no cambia nada.
func saludoMySQL() []byte {
	var p bytes.Buffer
	p.WriteByte(10) // protocolo v10
	p.WriteString("8.0.36")
	p.WriteByte(0)
	p.Write([]byte{0x01, 0x00, 0x00, 0x00})     // id de conexion
	p.Write([]byte("k0potSal"))                 // sal, parte 1 (8 bytes)
	p.WriteByte(0)                              // relleno
	p.Write([]byte{0x01, 0x82})                 // flags bajos: LONG_PASSWORD|PROTOCOL_41|SECURE_CONNECTION
	p.WriteByte(0x21)                          // juego de caracteres utf8
	p.Write([]byte{0x02, 0x00})                 // estado: autocommit
	p.Write([]byte{0x08, 0x00})                 // flags altos: PLUGIN_AUTH
	p.WriteByte(21)                            // longitud de los datos de auth
	p.Write(make([]byte, 10))                   // reservado
	p.Write([]byte("k0potSalParte2"[:12]))      // sal, parte 2 (12 bytes)
	p.WriteByte(0)
	p.WriteString("mysql_native_password")
	p.WriteByte(0)
	return conPaqueteMySQL(p.Bytes(), 0)
}

// errMySQL es un paquete de error "Access denied" con secuencia 2, la que
// toca despues del login del cliente (secuencia 1).
func errMySQL() []byte {
	var p bytes.Buffer
	p.WriteByte(0xff)
	p.Write([]byte{0x15, 0x04}) // codigo 1045
	p.WriteByte('#')
	p.WriteString("28000") // estado SQL
	p.WriteString("Access denied for user")
	return conPaqueteMySQL(p.Bytes(), 2)
}

// conPaqueteMySQL antepone la cabecera de 4 bytes: 3 de longitud en little
// endian y 1 de numero de secuencia.
func conPaqueteMySQL(carga []byte, seq byte) []byte {
	cab := make([]byte, 4)
	binary.LittleEndian.PutUint32(cab, uint32(len(carga)))
	cab[3] = seq
	return append(cab, carga...)
}

// leerPaqueteMySQL lee un paquete con su cabecera y devuelve la carga.
func leerPaqueteMySQL(r io.Reader) ([]byte, error) {
	cab := make([]byte, 4)
	if _, err := io.ReadFull(r, cab); err != nil {
		return nil, err
	}
	n := int(cab[0]) | int(cab[1])<<8 | int(cab[2])<<16
	if n <= 0 || n > maxPorConexion {
		return nil, io.ErrUnexpectedEOF
	}
	carga := make([]byte, n)
	if _, err := io.ReadFull(r, carga); err != nil {
		return nil, err
	}
	return carga, nil
}

// loginMySQL saca el usuario y, si viene, la base de datos del paquete de
// respuesta del cliente. La cabecera fija son 32 bytes: 4 de flags, 4 de
// tamano maximo, 1 de juego de caracteres y 23 reservados; luego va el
// usuario terminado en null.
func loginMySQL(carga []byte) (usuario, bd string) {
	if len(carga) < 33 {
		return "", ""
	}
	flags := binary.LittleEndian.Uint32(carga[0:4])
	resto := carga[32:]
	fin := bytes.IndexByte(resto, 0)
	if fin < 0 {
		return "", ""
	}
	usuario = string(resto[:fin])
	resto = resto[fin+1:]

	// La respuesta de auth va por delante de la base de datos, con longitud
	// codificada en el primer byte. Saltarla nos deja en el nombre de la bd.
	if len(resto) > 0 {
		n := int(resto[0])
		if 1+n <= len(resto) {
			resto = resto[1+n:]
		}
	}
	// CLIENT_CONNECT_WITH_DB = 0x08: solo entonces viene la base de datos.
	if flags&0x08 != 0 && len(resto) > 0 {
		if fin := bytes.IndexByte(resto, 0); fin >= 0 {
			bd = string(resto[:fin])
		} else {
			bd = string(resto)
		}
	}
	return usuario, bd
}
