package trampa

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// MySQL finge un servidor MySQL abierto y, ademas, DEBIL: acepta el login y
// deja "entrar". Asi el bot que buscaba una base mal protegida se anima a
// hurgar, y capturamos las consultas que lanza. Lo que sirve es botin falso
// -tablas con nombres jugosos y filas con credenciales SENUELO-, de modo que
// exfiltrar estos datos y reutilizarlos mas tarde dispara la alarma. La
// contrasena viaja cifrada con nuestra sal (irrecuperable en claro), pero el
// usuario, la base y cada consulta se anotan enteros.
type MySQL struct{}

func (*MySQL) ID() string            { return "mysql" }
func (*MySQL) Nombre() string        { return "MySQL" }
func (*MySQL) PuertoPorDefecto() int { return 3306 }
func (*MySQL) Descripcion() string {
	return "Finge una base de datos MySQL abierta y debil: acepta el login, sirve " +
		"tablas con datos falsos y credenciales senuelo, y anota cada consulta."
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
			// LoginExitoso a proposito: le dejamos pasar para ver que hace.
			reg(evento(t.ID(), "mysql", ipDe(conn), model.LoginExitoso, det))
		}

		// OK: el login "cuela" y entramos en la fase de comandos.
		if _, err := conn.Write(okMySQL(2)); err != nil {
			return
		}

		for {
			conn.SetDeadline(time.Now().Add(plazoLectura))
			carga, err := leerPaqueteMySQL(lector)
			if err != nil || len(carga) == 0 {
				return
			}
			switch carga[0] {
			case 0x01: // COM_QUIT
				return
			case 0x03: // COM_QUERY
				sql := string(carga[1:])
				reg(evento(t.ID(), "mysql", ipDe(conn), model.ComandoEjecutado,
					map[string]string{"comando": recortar(sql, 512)}))
				conn.Write(resultadoMySQL(tablaParaConsulta(sql, "8.0.36"), 1))
			default:
				// COM_PING, COM_INIT_DB y demas: un OK y a seguir.
				conn.Write(okMySQL(1))
			}
		}
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
	p.Write([]byte{0x01, 0x00, 0x00, 0x00}) // id de conexion
	p.Write([]byte("k0potSal"))             // sal, parte 1 (8 bytes)
	p.WriteByte(0)                          // relleno
	p.Write([]byte{0x01, 0x82})             // flags bajos: LONG_PASSWORD|PROTOCOL_41|SECURE_CONNECTION
	p.WriteByte(0x21)                       // juego de caracteres utf8
	p.Write([]byte{0x02, 0x00})             // estado: autocommit
	p.Write([]byte{0x08, 0x00})             // flags altos: PLUGIN_AUTH
	p.WriteByte(21)                         // longitud de los datos de auth
	p.Write(make([]byte, 10))               // reservado
	p.Write([]byte("k0potSalParte2"[:12]))  // sal, parte 2 (12 bytes)
	p.WriteByte(0)
	p.WriteString("mysql_native_password")
	p.WriteByte(0)
	return conPaqueteMySQL(p.Bytes(), 0)
}

// okMySQL es un paquete OK: header 0x00, filas afectadas 0, ultimo id 0,
// estado autocommit y 0 avisos.
func okMySQL(seq byte) []byte {
	return conPaqueteMySQL([]byte{0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}, seq)
}

// resultadoMySQL codifica una tabla como un conjunto de resultados del
// protocolo clasico (con paquetes EOF, que es lo que anunciamos en el saludo):
// cuenta de columnas, definicion de cada una, EOF, una fila por registro y EOF.
func resultadoMySQL(t tablaFalsa, seq byte) []byte {
	var out []byte
	añade := func(carga []byte) {
		out = append(out, conPaqueteMySQL(carga, seq)...)
		seq++
	}
	añade(lenencEntero(uint64(len(t.Columnas))))
	for _, col := range t.Columnas {
		añade(colDefMySQL(col))
	}
	añade(eofMySQL())
	for _, fila := range t.Filas {
		var row []byte
		for _, v := range fila {
			row = append(row, lenencCadena(v)...)
		}
		añade(row)
	}
	añade(eofMySQL())
	return out
}

// eofMySQL es un paquete EOF: 0xfe, 0 avisos, estado autocommit.
func eofMySQL() []byte { return []byte{0xfe, 0x00, 0x00, 0x02, 0x00} }

// colDefMySQL arma la definicion de una columna (formato del protocolo 41),
// toda de tipo cadena, que es lo que necesitan estos resultados de texto.
func colDefMySQL(nombre string) []byte {
	var b []byte
	b = append(b, lenencCadena("def")...)       // catalogo
	b = append(b, lenencCadena("acme_prod")...) // esquema
	b = append(b, lenencCadena("users")...)     // tabla
	b = append(b, lenencCadena("users")...)     // tabla original
	b = append(b, lenencCadena(nombre)...)      // nombre
	b = append(b, lenencCadena(nombre)...)      // nombre original
	b = append(b, 0x0c)                         // longitud de los campos fijos
	b = append(b, 0x21, 0x00)                   // juego de caracteres utf8
	b = append(b, 0xff, 0x00, 0x00, 0x00)       // longitud de columna
	b = append(b, 0xfd)                         // tipo VAR_STRING
	b = append(b, 0x00, 0x00)                   // flags
	b = append(b, 0x00)                         // decimales
	b = append(b, 0x00, 0x00)                   // relleno
	return b
}

// lenencEntero codifica un entero pequeno en el formato "length-encoded" de
// MySQL. Solo se usan cuentas pequenas, asi que basta el caso de un byte.
func lenencEntero(n uint64) []byte {
	if n < 251 {
		return []byte{byte(n)}
	}
	b := make([]byte, 9)
	b[0] = 0xfe
	binary.LittleEndian.PutUint64(b[1:], n)
	return b
}

// lenencCadena codifica una cadena precedida de su longitud length-encoded.
func lenencCadena(s string) []byte {
	return append(lenencEntero(uint64(len(s))), s...)
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
