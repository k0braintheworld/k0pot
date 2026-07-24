package trampa

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// Postgres finge un PostgreSQL abierto.
//
// A diferencia de MySQL, aqui si se captura la contrasena en claro: se le
// pide al cliente autenticacion en texto plano (que es una opcion legitima
// del protocolo) y el bot la manda tal cual. Se queda usuario, base de
// datos y contrasena, justo lo que estaba probando.
type Postgres struct{}

func (*Postgres) ID() string            { return "postgres" }
func (*Postgres) Nombre() string        { return "PostgreSQL" }
func (*Postgres) PuertoPorDefecto() int { return 5432 }
func (*Postgres) Descripcion() string {
	return "Finge una base de datos PostgreSQL abierta. Captura usuario, base de " +
		"datos y contrasena en claro de los bots que buscan bases mal protegidas."
}

func (t *Postgres) Servir(ctx context.Context, direccion string, reg Registrar) error {
	return servirTCP(ctx, direccion, func(conn net.Conn) {
		reg(evento(t.ID(), "postgres", ipDe(conn), model.Conexion,
			map[string]string{"puerto": puertoDe(direccion)}))

		lector := &lectorLimitado{r: conn, quedan: maxPorConexion}

		// El cliente habla primero. Puede empezar pidiendo TLS (SSLRequest):
		// se le dice que no con una 'N' y vuelve a mandar el arranque normal.
		cuerpo, err := leerArranquePG(lector)
		if err != nil {
			return
		}
		if esSSLRequestPG(cuerpo) {
			if _, err := conn.Write([]byte{'N'}); err != nil {
				return
			}
			cuerpo, err = leerArranquePG(lector)
			if err != nil {
				return
			}
		}

		usuario, bd := paramsArranquePG(cuerpo)

		// AuthenticationCleartextPassword: 'R' + longitud(8) + codigo 3. Es
		// lo que hace que el cliente suelte la contrasena en texto plano.
		conn.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 3})

		pass, err := leerMensajePG(lector, 'p')
		det := map[string]string{"usuario": recortar(usuario, 128)}
		if bd != "" {
			det["base_datos"] = recortar(bd, 128)
		}
		if err == nil {
			det["password"] = recortar(string(bytes.TrimRight(pass, "\x00")), 128)
		}
		if usuario != "" || det["password"] != "" {
			reg(evento(t.ID(), "postgres", ipDe(conn), model.LoginFallido, det))
		}

		// ErrorResponse: contrasena invalida. El bot se va como de un
		// Postgres real que le ha dado un portazo.
		conn.Write(errorPG("28P01", "password authentication failed"))
	})
}

// leerArranquePG lee un mensaje sin tipo (StartupMessage o SSLRequest):
// 4 bytes de longitud, que incluye esos 4, y luego el cuerpo.
func leerArranquePG(r io.Reader) ([]byte, error) {
	cab := make([]byte, 4)
	if _, err := io.ReadFull(r, cab); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint32(cab)) - 4
	if n <= 0 || n > maxPorConexion {
		return nil, io.ErrUnexpectedEOF
	}
	cuerpo := make([]byte, n)
	if _, err := io.ReadFull(r, cuerpo); err != nil {
		return nil, err
	}
	return cuerpo, nil
}

// esSSLRequestPG reconoce el codigo magico de la peticion de TLS.
func esSSLRequestPG(cuerpo []byte) bool {
	return len(cuerpo) == 4 && binary.BigEndian.Uint32(cuerpo) == 80877103
}

// paramsArranquePG saca usuario y base de datos de los pares clave-valor
// del StartupMessage. Van despues de los 4 bytes de version de protocolo,
// como cadenas terminadas en null y en pares seguidos.
func paramsArranquePG(cuerpo []byte) (usuario, bd string) {
	if len(cuerpo) < 4 {
		return "", ""
	}
	partes := bytes.Split(cuerpo[4:], []byte{0})
	for i := 0; i+1 < len(partes); i += 2 {
		clave := string(partes[i])
		valor := string(partes[i+1])
		switch clave {
		case "user":
			usuario = valor
		case "database":
			bd = valor
		}
	}
	return usuario, bd
}

// leerMensajePG lee un mensaje con tipo (1 byte) + longitud (4, se incluye)
// y comprueba que el tipo sea el esperado.
func leerMensajePG(r io.Reader, tipo byte) ([]byte, error) {
	cab := make([]byte, 5)
	if _, err := io.ReadFull(r, cab); err != nil {
		return nil, err
	}
	if cab[0] != tipo {
		return nil, io.ErrUnexpectedEOF
	}
	n := int(binary.BigEndian.Uint32(cab[1:])) - 4
	if n < 0 || n > maxPorConexion {
		return nil, io.ErrUnexpectedEOF
	}
	cuerpo := make([]byte, n)
	if _, err := io.ReadFull(r, cuerpo); err != nil {
		return nil, err
	}
	return cuerpo, nil
}

// errorPG arma un ErrorResponse minimo: severidad, codigo SQLSTATE y
// mensaje, cada campo con su etiqueta de un byte y terminado en null.
func errorPG(codigo, mensaje string) []byte {
	var b bytes.Buffer
	b.WriteByte('S')
	b.WriteString("FATAL")
	b.WriteByte(0)
	b.WriteByte('C')
	b.WriteString(codigo)
	b.WriteByte(0)
	b.WriteByte('M')
	b.WriteString(mensaje)
	b.WriteByte(0)
	b.WriteByte(0) // fin de los campos

	var m bytes.Buffer
	m.WriteByte('E')
	long := make([]byte, 4)
	binary.BigEndian.PutUint32(long, uint32(b.Len()+4))
	m.Write(long)
	m.Write(b.Bytes())
	return m.Bytes()
}
