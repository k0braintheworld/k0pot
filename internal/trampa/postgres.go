package trampa

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// Postgres finge un PostgreSQL abierto y DEBIL: pide la contrasena en claro
// (opcion legitima del protocolo), la anota, y luego deja "entrar" para ver
// que consulta el bot. Sirve botin falso -tablas jugosas con credenciales
// SENUELO- de modo que exfiltrarlo y reutilizarlo dispara la alarma. Se quedan
// usuario, base, contrasena en claro y cada consulta.
type Postgres struct{}

func (*Postgres) ID() string            { return "postgres" }
func (*Postgres) Nombre() string        { return "PostgreSQL" }
func (*Postgres) PuertoPorDefecto() int { return 5432 }
func (*Postgres) Descripcion() string {
	return "Finge una base de datos PostgreSQL abierta y debil: captura usuario, " +
		"base y contrasena en claro, deja entrar y sirve tablas con datos falsos " +
		"y credenciales senuelo, anotando cada consulta."
}

const versionPG = "PostgreSQL 14.11 on x86_64-pc-linux-gnu, compiled by gcc 12.2.0, 64-bit"

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
			// LoginExitoso a proposito: le dejamos pasar para ver que hace.
			reg(evento(t.ID(), "postgres", ipDe(conn), model.LoginExitoso, det))
		}

		// El login "cuela": autenticacion aceptada y listo para consultas.
		conn.Write([]byte{'R', 0, 0, 0, 8, 0, 0, 0, 0}) // AuthenticationOk
		conn.Write(parametroPG("server_version", "14.11"))
		conn.Write(listoPG())

		for {
			conn.SetDeadline(time.Now().Add(plazoLectura))
			tipo, cuerpo, err := leerMensajeTipadoPG(lector)
			if err != nil {
				return
			}
			switch tipo {
			case 'X': // Terminate
				return
			case 'Q': // Simple Query
				sql := string(bytes.TrimRight(cuerpo, "\x00"))
				reg(evento(t.ID(), "postgres", ipDe(conn), model.ComandoEjecutado,
					map[string]string{"comando": recortar(sql, 512)}))
				tabla := tablaParaConsulta(sql, versionPG)
				conn.Write(resultadoPG(tabla))
				conn.Write(completadoPG("SELECT", len(tabla.Filas)))
				conn.Write(listoPG())
			default:
				// Protocolo extendido u otro mensaje: se le dice que puede
				// seguir. Mejor eso que cortar y perder la sesion.
				conn.Write(listoPG())
			}
		}
	})
}

// --- Mensajes del servidor -------------------------------------------------

// mensajePG antepone el tipo (1 byte) y la longitud (4, se incluye a si misma).
func mensajePG(tipo byte, cuerpo []byte) []byte {
	out := make([]byte, 5, 5+len(cuerpo))
	out[0] = tipo
	binary.BigEndian.PutUint32(out[1:], uint32(len(cuerpo)+4))
	return append(out, cuerpo...)
}

// listoPG es ReadyForQuery en estado "ocioso" ('I').
func listoPG() []byte { return mensajePG('Z', []byte{'I'}) }

// parametroPG es un ParameterStatus (clave y valor de configuracion).
func parametroPG(clave, valor string) []byte {
	var b bytes.Buffer
	b.WriteString(clave)
	b.WriteByte(0)
	b.WriteString(valor)
	b.WriteByte(0)
	return mensajePG('S', b.Bytes())
}

// resultadoPG codifica una tabla como RowDescription seguida de una DataRow
// por registro. Todas las columnas se declaran de tipo texto (OID 25).
func resultadoPG(t tablaFalsa) []byte {
	var desc bytes.Buffer
	binary.Write(&desc, binary.BigEndian, int16(len(t.Columnas)))
	for _, col := range t.Columnas {
		desc.WriteString(col)
		desc.WriteByte(0)
		binary.Write(&desc, binary.BigEndian, int32(0))  // OID de la tabla
		binary.Write(&desc, binary.BigEndian, int16(0))  // numero de columna
		binary.Write(&desc, binary.BigEndian, int32(25)) // OID de tipo: text
		binary.Write(&desc, binary.BigEndian, int16(-1)) // longitud de tipo
		binary.Write(&desc, binary.BigEndian, int32(-1)) // modificador de tipo
		binary.Write(&desc, binary.BigEndian, int16(0))  // formato: texto
	}
	out := mensajePG('T', desc.Bytes())

	for _, fila := range t.Filas {
		var row bytes.Buffer
		binary.Write(&row, binary.BigEndian, int16(len(fila)))
		for _, v := range fila {
			binary.Write(&row, binary.BigEndian, int32(len(v)))
			row.WriteString(v)
		}
		out = append(out, mensajePG('D', row.Bytes())...)
	}
	return out
}

// completadoPG es CommandComplete con la etiqueta del comando ("SELECT n").
func completadoPG(etiqueta string, n int) []byte {
	return mensajePG('C', append([]byte(fmt.Sprintf("%s %d", etiqueta, n)), 0))
}

// --- Lectura de mensajes del cliente ---------------------------------------

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
	got, cuerpo, err := leerMensajeTipadoPG(r)
	if err != nil {
		return nil, err
	}
	if got != tipo {
		return nil, io.ErrUnexpectedEOF
	}
	return cuerpo, nil
}

// leerMensajeTipadoPG lee un mensaje con tipo y devuelve su tipo y su cuerpo.
func leerMensajeTipadoPG(r io.Reader) (byte, []byte, error) {
	cab := make([]byte, 5)
	if _, err := io.ReadFull(r, cab); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(cab[1:])) - 4
	if n < 0 || n > maxPorConexion {
		return 0, nil, io.ErrUnexpectedEOF
	}
	cuerpo := make([]byte, n)
	if _, err := io.ReadFull(r, cuerpo); err != nil {
		return 0, nil, err
	}
	return cab[0], cuerpo, nil
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
	return mensajePG('E', b.Bytes())
}
