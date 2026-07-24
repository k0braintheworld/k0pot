package trampa

import (
	"bytes"
	"context"
	"io"
	"net"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// RDP finge el escritorio remoto de Windows.
//
// Es de los puertos mas machacados de internet: las bandas de ransomware
// fuerzan RDP a lo bruto buscando entrar. En modo ligero no se captura la
// contrasena -eso exige emular la negociacion TLS y NLA entera-, pero si el
// usuario que viene en el "cookie" de la primera peticion, que muchos
// clientes mandan en claro. Aunque solo sea la conexion, confirma que
// alguien esta martilleando RDP.
type RDP struct{}

func (*RDP) ID() string            { return "rdp" }
func (*RDP) Nombre() string        { return "RDP" }
func (*RDP) PuertoPorDefecto() int { return 3389 }
func (*RDP) Descripcion() string {
	return "Finge un escritorio remoto de Windows (RDP), de los puertos mas " +
		"forzados por el ransomware. Captura la conexion y, si viene, el usuario."
}

func (t *RDP) Servir(ctx context.Context, direccion string, reg Registrar) error {
	return servirTCP(ctx, direccion, func(conn net.Conn) {
		reg(evento(t.ID(), "rdp", ipDe(conn), model.Conexion,
			map[string]string{"puerto": puertoDe(direccion)}))

		// La primera peticion RDP (X.224 Connection Request) suele traer
		// "Cookie: mstshash=USUARIO". Se lee el primer paquete y se busca.
		paquete := leerPaqueteTPKT(conn)
		if usuario := mstshash(paquete); usuario != "" {
			reg(evento(t.ID(), "rdp", ipDe(conn), model.LoginFallido,
				map[string]string{"usuario": recortar(usuario, 128)}))
		}
	})
}

// leerPaqueteTPKT lee un paquete con cabecera TPKT: version(1) reservado(1)
// longitud(2, big endian, incluye la cabecera). Si no cuadra, devuelve lo
// que haya leido: un escaner de puertos manda basura y tambien es un dato.
func leerPaqueteTPKT(conn net.Conn) []byte {
	cab := make([]byte, 4)
	if _, err := io.ReadFull(conn, cab); err != nil {
		return cab
	}
	if cab[0] != 0x03 {
		return cab // no es TPKT
	}
	total := int(cab[2])<<8 | int(cab[3])
	n := total - 4
	if n <= 0 || n > maxPorConexion {
		return cab
	}
	resto := make([]byte, n)
	if _, err := io.ReadFull(conn, resto); err != nil {
		return append(cab, resto...)
	}
	return append(cab, resto...)
}

// mstshash saca el usuario del cookie de la peticion RDP.
func mstshash(paquete []byte) string {
	marca := []byte("mstshash=")
	i := bytes.Index(paquete, marca)
	if i < 0 {
		return ""
	}
	resto := paquete[i+len(marca):]
	// El cookie acaba en \r\n; si no lo encuentra, corta en el primer
	// caracter de control.
	fin := bytes.IndexAny(resto, "\r\n")
	if fin < 0 {
		fin = len(resto)
	}
	return string(resto[:fin])
}
