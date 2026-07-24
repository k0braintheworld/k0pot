package trampa

import (
	"context"
	"io"
	"net"
	"strings"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// VNC finge un escritorio VNC.
//
// El VNC abierto o con contrasena floja es un objetivo recurrente. En modo
// ligero no se saca la contrasena (VNC la prueba con un reto cifrado, no en
// claro), pero el saludo del protocolo revela la version del cliente, que
// distingue a un forzador de VNC de un simple escaner de puertos.
type VNC struct{}

func (*VNC) ID() string            { return "vnc" }
func (*VNC) Nombre() string        { return "VNC" }
func (*VNC) PuertoPorDefecto() int { return 5900 }
func (*VNC) Descripcion() string {
	return "Finge un escritorio remoto VNC. Captura la conexion y la version del " +
		"cliente de quien busca pantallas VNC abiertas o con contrasena debil."
}

func (t *VNC) Servir(ctx context.Context, direccion string, reg Registrar) error {
	return servirTCP(ctx, direccion, func(conn net.Conn) {
		det := map[string]string{"puerto": puertoDe(direccion)}

		// El servidor VNC habla primero, con su version del protocolo RFB.
		if _, err := conn.Write([]byte("RFB 003.008\n")); err != nil {
			reg(evento(t.ID(), "vnc", ipDe(conn), model.Conexion, det))
			return
		}
		// El cliente responde con su version, tambien de 12 bytes.
		version := make([]byte, 12)
		if _, err := io.ReadFull(conn, version); err == nil {
			if v := strings.TrimSpace(string(version)); strings.HasPrefix(v, "RFB") {
				det["cliente"] = recortar(v, 32)
			}
		}
		reg(evento(t.ID(), "vnc", ipDe(conn), model.Conexion, det))

		// Se le ofrece "VNC Authentication" (tipo 2) y se le manda un reto,
		// para que un cliente real siga y se retrate como intento de acceso,
		// no como un simple toque de puerto.
		conn.Write([]byte{0x01, 0x02})     // una opcion: VNC auth
		conn.Read(make([]byte, 1))         // tipo elegido
		conn.Write(make([]byte, 16))       // reto de 16 bytes
	})
}
