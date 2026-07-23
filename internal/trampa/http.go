package trampa

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// HTTP finge ser un servidor web corriente.
//
// Es la trampa de mas volumen con diferencia: internet esta lleno de bots
// probando rutas de administracion, ficheros de configuracion olvidados y
// exploits recien publicados. Cada peticion dice mucho de quien la manda.
type HTTP struct{}

func (*HTTP) ID() string            { return "http" }
func (*HTTP) Nombre() string        { return "HTTP" }
func (*HTTP) PuertoPorDefecto() int { return 8081 }
func (*HTTP) Descripcion() string {
	return "Finge un servidor web. Captura escaneos de rutas, intentos de explotar " +
		"vulnerabilidades conocidas y bots que buscan paneles de administracion."
}

// respuesta imita a un nginx cualquiera. Interesa parecer un servidor real
// y aburrido: si respondiera algo raro, los bots dejarian de insistir.
const cuerpoHTTP = `<!doctype html>
<html><head><title>Welcome to nginx!</title></head>
<body><h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed.</p>
</body></html>
`

func (t *HTTP) Servir(ctx context.Context, direccion string, reg Registrar) error {
	return servirTCP(ctx, direccion, func(conn net.Conn) {
		lector := bufio.NewReader(&lectorLimitado{r: conn, quedan: maxPorConexion})

		req, err := http.ReadRequest(lector)
		if err != nil {
			// Basura que no es HTTP: se anota igual, un escaner de puertos
			// tambien es informacion.
			reg(evento(t.ID(), "http", ipDe(conn), model.Conexion,
				map[string]string{"puerto": puertoDe(direccion)}))
			return
		}
		defer req.Body.Close()

		detalle := map[string]string{
			"metodo": req.Method,
			"ruta":   recortar(req.URL.RequestURI(), 512),
		}
		if ua := req.UserAgent(); ua != "" {
			detalle["cliente"] = recortar(ua, 256)
		}
		if h := req.Host; h != "" {
			detalle["host"] = recortar(h, 128)
		}
		// La autenticacion basica llega en claro: son credenciales que el
		// atacante esta probando, igual que en SSH.
		if usuario, clave, ok := req.BasicAuth(); ok {
			detalle["usuario"] = recortar(usuario, 128)
			detalle["password"] = recortar(clave, 128)
		}

		reg(evento(t.ID(), "http", ipDe(conn), model.PeticionHTTP, detalle))

		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\n"+
			"Server: nginx/1.24.0\r\n"+
			"Content-Type: text/html\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n\r\n%s", len(cuerpoHTTP), cuerpoHTTP)
	})
}

// lectorLimitado corta la lectura para que nadie mande un cuerpo infinito.
type lectorLimitado struct {
	r      net.Conn
	quedan int
}

func (l *lectorLimitado) Read(p []byte) (int, error) {
	if l.quedan <= 0 {
		return 0, fmt.Errorf("peticion demasiado grande")
	}
	if len(p) > l.quedan {
		p = p[:l.quedan]
	}
	n, err := l.r.Read(p)
	l.quedan -= n
	return n, err
}

func recortar(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		// Los caracteres de control se van: acaban en el panel y en el log.
		if r < 32 && r != '\t' {
			return -1
		}
		return r
	}, s)
	if len(s) > max {
		return s[:max]
	}
	return s
}
