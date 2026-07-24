package trampa

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// Docker finge la API de un demonio Docker sin proteger.
//
// Un Docker abierto en el 2375 es ejecucion remota directa: quien llega
// crea un contenedor con la imagen y el comando que quiera, y ya esta
// corriendo codigo en la maquina. Los bots lo escanean sin parar para
// soltar mineros. Es la trampa que mas dice de un golpe: se queda con la
// imagen y el comando exactos que intentaban desplegar.
type Docker struct{}

func (*Docker) ID() string            { return "docker" }
func (*Docker) Nombre() string        { return "Docker API" }
func (*Docker) PuertoPorDefecto() int { return 2375 }
func (*Docker) Descripcion() string {
	return "Finge la API de un Docker sin proteger. Captura la imagen y el comando " +
		"que los bots intentan desplegar, normalmente un minero de criptomonedas."
}

func (t *Docker) Servir(ctx context.Context, direccion string, reg Registrar) error {
	return servirTCP(ctx, direccion, func(conn net.Conn) {
		lector := bufio.NewReader(&lectorLimitado{r: conn, quedan: maxPorConexion})

		// La API de Docker es HTTP y reutiliza la conexion: un "docker run"
		// son varias peticiones seguidas. Se atienden en bucle.
		for {
			conn.SetDeadline(time.Now().Add(plazoLectura))
			req, err := http.ReadRequest(lector)
			if err != nil {
				return
			}
			cuerpo, _ := io.ReadAll(io.LimitReader(req.Body, maxPorConexion))
			req.Body.Close()

			atenderDocker(t.ID(), conn, req, cuerpo, reg)
		}
	})
}

// atenderDocker registra la peticion segun lo que pida y responde algo
// creible para que el bot siga hasta desplegar.
func atenderDocker(id string, conn net.Conn, req *http.Request, cuerpo []byte, reg Registrar) {
	ip := ipDe(conn)
	ruta := req.URL.Path

	switch {
	case strings.HasSuffix(ruta, "/containers/create"):
		// Crear un contenedor es lanzar codigo: se guarda imagen y comando.
		reg(evento(id, "docker", ip, model.ComandoEjecutado,
			map[string]string{"comando": recortar(resumenContenedor(cuerpo), 512)}))
		responderDocker(conn, 201, `{"Id":"a1b2c3d4e5f6","Warnings":[]}`)

	case strings.Contains(ruta, "/exec"):
		reg(evento(id, "docker", ip, model.ComandoEjecutado,
			map[string]string{"comando": recortar("exec "+resumenContenedor(cuerpo), 512)}))
		responderDocker(conn, 201, `{"Id":"e1x2e3c4"}`)

	case strings.HasSuffix(ruta, "/images/create"):
		// Bajarse una imagen NO es traerse malware: son imagenes base publicas
		// (alpine, debian, busybox...). Es una accion de la API, no un
		// artefacto, asi que se registra como comando y no como descarga: de lo
		// contrario la lista de artefactos se llena de nombres de distros.
		imagen := req.URL.Query().Get("fromImage")
		if tag := req.URL.Query().Get("tag"); tag != "" {
			imagen += ":" + tag
		}
		reg(evento(id, "docker", ip, model.ComandoEjecutado,
			map[string]string{"comando": recortar("pull "+imagen, 256)}))
		responderDocker(conn, 200, `{"status":"Pulling from library"}`)

	case ruta == "/_ping":
		responderDocker(conn, 200, "OK")

	case strings.HasSuffix(ruta, "/version"):
		reg(evento(id, "docker", ip, model.PeticionHTTP, detalleDocker(req)))
		responderDocker(conn, 200,
			`{"Version":"24.0.7","ApiVersion":"1.43","Os":"linux","Arch":"amd64"}`)

	case strings.HasSuffix(ruta, "/info"):
		reg(evento(id, "docker", ip, model.PeticionHTTP, detalleDocker(req)))
		responderDocker(conn, 200,
			`{"Containers":0,"Images":0,"ServerVersion":"24.0.7","OSType":"linux"}`)

	case strings.HasSuffix(ruta, "/json"): // /containers/json, /images/json
		reg(evento(id, "docker", ip, model.PeticionHTTP, detalleDocker(req)))
		responderDocker(conn, 200, "[]")

	default:
		reg(evento(id, "docker", ip, model.PeticionHTTP, detalleDocker(req)))
		responderDocker(conn, 200, "{}")
	}
}

func detalleDocker(req *http.Request) map[string]string {
	return map[string]string{
		"metodo": req.Method,
		"ruta":   recortar(req.URL.RequestURI(), 512),
	}
}

// resumenContenedor saca de la peticion de crear contenedor la imagen y el
// comando, que es lo que de verdad importa: el resto del JSON es ruido.
func resumenContenedor(cuerpo []byte) string {
	var c struct {
		Image      string   `json:"Image"`
		Cmd        []string `json:"Cmd"`
		Entrypoint []string `json:"Entrypoint"`
	}
	if err := json.Unmarshal(cuerpo, &c); err != nil {
		return strings.TrimSpace(string(cuerpo))
	}
	partes := []string{}
	if c.Image != "" {
		partes = append(partes, "image="+c.Image)
	}
	orden := append(c.Entrypoint, c.Cmd...)
	if len(orden) > 0 {
		partes = append(partes, "cmd="+strings.Join(orden, " "))
	}
	if len(partes) == 0 {
		return strings.TrimSpace(string(cuerpo))
	}
	return strings.Join(partes, " ")
}

// responderDocker manda una respuesta HTTP con cierre de conexion cuando
// toca, para no dejar la lectura colgada.
func responderDocker(conn net.Conn, estado int, cuerpo string) {
	texto := map[int]string{200: "OK", 201: "Created"}[estado]
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n"+
		"Server: Docker/24.0.7\r\n"+
		"Api-Version: 1.43\r\n"+
		"Content-Type: application/json\r\n"+
		"Content-Length: %d\r\n"+
		"Connection: keep-alive\r\n\r\n%s", estado, texto, len(cuerpo), cuerpo)
}
