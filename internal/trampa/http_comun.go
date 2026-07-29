package trampa

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/k0braintheworld/k0pot/internal/exploit"
	"github.com/k0braintheworld/k0pot/internal/model"
)

// respuestaHTTP es lo que una trampa HTTP devuelve a una peticion.
type respuestaHTTP struct {
	Cuerpo    string
	Tipo      string            // Content-Type; por defecto text/html
	Cabeceras map[string]string // cabeceras extra (X-Jenkins, etc.)
	Cebo      string            // etiqueta para el panel si sirve algo jugoso
	Codigo    int               // estado HTTP; 0 => 200
}

// atenderHTTP es el molde comun de las trampas que hablan HTTP (Elasticsearch,
// Jenkins, Grafana...). Lee la peticion, la registra como evento -con captura
// de credenciales de formulario Y JSON, y deteccion de exploits/callbacks-, y
// responde con lo que decida 'responder'.
func atenderHTTP(t Trampa, protocolo, direccion string, conn net.Conn, reg Registrar,
	responder func(req *http.Request, cuerpo []byte) respuestaHTTP) {
	lector := bufio.NewReader(&lectorLimitado{r: conn, quedan: maxPorConexion})
	req, err := http.ReadRequest(lector)
	if err != nil {
		// Basura que no es HTTP: se anota como conexion a secas.
		reg(evento(t.ID(), protocolo, ipDe(conn), model.Conexion,
			map[string]string{"puerto": puertoDe(direccion)}))
		return
	}

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
	if u, p, ok := req.BasicAuth(); ok {
		detalle["usuario"] = recortar(u, 128)
		detalle["password"] = recortar(p, 128)
	}

	var cuerpo []byte
	if req.Method == http.MethodPost || req.Method == http.MethodPut {
		cuerpo, _ = io.ReadAll(io.LimitReader(req.Body, 8192))
		if len(cuerpo) > 0 {
			if u, p := credencialesDeCuerpo(req.Header.Get("Content-Type"), cuerpo); u != "" || p != "" {
				if u != "" {
					detalle["usuario"] = recortar(u, 128)
				}
				if p != "" {
					detalle["password"] = recortar(p, 128)
				}
			}
			detalle["cuerpo"] = recortar(string(cuerpo), 512)
		}
	}

	if h, ok := exploit.Detectar(superficieDe(req, cuerpo)); ok {
		detalle["exploit"] = h.Familia
		if h.Destino != "" {
			detalle["callback"] = recortar(h.Destino, 512)
		}
	}

	resp := responder(req, cuerpo)
	if resp.Cebo != "" {
		detalle["cebo"] = resp.Cebo
	}
	reg(evento(t.ID(), protocolo, ipDe(conn), model.PeticionHTTP, detalle))

	codigo := resp.Codigo
	if codigo == 0 {
		codigo = 200
	}
	tipo := resp.Tipo
	if tipo == "" {
		tipo = "text/html; charset=utf-8"
	}
	var extra strings.Builder
	for k, v := range resp.Cabeceras {
		fmt.Fprintf(&extra, "%s: %s\r\n", k, v)
	}
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n"+
		"Content-Type: %s\r\n"+
		"Content-Length: %d\r\n%s"+
		"Connection: close\r\n\r\n%s",
		codigo, http.StatusText(codigo), tipo, len(resp.Cuerpo), extra.String(), resp.Cuerpo)
}

var (
	reJSONUsuario = regexp.MustCompile(`(?i)"(?:user|username|login|email)"\s*:\s*"([^"]{1,128})"`)
	reJSONClave   = regexp.MustCompile(`(?i)"(?:password|passwd|pass|pwd)"\s*:\s*"([^"]{1,128})"`)
)

// credencialesDeCuerpo saca usuario y clave del cuerpo de un POST, tanto si
// vienen en un formulario (application/x-www-form-urlencoded) como en JSON
// (Grafana, muchas APIs). Nadie legitimo teclea sus credenciales en una
// maquina trampa: cada una es intencion pura.
func credencialesDeCuerpo(contentType string, cuerpo []byte) (usuario, clave string) {
	if strings.Contains(contentType, "form-urlencoded") {
		if vals, e := url.ParseQuery(string(cuerpo)); e == nil {
			return primerCampo(vals, camposUsuario), primerCampo(vals, camposClave)
		}
	}
	if strings.Contains(contentType, "json") || (len(cuerpo) > 0 && cuerpo[0] == '{') {
		if m := reJSONUsuario.FindSubmatch(cuerpo); m != nil {
			usuario = string(m[1])
		}
		if m := reJSONClave.FindSubmatch(cuerpo); m != nil {
			clave = string(m[1])
		}
	}
	return usuario, clave
}
