package trampa

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/k0braintheworld/k0pot/internal/exploit"
	"github.com/k0braintheworld/k0pot/internal/model"
)

// HTTP finge ser un servidor web corriente CON CEBO.
//
// Es la trampa de mas volumen con diferencia: internet esta lleno de bots
// probando rutas de administracion, ficheros de configuracion olvidados y
// exploits recien publicados. Cada peticion dice mucho de quien la manda.
//
// Ademas de anotar, MUERDE: a las rutas mas jugosas (un .env, un panel de
// login, un phpMyAdmin) les devuelve contenido falso pero creible. Con eso
// se consiguen dos cosas. Una, que el escaner siga tirando del hilo y se
// retrate mas. Dos, y mas importante, que si envia algo -las credenciales
// que teclea en el formulario, el payload que inyecta- lo capturamos. Nadie
// legitimo mete su usuario en el panel de una maquina trampa: cada POST aqui
// es, por definicion, alguien intentando entrar.
type HTTP struct{}

func (*HTTP) ID() string            { return "http" }
func (*HTTP) Nombre() string        { return "HTTP" }
func (*HTTP) PuertoPorDefecto() int { return 8081 }
func (*HTTP) Descripcion() string {
	return "Finge un servidor web con cebo. Captura escaneos de rutas, intentos " +
		"de explotar vulnerabilidades y las credenciales que teclean en paneles falsos."
}

// paginaNginx imita a un nginx cualquiera. Interesa parecer un servidor real
// y aburrido: si respondiera algo raro, los bots dejarian de insistir.
const paginaNginx = `<!doctype html>
<html><head><title>Welcome to nginx!</title></head>
<body><h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed.</p>
</body></html>
`

// cebo describe una respuesta trampa: un contenido falso pero creible para
// una ruta jugosa, con una etiqueta en llano para el panel.
type cebo struct {
	cuerpo string
	tipo   string // Content-Type
	que    string // etiqueta para el panel/informe
}

// envFalso es el cebo estrella: un fichero de entorno de Laravel con
// credenciales de base de datos y llaves que PARECEN de produccion. Son
// falsas y no abren nada. Su gracia es doble: entretiene al escaner, y si
// mas tarde alguien intenta usar estas credenciales concretas contra la
// maquina, sabemos con total certeza que salieron de aqui.
const envFalso = `APP_NAME=Acme
APP_ENV=production
APP_KEY=base64:kR3p9Xv2mQ8sLd1fH7bN4wZ6cT0yUeI5oPaJgKlMnQ=
APP_DEBUG=false
APP_URL=https://shop.acme-corp.example

DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=acme_prod
DB_USERNAME=acme_app
DB_PASSWORD=Pr0d_9xQZ!ktm2024

REDIS_HOST=127.0.0.1
REDIS_PASSWORD=r3d1s_Wq82Lp!x
REDIS_PORT=6379

MAIL_HOST=smtp.acme-corp.example
MAIL_USERNAME=noreply@acme-corp.example
MAIL_PASSWORD=Sm7p__Nz19Kd

AWS_ACCESS_KEY_ID=AKIA7ACMEQK2NR0PZ3XV
AWS_SECRET_ACCESS_KEY=wq8Lz2Kd9xR3mNp7Ht4bV6cY0aJ1eU5oI2sFgQ
AWS_DEFAULT_REGION=eu-west-1
`

const gitConfigFalso = `[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = https://github.com/acme-corp/shop-backend.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
[user]
	name = deploy
	email = deploy@acme-corp.example
`

// loginFalso genera un panel de acceso que envia el formulario a la MISMA
// ruta, para que las credenciales que prueben caigan en nuestro POST.
func loginFalso(ruta string) string {
	return `<!doctype html>
<html><head><meta charset="utf-8"><title>Sign in</title></head>
<body style="font-family:sans-serif;max-width:340px;margin:80px auto">
<h2>Admin Login</h2>
<form method="post" action="` + htmlEscapa(ruta) + `">
<p><label>Username<br><input type="text" name="username" style="width:100%"></label></p>
<p><label>Password<br><input type="password" name="password" style="width:100%"></label></p>
<p><button type="submit">Log in</button></p>
</form>
</body></html>
`
}

func htmlEscapa(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;")
	return r.Replace(s)
}

// mirarCebo decide si una ruta merece contenido trampa. Devuelve nil cuando
// no, y entonces se sirve la pagina de nginx aburrida.
func mirarCebo(ruta string) *cebo {
	r := strings.ToLower(ruta)
	corta := func(s string) string {
		if i := strings.IndexAny(s, "?#"); i >= 0 {
			return s[:i]
		}
		return s
	}
	base := corta(r)
	switch {
	case strings.HasSuffix(base, "/.env") || base == "/.env":
		return &cebo{envFalso, "text/plain; charset=utf-8", "un fichero .env con credenciales dentro"}
	case strings.Contains(base, "/.git/config"):
		return &cebo{gitConfigFalso, "text/plain; charset=utf-8", "la configuracion de git del proyecto"}
	}
	for _, p := range []string{"/wp-login", "/wp-admin", "/administrator", "/admin", "/phpmyadmin", "/manager/html"} {
		if strings.Contains(base, p) {
			return &cebo{loginFalso(ruta), "text/html; charset=utf-8", "un panel de administracion"}
		}
	}
	return nil
}

// camposCredencial son los nombres habituales del usuario y la clave en los
// formularios de login que rondan por internet.
var camposUsuario = []string{"username", "user", "usuario", "login", "email", "log", "uname"}
var camposClave = []string{"password", "pass", "passwd", "pwd", "clave", "pwd1"}

func primerCampo(v url.Values, nombres []string) string {
	for _, n := range nombres {
		if s := v.Get(n); s != "" {
			return s
		}
	}
	return ""
}

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

		// El cuerpo del POST es la parte mas jugosa: lo que teclean en el
		// panel falso o el payload que inyectan. Se lee acotado.
		var cuerpo []byte
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			cuerpo, _ = io.ReadAll(io.LimitReader(req.Body, 8192))
			if len(cuerpo) > 0 {
				ct := req.Header.Get("Content-Type")
				if strings.Contains(ct, "form-urlencoded") {
					if vals, e := url.ParseQuery(string(cuerpo)); e == nil {
						if u := primerCampo(vals, camposUsuario); u != "" {
							detalle["usuario"] = recortar(u, 128)
						}
						if p := primerCampo(vals, camposClave); p != "" {
							detalle["password"] = recortar(p, 128)
						}
					}
				}
				detalle["cuerpo"] = recortar(string(cuerpo), 512)
			}
		}

		// Si la ruta pide algo jugoso, mordemos: contenido falso creible y
		// una etiqueta que deja claro en el panel que fue un cebo.
		// Un escaneo de explotacion filtra a menudo la infraestructura del
		// propio atacante (el ldap:// del Log4Shell, el http:// de la segunda
		// fase). Se extrae de toda la peticion, sin ejecutar nada.
		if h, ok := exploit.Detectar(superficieDe(req, cuerpo)); ok {
			detalle["exploit"] = h.Familia
			if h.Destino != "" {
				detalle["callback"] = recortar(h.Destino, 512)
			}
		}

		trampa := mirarCebo(req.URL.RequestURI())
		cuerpoResp, tipoResp := paginaNginx, "text/html"
		if trampa != nil {
			cuerpoResp, tipoResp = trampa.cuerpo, trampa.tipo
			detalle["cebo"] = trampa.que
		}

		reg(evento(t.ID(), "http", ipDe(conn), model.PeticionHTTP, detalle))

		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\n"+
			"Server: nginx/1.24.0\r\n"+
			"Content-Type: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n\r\n%s", tipoResp, len(cuerpoResp), cuerpoResp)
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

// superficieDe junta lo que un atacante puede usar para colar un payload
// -la ruta, todas las cabeceras y el cuerpo- en un solo texto. Log4Shell,
// por ejemplo, suele venir en una cabecera cualquiera, no en la ruta.
func superficieDe(req *http.Request, cuerpo []byte) string {
	var b strings.Builder
	b.WriteString(req.Method)
	b.WriteByte(' ')
	b.WriteString(req.URL.RequestURI())
	for k, vals := range req.Header {
		for _, v := range vals {
			b.WriteByte('\n')
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
		}
	}
	if len(cuerpo) > 0 {
		b.WriteByte('\n')
		b.Write(cuerpo)
	}
	return b.String()
}
