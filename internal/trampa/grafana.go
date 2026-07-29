package trampa

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// Grafana finge un panel de metricas Grafana abierto. Es un login muy sondeado
// y su version 8.3.0 arrastra el path traversal CVE-2021-43798, uno de los
// sondeos mas repetidos de internet: se responde con un /etc/passwd de pega
// para que el atacante crea que funciono y siga tirando del hilo. El login
// captura las credenciales que prueben, vengan en formulario o en JSON.
type Grafana struct{}

func (*Grafana) ID() string            { return "grafana" }
func (*Grafana) Nombre() string        { return "Grafana" }
func (*Grafana) PuertoPorDefecto() int { return 3000 }
func (*Grafana) Descripcion() string {
	return "Finge un Grafana abierto (paneles de metricas): pagina de login que " +
		"captura credenciales, API de salud con version, y responde al path " +
		"traversal (CVE-2021-43798) que tanto sondean."
}

func (t *Grafana) Servir(ctx context.Context, direccion string, reg Registrar) error {
	return servirTCP(ctx, direccion, func(conn net.Conn) {
		atenderHTTP(t, "grafana", direccion, conn, reg, responderGrafana)
	})
}

func responderGrafana(req *http.Request, _ []byte) respuestaHTTP {
	p := req.URL.Path
	low := strings.ToLower(p)
	switch {
	case strings.Contains(low, "/api/health"):
		return respuestaHTTP{Cuerpo: grafanaSalud, Tipo: "application/json"}
	case strings.Contains(p, "..") && strings.Contains(low, "/public/plugins/"):
		// CVE-2021-43798: path traversal de Grafana, de los mas sondeados.
		return respuestaHTTP{Cuerpo: passwdFalso, Tipo: "text/plain; charset=utf-8",
			Cebo: "un /etc/passwd por el path traversal (CVE-2021-43798)"}
	case req.Method == http.MethodPost && strings.Contains(low, "/login"):
		return respuestaHTTP{Cuerpo: `{"message":"Invalid username or password"}`,
			Tipo: "application/json", Codigo: 401}
	default:
		return respuestaHTTP{Cuerpo: grafanaLogin}
	}
}

const grafanaSalud = `{
  "commit": "d7f71e9eae",
  "database": "ok",
  "version": "8.3.0"
}
`

const grafanaLogin = `<!DOCTYPE html><html lang="en"><head>
<title>Grafana</title>
<meta charset="utf-8"><meta name="viewport" content="width=device-width">
<base href="/"></head>
<body class="theme-dark app-grafana"><grafana-app>
<div class="preloader"><div class="preloader__logo"></div></div>
</grafana-app>
<form method="post" action="/login">
  <input name="user" type="text" placeholder="email or username">
  <input name="password" type="password" placeholder="password">
  <button type="submit">Log in</button>
</form>
</body></html>
`

const passwdFalso = `root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
sshd:x:110:65534::/run/sshd:/usr/sbin/nologin
grafana:x:472:0:Grafana:/usr/share/grafana:/sbin/nologin
deploy:x:1000:1000:deploy:/home/deploy:/bin/bash
`
