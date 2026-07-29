package trampa

import (
	"context"
	"net"
	"net/http"
	"strings"
)

// Jenkins finge un servidor de integracion continua abierto. Es un blanco muy
// buscado: la consola de scripts Groovy es ejecucion de codigo directa, y sus
// credenciales suelen abrir el despliegue a produccion. Devuelve la cabecera
// X-Jenkins -su huella-, un panel de login que captura lo que teclean y la
// consola de scripts para que el atacante suelte su payload (que anotamos).
type Jenkins struct{}

func (*Jenkins) ID() string            { return "jenkins" }
func (*Jenkins) Nombre() string        { return "Jenkins" }
func (*Jenkins) PuertoPorDefecto() int { return 8000 }
func (*Jenkins) Descripcion() string {
	return "Finge un Jenkins (integracion continua) abierto: cabecera X-Jenkins, " +
		"panel de login que captura credenciales y la consola de scripts Groovy " +
		"que tanto buscan para ejecutar codigo."
}

func (t *Jenkins) Servir(ctx context.Context, direccion string, reg Registrar) error {
	return servirTCP(ctx, direccion, func(conn net.Conn) {
		atenderHTTP(t, "jenkins", direccion, conn, reg, responderJenkins)
	})
}

func responderJenkins(req *http.Request, _ []byte) respuestaHTTP {
	cab := map[string]string{
		"X-Jenkins":         "2.426.1",
		"X-Jenkins-Session": "8f3a1c2d",
		"X-Hudson":          "1.395",
	}
	p := strings.ToLower(req.URL.Path)
	switch {
	case strings.HasPrefix(p, "/script"):
		return respuestaHTTP{Cuerpo: jenkinsScript, Cabeceras: cab,
			Cebo: "la consola de scripts Groovy (ejecucion de codigo)"}
	case strings.HasPrefix(p, "/api/json"):
		return respuestaHTTP{Cuerpo: jenkinsAPI, Tipo: "application/json;charset=utf-8", Cabeceras: cab}
	default:
		// Raiz, /login, /j_spring_security_check... todo devuelve el login.
		// Las credenciales del POST ya las capturo atenderHTTP.
		return respuestaHTTP{Cuerpo: jenkinsLogin, Cabeceras: cab}
	}
}

const jenkinsLogin = `<!DOCTYPE html><html lang="en"><head>
<title>Sign in [Jenkins]</title>
<meta name="ROBOTS" content="NOINDEX,NOFOLLOW">
</head><body class="jenkins-2.426.1">
<div id="main-panel"><h1>Welcome to Jenkins!</h1>
<form method="post" name="login" action="j_spring_security_check">
  <div><label>Username</label><input name="j_username" type="text"></div>
  <div><label>Password</label><input name="j_password" type="password"></div>
  <input name="from" type="hidden">
  <button type="submit" name="Submit">Sign in</button>
</form>
<footer>Jenkins ver. 2.426.1</footer>
</div></body></html>
`

const jenkinsScript = `<!DOCTYPE html><html><head><title>Script Console [Jenkins]</title></head>
<body class="jenkins-2.426.1"><div id="main-panel">
<h1>Script Console</h1>
<p>Type in an arbitrary Groovy script and execute it on the server.</p>
<form method="post" action="script">
  <textarea name="script" rows="10" cols="80"></textarea>
  <button type="submit">Run</button>
</form>
</div></body></html>
`

const jenkinsAPI = `{"_class":"hudson.model.Hudson","mode":"NORMAL","nodeDescription":"the Jenkins controller's built-in node","nodeName":"","numExecutors":2,"jobs":[{"_class":"hudson.model.FreeStyleProject","name":"acme-shop-deploy","url":"http://localhost:8080/job/acme-shop-deploy/","color":"blue"},{"_class":"hudson.model.FreeStyleProject","name":"nightly-backup","url":"http://localhost:8080/job/nightly-backup/","color":"blue"}],"quietingDown":false,"useSecurity":true}
`
