package trampa

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"strings"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// SMTP finge un servidor de correo.
//
// Los bots buscan servidores de correo abiertos por dos cosas: probar
// credenciales (AUTH) y usarlos de reenvio anonimo para mandar spam (open
// relay). Se capturan las dos: el usuario y la contrasena que prueban, y
// las direcciones a las que intentan reenviar.
type SMTP struct{}

func (*SMTP) ID() string     { return "smtp" }
func (*SMTP) Nombre() string { return "SMTP" }

// 2525, no 25: el puerto real es privilegiado y el proceso no corre como
// root. Se expone el 25 de fuera con el cortafuegos, igual que FTP con 2121.
func (*SMTP) PuertoPorDefecto() int { return 2525 }
func (*SMTP) Descripcion() string {
	return "Finge un servidor de correo. Captura las credenciales que prueban los " +
		"bots y los intentos de usarlo como reenvio anonimo de spam."
}

func (t *SMTP) Servir(ctx context.Context, direccion string, reg Registrar) error {
	return servirTCP(ctx, direccion, func(conn net.Conn) {
		lector := bufio.NewReader(&lectorLimitado{r: conn, quedan: maxPorConexion})
		reg(evento(t.ID(), "smtp", ipDe(conn), model.Conexion,
			map[string]string{"puerto": puertoDe(direccion)}))
		fmt.Fprint(conn, "220 mail.example.com ESMTP Postfix\r\n")

		leer := func() (string, bool) {
			linea, err := lector.ReadString('\n')
			if err != nil {
				return "", false
			}
			return strings.TrimRight(linea, "\r\n"), true
		}

		for {
			linea, ok := leer()
			if !ok {
				return
			}
			partes := strings.SplitN(linea, " ", 2)
			orden := strings.ToUpper(partes[0])
			arg := ""
			if len(partes) > 1 {
				arg = partes[1]
			}

			switch orden {
			case "EHLO":
				fmt.Fprint(conn, "250-mail.example.com\r\n250-AUTH LOGIN PLAIN\r\n250 OK\r\n")
			case "HELO":
				fmt.Fprint(conn, "250 mail.example.com\r\n")
			case "AUTH":
				usuario, password := loginSMTP(conn, lector, arg)
				if usuario != "" || password != "" {
					reg(evento(t.ID(), "smtp", ipDe(conn), model.LoginFallido,
						map[string]string{
							"usuario":  recortar(usuario, 128),
							"password": recortar(password, 128),
						}))
				}
				fmt.Fprint(conn, "535 5.7.8 Authentication credentials invalid\r\n")
			case "MAIL":
				fmt.Fprint(conn, "250 2.1.0 Ok\r\n")
			case "RCPT":
				// El destino de un RCPT hacia fuera es un intento de reenvio:
				// es lo que hace un probador de open relay.
				reg(evento(t.ID(), "smtp", ipDe(conn), model.ComandoEjecutado,
					map[string]string{"comando": recortar("RCPT "+arg, 256)}))
				fmt.Fprint(conn, "250 2.1.5 Ok\r\n")
			case "DATA":
				fmt.Fprint(conn, "354 End data with <CR><LF>.<CR><LF>\r\n")
				for {
					l, ok := leer()
					if !ok || l == "." {
						break
					}
				}
				fmt.Fprint(conn, "250 2.0.0 Ok\r\n")
			case "RSET", "NOOP":
				fmt.Fprint(conn, "250 2.0.0 Ok\r\n")
			case "VRFY":
				fmt.Fprint(conn, "252 2.0.0 Cannot verify\r\n")
			case "QUIT":
				fmt.Fprint(conn, "221 2.0.0 Bye\r\n")
				return
			default:
				fmt.Fprint(conn, "502 5.5.2 Error: command not recognized\r\n")
			}
		}
	})
}

// loginSMTP resuelve un AUTH, sea LOGIN (usuario y clave en dos pasos, cada
// uno en base64) o PLAIN (todo junto, separado por bytes null). Los bots
// mandan base64 pensando que es un servidor real; se descodifica y ya esta.
func loginSMTP(conn net.Conn, r *bufio.Reader, arg string) (usuario, password string) {
	campos := strings.SplitN(arg, " ", 2)
	metodo := strings.ToUpper(campos[0])

	descodificar := func() string {
		linea, err := r.ReadString('\n')
		if err != nil {
			return ""
		}
		return desB64(strings.TrimRight(linea, "\r\n"))
	}

	switch metodo {
	case "LOGIN":
		fmt.Fprint(conn, "334 VXNlcm5hbWU6\r\n") // "Username:"
		usuario = descodificar()
		fmt.Fprint(conn, "334 UGFzc3dvcmQ6\r\n") // "Password:"
		password = descodificar()
	case "PLAIN":
		datos := ""
		if len(campos) > 1 && campos[1] != "" {
			datos = desB64(campos[1])
		} else {
			fmt.Fprint(conn, "334 \r\n")
			datos = descodificar()
		}
		// El formato es identidad\0usuario\0contrasena.
		trozos := strings.Split(datos, "\x00")
		if len(trozos) == 3 {
			usuario, password = trozos[1], trozos[2]
		}
	}
	return usuario, password
}

func desB64(s string) string {
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return string(b)
}
