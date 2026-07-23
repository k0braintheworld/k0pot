package trampa

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// Redis finge un Redis sin contrasena.
//
// Un Redis abierto es uno de los objetivos clasicos: se usa para escribir
// claves SSH en el disco del servidor o para minar. Los bots lo prueban en
// cuanto lo encuentran.
type Redis struct{}

func (*Redis) ID() string            { return "redis" }
func (*Redis) Nombre() string        { return "Redis" }
func (*Redis) PuertoPorDefecto() int { return 6379 }
func (*Redis) Descripcion() string {
	return "Finge un Redis sin contrasena. Captura los intentos de escribir claves " +
		"SSH o instalar mineros, un objetivo clasico de las botnets."
}

func (t *Redis) Servir(ctx context.Context, direccion string, reg Registrar) error {
	return servirTCP(ctx, direccion, func(conn net.Conn) {
		lector := bufio.NewReader(&lectorLimitado{r: conn, quedan: maxPorConexion})
		reg(evento(t.ID(), "redis", ipDe(conn), model.Conexion,
			map[string]string{"puerto": puertoDe(direccion)}))

		for {
			orden, err := leerOrdenRESP(lector)
			if err != nil || len(orden) == 0 {
				return
			}

			reg(evento(t.ID(), "redis", ipDe(conn), model.ComandoEjecutado,
				map[string]string{"comando": recortar(strings.Join(orden, " "), 512)}))

			// Respuestas minimas para que el bot siga hablando y se retrate.
			switch strings.ToUpper(orden[0]) {
			case "PING":
				fmt.Fprint(conn, "+PONG\r\n")
			case "INFO":
				info := "# Server\r\nredis_version:7.0.11\r\nos:Linux\r\n"
				fmt.Fprintf(conn, "$%d\r\n%s\r\n", len(info), info)
			case "QUIT":
				fmt.Fprint(conn, "+OK\r\n")
				return
			default:
				fmt.Fprint(conn, "+OK\r\n")
			}
		}
	})
}

// leerOrdenRESP entiende el protocolo de Redis: o un array de bulk strings,
// o una linea suelta (los bots usan las dos formas).
func leerOrdenRESP(r *bufio.Reader) ([]string, error) {
	linea, err := r.ReadString('\n')
	if err != nil {
		return nil, err
	}
	linea = strings.TrimRight(linea, "\r\n")
	if linea == "" {
		return nil, nil
	}

	if !strings.HasPrefix(linea, "*") {
		return strings.Fields(linea), nil // forma antigua, sin formato
	}

	var n int
	if _, err := fmt.Sscanf(linea, "*%d", &n); err != nil || n <= 0 || n > 128 {
		return nil, fmt.Errorf("array RESP invalido")
	}

	orden := make([]string, 0, n)
	for i := 0; i < n; i++ {
		if _, err := r.ReadString('\n'); err != nil { // cabecera $N
			return nil, err
		}
		valor, err := r.ReadString('\n')
		if err != nil {
			return nil, err
		}
		orden = append(orden, strings.TrimRight(valor, "\r\n"))
	}
	return orden, nil
}

// FTP finge un servidor FTP que acepta cualquier usuario.
//
// Sigue habiendo muchisimo escaneo de FTP buscando servidores anonimos o con
// credenciales por defecto.
type FTP struct{}

func (*FTP) ID() string            { return "ftp" }
func (*FTP) Nombre() string        { return "FTP" }
func (*FTP) PuertoPorDefecto() int { return 2121 }
func (*FTP) Descripcion() string {
	return "Finge un servidor FTP. Captura las credenciales que prueban los bots " +
		"que buscan acceso anonimo o contrasenas por defecto."
}

func (t *FTP) Servir(ctx context.Context, direccion string, reg Registrar) error {
	return servirTCP(ctx, direccion, func(conn net.Conn) {
		lector := bufio.NewReader(&lectorLimitado{r: conn, quedan: maxPorConexion})
		reg(evento(t.ID(), "ftp", ipDe(conn), model.Conexion,
			map[string]string{"puerto": puertoDe(direccion)}))
		fmt.Fprint(conn, "220 (vsFTPd 3.0.5)\r\n")

		var usuario string
		for {
			linea, err := lector.ReadString('\n')
			if err != nil {
				return
			}
			partes := strings.SplitN(strings.TrimRight(linea, "\r\n"), " ", 2)
			orden := strings.ToUpper(partes[0])
			arg := ""
			if len(partes) > 1 {
				arg = partes[1]
			}

			switch orden {
			case "USER":
				usuario = recortar(arg, 128)
				fmt.Fprint(conn, "331 Please specify the password.\r\n")
			case "PASS":
				reg(evento(t.ID(), "ftp", ipDe(conn), model.LoginFallido,
					map[string]string{"usuario": usuario, "password": recortar(arg, 128)}))
				fmt.Fprint(conn, "530 Login incorrect.\r\n")
			case "QUIT":
				fmt.Fprint(conn, "221 Goodbye.\r\n")
				return
			case "SYST":
				fmt.Fprint(conn, "215 UNIX Type: L8\r\n")
			default:
				fmt.Fprint(conn, "530 Please login with USER and PASS.\r\n")
			}
		}
	})
}
