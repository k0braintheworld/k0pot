// Package episodio agrupa eventos sueltos en ataques.
//
// Un evento aislado casi nunca dice nada: la inmensa mayoria de lo que
// captura un honeypot son lineas "conexion" que por si solas no permiten
// distinguir un escaner de alguien que entro. Lo que una persona llama
// "un ataque" es una secuencia — esta IP conecto, probo doce contrasenas,
// entro y ejecuto wget — y esa secuencia esta desparramada en filas que
// nada relaciona.
//
// Aqui se reconstruye esa secuencia y se resume en una frase.
package episodio

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/saber"
)

// HuecoPorDefecto es el silencio tras el cual se considera que un ataque
// termino y el siguiente es otro distinto.
const HuecoPorDefecto = 30 * time.Minute

// Severidad ordena los episodios por lo que el atacante CONSIGUIO, no por
// cuanto insistio.
//
// Mil conexiones de un escaner valen menos que una sola sesion donde
// alguien tecleo "cat /etc/passwd". Ordenar por volumen es justo lo que
// entierra el unico episodio que habia que mirar.
type Severidad string

const (
	// Roce: toco el puerto y se fue. El ruido de fondo de internet.
	Roce Severidad = "roce"
	// Tanteo: probo credenciales o rutas. Sigue siendo automatico, pero
	// ya es un intento.
	Tanteo Severidad = "tanteo"
	// Acceso: entro.
	Acceso Severidad = "acceso"
	// Intrusion: entro y ademas actuo dentro.
	Intrusion Severidad = "intrusion"
)

// orden permite comparar severidades; el valor mayor manda.
var orden = map[Severidad]int{Roce: 0, Tanteo: 1, Acceso: 2, Intrusion: 3}

// Rango convierte una severidad en un numero comparable.
//
// Es la unica definicion del orden de gravedad en todo el proyecto: la
// consulta SQL de los avisos y la ordenacion del panel la citan en vez de
// repetirla, porque dos criterios que divergen hacen que el panel y las
// notificaciones discrepen sobre que es mas grave.
func Rango(s Severidad) int { return orden[s] }

// Peor devuelve la mas grave de dos severidades.
func Peor(a, b Severidad) Severidad {
	if orden[b] > orden[a] {
		return b
	}
	return a
}

// Episodio es un ataque: lo que una IP hizo contra un servicio de forma
// continuada.
type Episodio struct {
	// Clave identifica al episodio de forma estable entre reconstrucciones,
	// para poder rehacerlos sin duplicarlos.
	Clave     string    `json:"clave"`
	IP        string    `json:"ip"`
	Protocolo string    `json:"protocolo"`
	Inicio    time.Time `json:"inicio"`
	Fin       time.Time `json:"fin"`
	Eventos   int       `json:"eventos"`
	Severidad Severidad `json:"severidad"`

	// Puerto al que llamaron. "Conecta" a secas no distingue un sondeo
	// del 6379 de uno del 21.
	Puerto string `json:"puerto,omitempty"`
	// SoloConexiones marca el episodio en que nadie llego a decir nada:
	// abrieron el puerto, comprobaron que respondia y se fueron. Es un
	// sondeo de puertos, y merece decirse con esas palabras.
	SoloConexiones bool `json:"solo_conexiones"`

	LoginsFallidos int      `json:"logins_fallidos"`
	LoginExitoso   bool     `json:"login_exitoso"`
	Usuarios       []string `json:"usuarios,omitempty"`
	Passwords      []string `json:"passwords,omitempty"`
	Comandos       []string `json:"comandos,omitempty"`
	Rutas          []string `json:"rutas,omitempty"`
	Descargas      []string `json:"descargas,omitempty"`
	// Tuneles son los destinos a los que pidieron reenviar trafico.
	Tuneles []string `json:"tuneles,omitempty"`

	// Motivos son los veredictos del clasificador que elevaron el episodio.
	// Se guardan para poder explicar una severidad que no se deduce de los
	// tipos de evento: un "tanteo" cuyo resumen diga "solo conecto" es una
	// contradiccion en pantalla, y quien la lee deja de fiarse del resto.
	Motivos []string `json:"motivos,omitempty"`

	// CeboMordido lleva la etiqueta del senuelo que el atacante
	// reutilizo. Es la senal mas fuerte: leyo el cebo y volvio.
	CeboMordido string `json:"cebo_mordido,omitempty"`

	// Resumen cuenta en una frase que paso, para poder leer la lista sin
	// abrir cada episodio.
	Resumen string `json:"resumen"`

	// hablaron es interno: se usa al cerrar para decidir SoloConexiones.
	hablaron bool
}

// Duracion es lo que duro el ataque.
func (e Episodio) Duracion() time.Duration { return e.Fin.Sub(e.Inicio) }

// Agrupar reconstruye los episodios de una tanda de eventos.
//
// Los eventos deben venir ordenados por fecha. Se agrupa por (IP,
// protocolo) y se corta cuando pasa mas de "hueco" sin actividad.
//
// Se agrupa por IP y protocolo, y NO por la sesion de Cowrie, aunque la
// haya: las trampas nativas no tienen sesion, y usar dos criterios
// distintos daria episodios que no se pueden comparar entre si. Ademas dos
// sesiones seguidas de la misma IP son el mismo ataque para quien lo mira,
// aunque sean dos conexiones TCP para la maquina.
func Agrupar(eventos []model.Evento, hueco time.Duration) []Episodio {
	if hueco <= 0 {
		hueco = HuecoPorDefecto
	}
	// abiertos guarda, por clave de agrupacion, el episodio en curso.
	abiertos := map[string]*Episodio{}
	var todos []*Episodio

	for _, ev := range eventos {
		clave := ev.IP + "|" + ev.Protocolo
		actual, hay := abiertos[clave]
		if !hay || ev.Timestamp.Sub(actual.Fin) > hueco {
			actual = &Episodio{
				Clave:     fmt.Sprintf("%s|%s|%d", ev.IP, ev.Protocolo, ev.Timestamp.UTC().Unix()),
				IP:        ev.IP,
				Protocolo: ev.Protocolo,
				Inicio:    ev.Timestamp,
				Severidad: Roce,
			}
			abiertos[clave] = actual
			todos = append(todos, actual)
		}
		actual.absorber(ev)
	}

	fin := make([]Episodio, 0, len(todos))
	for _, e := range todos {
		e.SoloConexiones = !e.hablaron
		e.Resumen = e.redactar("es")
		fin = append(fin, *e)
	}
	return fin
}

// absorber incorpora un evento al episodio en curso.
func (e *Episodio) absorber(ev model.Evento) {
	e.Eventos++
	if ev.Timestamp.After(e.Fin) {
		e.Fin = ev.Timestamp
	}

	// Mordio el cebo: reutilizo una credencial plantada. Es lo mas
	// grave que sabemos con certeza, sea cual sea el tipo de evento.
	if m := ev.Detalle["cebo_mordido"]; m != "" {
		e.CeboMordido = m
		e.Severidad = Peor(e.Severidad, Intrusion)
		anadir(&e.Motivos, "mordio el cebo: reutilizo "+m, 5)
	}

	if ev.Tipo == model.Conexion {
		if p := ev.Detalle["puerto"]; p != "" && e.Puerto == "" {
			e.Puerto = p
		}
	} else {
		// Cualquier cosa que no sea abrir la conexion ya es hablar.
		e.hablaron = true
	}

	switch ev.Tipo {
	case model.LoginFallido:
		e.LoginsFallidos++
		e.Severidad = Peor(e.Severidad, Tanteo)
		anadir(&e.Usuarios, ev.Detalle["usuario"], 20)
		anadir(&e.Passwords, ev.Detalle["password"], 20)
	case model.LoginExitoso:
		e.LoginExitoso = true
		e.Severidad = Peor(e.Severidad, Acceso)
		anadir(&e.Usuarios, ev.Detalle["usuario"], 20)
		anadir(&e.Passwords, ev.Detalle["password"], 20)
	case model.ComandoEjecutado:
		cmd := ev.Detalle["comando"]
		anadir(&e.Comandos, cmd, 50)
		// Un comando solo significa "esta dentro del sistema" si venia por
		// una shell. En Redis o FTP es un verbo del protocolo: un PING no
		// es nadie actuando dentro de la maquina, y marcarlo como
		// intrusion ahoga las alertas de verdad entre ruido.
		if saber.SinShell(ev.Protocolo) {
			sev := Tanteo
			if v, hay := saber.DeVerbo(ev.Protocolo, cmd); hay && v.Grave {
				// Pero no todos son inofensivos: un CONFIG SET de Redis es
				// el primer paso para escribir un fichero ajeno en disco.
				sev = Intrusion
				anadir(&e.Motivos, v.Que, 5)
			}
			e.Severidad = Peor(e.Severidad, sev)
			break
		}
		e.Severidad = Peor(e.Severidad, Intrusion)
	case model.TunelSolicitado:
		// Pedir un tunel no es tantear: es servirse de la maquina. Pesa
		// como una intrusion aunque no llegue a teclearse un solo comando.
		e.Severidad = Peor(e.Severidad, Intrusion)
		anadir(&e.Tuneles, ev.Detalle["destino"], 20)

	case model.DescargaFichero:
		e.Severidad = Peor(e.Severidad, Intrusion)
		anadir(&e.Descargas, primero(ev.Detalle, "url", "fichero"), 20)
	case model.PeticionHTTP:
		e.Severidad = Peor(e.Severidad, Tanteo)
		anadir(&e.Rutas, ev.Detalle["ruta"], 30)
	}

	// La clasificacion del evento tambien cuenta: una peticion HTTP a
	// /.env es un tanteo aunque el tipo por si solo no lo diga.
	if ev.Clasificacion == model.Revisar || ev.Clasificacion == model.Notable {
		e.Severidad = Peor(e.Severidad, Tanteo)
		anadir(&e.Motivos, ev.Motivo, 5)
	}
}

// redactar resume el episodio en una frase.
//
// Se escribe en el orden en que a alguien le importa: primero si entro,
// luego que hizo dentro, y solo al final cuanto insistio.
func Redactar(e Episodio, idioma string) string { return e.redactar(idioma) }

func (e *Episodio) redactar(idioma string) string {
	tr := func(es, en string) string {
		if idioma == "en" {
			return en
		}
		return es
	}
	var partes []string

	if e.CeboMordido != "" {
		partes = append(partes, tr("mordio el cebo plantado", "took the planted bait"))
	}

	if e.LoginExitoso {
		if u := ultimo(e.Usuarios); u != "" {
			partes = append(partes, tr("entro como "+u, "entered as "+u))
		} else {
			partes = append(partes, tr("entro", "entered"))
		}
	}
	if n := len(e.Comandos); n > 0 {
		// "Ejecuto 4 comandos" sobre un PING de Redis suena a intrusion y
		// no lo es. El verbo tiene que decir la verdad de lo que paso.
		if saber.SinShell(e.Protocolo) && orden[e.Severidad] < orden[Intrusion] {
			partes = append(partes, tr(
				"sondeo el servicio con "+plural(n, "orden", "ordenes"),
				"probed the service with "+plural(n, "command", "commands")))
		} else {
			partes = append(partes, tr(
				"ejecuto "+plural(n, "comando", "comandos"),
				"ran "+plural(n, "command", "commands")))
		}
	}
	if n := len(e.Descargas); n > 0 {
		partes = append(partes, tr(
			"intento descargar "+plural(n, "fichero", "ficheros"),
			"tried to download "+plural(n, "file", "files")))
	}
	if n := len(e.Tuneles); n > 0 {
		dest := strings.Join(recorta(e.Tuneles, 2), ", ")
		partes = append(partes, tr(
			"intento usar el servidor de pasarela hacia "+dest,
			"tried to use the server as a relay toward "+dest))
	}
	if e.LoginsFallidos > 0 {
		partes = append(partes, tr(
			"probo "+plural(e.LoginsFallidos, "credencial", "credenciales"),
			"tried "+plural(e.LoginsFallidos, "credential", "credentials")))
	}
	if n := len(e.Rutas); n > 0 {
		partes = append(partes, tr(
			"tanteo "+plural(n, "ruta", "rutas"),
			"probed "+plural(n, "path", "paths")))
	}

	if len(partes) == 0 {
		// Sin hallazgos por tipo de evento, pero con severidad elevada, el
		// motivo del clasificador es lo unico que explica la etiqueta.
		if len(e.Motivos) > 0 {
			return mayuscula(saber.Nota{Que: e.Motivos[0]}.En(idioma).Que)
		}
		// Decir "solo conecto" desaprovecha lo que sabemos: quien llamo,
		// a que puerto y que se fue sin decir nada. Eso es un sondeo de
		// puertos, y nombrarlo asi ahorra tener que deducirlo.
		if e.SoloConexiones {
			donde := tr("el servicio", "the service")
			if e.Puerto != "" {
				donde = tr("el puerto "+e.Puerto, "port "+e.Puerto)
			}
			return mayuscula(tr(
				"comprobo que "+donde+" estuviera abierto y se fue sin enviar nada ("+plural(e.Eventos, "vez", "veces")+")",
				"checked that "+donde+" was open and left without sending anything ("+plural(e.Eventos, "time", "times")+")"))
		}
		return mayuscula(tr(
			"solo conecto, "+plural(e.Eventos, "vez", "veces"),
			"only connected, "+plural(e.Eventos, "time", "times")))
	}
	return mayuscula(strings.Join(partes, "; "))
}

// PorGravedad ordena los episodios para ensenarlos: primero los graves y,
// a igual gravedad, los mas recientes.
func PorGravedad(es []Episodio) {
	sort.SliceStable(es, func(i, j int) bool {
		if orden[es[i].Severidad] != orden[es[j].Severidad] {
			return orden[es[i].Severidad] > orden[es[j].Severidad]
		}
		return es[i].Fin.After(es[j].Fin)
	})
}

// anadir mete un valor si no esta ya y queda sitio. El tope evita que un
// bot con un diccionario de cien mil contrasenas haga crecer una fila sin
// limite.
func anadir(destino *[]string, valor string, tope int) {
	if valor == "" || len(*destino) >= tope {
		return
	}
	for _, v := range *destino {
		if v == valor {
			return
		}
	}
	*destino = append(*destino, valor)
}

func primero(m map[string]string, claves ...string) string {
	for _, c := range claves {
		if v := m[c]; v != "" {
			return v
		}
	}
	return ""
}

func ultimo(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[len(s)-1]
}

func plural(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return fmt.Sprintf("%d %s", n, plural)
}

func mayuscula(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// recorta limita una lista para citarla en una frase.
func recorta(v []string, n int) []string {
	if len(v) <= n {
		return v
	}
	return append(append([]string(nil), v[:n]...), "...")
}
