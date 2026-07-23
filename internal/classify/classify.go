// Package classify decide cuanta atencion humana merece cada evento.
//
// Es la pieza que convierte un monton de eventos en una senal util. La
// regla de fondo: la inmensa mayoria del trafico que ve un honeypot es
// ruido automatizado, y decirlo claramente vale mas que alarmar por todo.
//
// Cada regla que dispara devuelve tambien el motivo en lenguaje llano,
// para que los informes puedan explicar el porque sin recalcular nada.
package classify

import (
	"fmt"
	"strings"

	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/saber"
)

// Resultado es el veredicto sobre un evento.
type Resultado struct {
	Clasificacion model.Clasificacion
	// Motivo explica la decision en una frase entendible por alguien que
	// no sea analista de seguridad.
	Motivo string
}

// Umbrales agrupa los valores ajustables. Son criterio de producto, no
// constantes tecnicas: subirlos hace a honey mas callado, bajarlos mas
// alarmista.
type Umbrales struct {
	// ReputacionAlta es la puntuacion de AbuseIPDB (0-100) a partir de la
	// cual una IP se considera conocida por atacar.
	ReputacionAlta int
	// DenunciasAltas es el numero de denuncias acumuladas que confirma
	// que la IP lleva tiempo dando guerra.
	DenunciasAltas int
}

// UmbralesPorDefecto son los valores de partida.
//
// 75/100 en AbuseIPDB es su propio corte para "confianza alta" en que la
// IP es maliciosa. Por debajo hay demasiadas IPs denunciadas una sola vez
// por error como para tratarlas distinto del ruido.
func UmbralesPorDefecto() Umbrales {
	return Umbrales{ReputacionAlta: 75, DenunciasAltas: 100}
}

// Clasificador aplica las reglas.
type Clasificador struct {
	Umbrales Umbrales
}

// Nuevo crea un clasificador con los umbrales por defecto.
func Nuevo() *Clasificador {
	return &Clasificador{Umbrales: UmbralesPorDefecto()}
}

// Clasificar emite el veredicto de un evento.
//
// origen puede venir vacio: el enriquecimiento es asincrono y llega
// despues. En ese caso se clasifica solo con lo que el evento dice de si
// mismo, y basta con volver a clasificar cuando el contexto aparezca.
func (c *Clasificador) Clasificar(ev *model.Evento, origen model.Origen) Resultado {
	// Lo que el atacante HACE pesa mas que quien sea: ejecutar comandos o
	// descargar ficheros es haber entrado y estar actuando, no llamar a
	// la puerta. Por eso estas reglas van primero.
	if r, ok := c.porAccion(ev); ok {
		return r
	}
	if r, ok := c.porOrigen(ev, origen); ok {
		return r
	}
	return Resultado{
		Clasificacion: model.RuidoFondo,
		Motivo:        "escaneo automatizado, el ruido habitual de internet",
	}
}

// porAccion mira lo que hizo el atacante dentro del honeypot.
func (c *Clasificador) porAccion(ev *model.Evento) (Resultado, bool) {
	switch ev.Tipo {
	case model.DescargaFichero:
		return Resultado{
			Clasificacion: model.Notable,
			Motivo: "intento descargar un fichero al sistema, tipico de " +
				"quien quiere dejar malware instalado",
		}, true

	case model.TunelSolicitado:
		destino := ev.Detalle["destino"]
		motivo := "intento usar el servidor de pasarela para reenviar trafico ajeno"
		if destino != "" {
			motivo += " hacia " + destino
		}
		return Resultado{Clasificacion: model.Notable, Motivo: motivo}, true

	case model.ComandoEjecutado:
		comando := ev.Detalle["comando"]
		if patron, desc := patronMalicioso(comando); patron != "" {
			return Resultado{
				Clasificacion: model.Notable,
				Motivo:        "ejecuto comandos para " + desc,
			}, true
		}
		// Un comando solo significa "esta dentro del sistema" si venia por
		// una shell. En Redis o FTP, "comando" es una orden del protocolo:
		// un PING no es nadie actuando dentro de la maquina, y tratarlo
		// como notable ahogaria las alertas de verdad.
		if saber.SinShell(ev.Protocolo) {
			return Resultado{
				Clasificacion: model.RuidoFondo,
				Motivo: fmt.Sprintf("hablo el protocolo %s sin hacer nada llamativo",
					ev.Protocolo),
			}, true
		}
		return Resultado{
			Clasificacion: model.Notable,
			Motivo: "ejecuto comandos dentro del sistema: ya no es un " +
				"escaneo, alguien esta actuando",
		}, true

	case model.PeticionHTTP:
		// El escaneo web es ruido puro salvo que la ruta delate a que va.
		if ruta := ev.Detalle["ruta"]; ruta != "" {
			if _, desc := patronMalicioso(ruta); desc != "" {
				return Resultado{
					Clasificacion: model.Revisar,
					Motivo:        "pidio una ruta que busca " + desc,
				}, true
			}
			if desc := rutaSospechosa(ruta); desc != "" {
				return Resultado{
					Clasificacion: model.Revisar,
					Motivo:        "busco " + desc,
				}, true
			}
		}
		return Resultado{}, false

	case model.LoginExitoso:
		return Resultado{
			Clasificacion: model.Revisar,
			Motivo:        "consiguio entrar con las credenciales que probo",
		}, true
	}
	return Resultado{}, false
}

// porOrigen mira quien esta detras de la IP.
func (c *Clasificador) porOrigen(ev *model.Evento, o model.Origen) (Resultado, bool) {
	if !o.Enriquecido {
		return Resultado{}, false
	}

	if o.Tor {
		return Resultado{
			Clasificacion: model.Revisar,
			Motivo: "llega desde la red Tor, es decir, alguien que se " +
				"molesta en ocultar de donde viene",
		}, true
	}

	if o.Reputacion >= c.Umbrales.ReputacionAlta {
		motivo := fmt.Sprintf(
			"procede de una IP con mala fama (%d/100 en AbuseIPDB", o.Reputacion)
		if o.TotalReportes >= c.Umbrales.DenunciasAltas {
			motivo += fmt.Sprintf(", %d denuncias acumuladas", o.TotalReportes)
		}
		return Resultado{Clasificacion: model.Revisar, Motivo: motivo + ")"}, true
	}

	return Resultado{}, false
}

// rutasSospechosas son las que piden los escaneres web buscando algo
// concreto. La descripcion se publica tal cual en el informe.
var rutasSospechosas = []struct {
	claves []string
	que    string
}{
	{[]string{"/.env", "/.git/", "/config.php", "/wp-config"},
		"ficheros de configuracion con contrasenas dentro"},
	{[]string{"/wp-admin", "/wp-login", "/administrator", "/phpmyadmin", "/manager/html"},
		"paneles de administracion"},
	{[]string{"${jndi:", "/solr/", "/struts", "cgi-bin"},
		"vulnerabilidades conocidas para ejecutar codigo"},
	{[]string{"/.aws/", "/.ssh/", "id_rsa", "credentials"},
		"credenciales y llaves guardadas en el servidor"},
	{[]string{"/shell", "/cmd", "/backdoor", ".php?cmd="},
		"puertas traseras dejadas por otro atacante"},
}

func rutaSospechosa(ruta string) string {
	r := strings.ToLower(ruta)
	for _, p := range rutasSospechosas {
		for _, clave := range p.claves {
			if strings.Contains(r, clave) {
				return p.que
			}
		}
	}
	return ""
}

// patronesMaliciosos empareja lo que se ve en un comando con lo que el
// atacante esta intentando conseguir. La descripcion se reutiliza tal cual
// en los informes, asi que esta escrita para que la entienda cualquiera.
var patronesMaliciosos = []struct {
	claves []string
	que    string
}{
	{[]string{"wget", "curl", "tftp"},
		"traerse programas de fuera al servidor"},
	{[]string{"chmod +x", "chmod 777", "chmod 755"},
		"dar permisos de ejecucion a un fichero que acaba de dejar"},
	{[]string{"xmrig", "minerd", "stratum+tcp", "cpuminer"},
		"poner el servidor a minar criptomonedas"},
	{[]string{"history -c", "unset histfile", "rm -rf /var/log", "shred"},
		"borrar sus huellas del sistema"},
	{[]string{"base64 -d", "base64 --decode", "echo -e \\x"},
		"ocultar lo que ejecuta detras de texto codificado"},
	{[]string{"busybox", "/dev/tcp/", "nc -e", "ncat -e"},
		"abrir una conexion de vuelta hacia su maquina"},
	{[]string{"authorized_keys", "ssh-rsa ", "ssh-ed25519 "},
		"dejarse una llave para poder volver a entrar cuando quiera"},
	{[]string{"passwd", "useradd", "adduser"},
		"crearse un usuario propio o cambiar contrasenas"},
	{[]string{"/etc/shadow", "/etc/passwd"},
		"leer el fichero de contrasenas del sistema"},
	{[]string{"iptables -f", "ufw disable", "systemctl stop"},
		"desactivar defensas del servidor"},
}

// patronMalicioso busca en un comando alguna intencion reconocible.
// Devuelve la clave que encajo y su descripcion.
func patronMalicioso(comando string) (string, string) {
	c := strings.ToLower(comando)
	for _, p := range patronesMaliciosos {
		for _, clave := range p.claves {
			if strings.Contains(c, clave) {
				return clave, p.que
			}
		}
	}
	return "", ""
}
