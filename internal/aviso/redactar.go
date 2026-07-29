package aviso

import (
	"fmt"
	"sort"
	"strings"

	"github.com/k0braintheworld/k0pot/internal/episodio"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// topeEnMensaje es cuantos ataques se detallan en un aviso. Si llegan
// treinta a la vez, treinta notificaciones son ruido y una lista de treinta
// no se lee en un movil: se detallan los primeros y se cuenta el resto.
const topeEnMensaje = 5

// Redactar convierte los ataques en el aviso que llega al movil.
//
// Se escribe para leerse en una notificacion, no en un panel: la primera
// linea tiene que bastar para decidir si hay que levantarse.
func Redactar(eps []store.EpisodioFila, enlace, idioma string) (Mensaje, bool) {
	if len(eps) == 0 {
		return Mensaje{}, false
	}
	// Se ordena aqui con el mismo criterio que el panel: lo primero que se
	// lee en la notificacion tiene que ser lo mas grave.
	sort.SliceStable(eps, func(i, j int) bool {
		return episodio.Rango(eps[i].Severidad) > episodio.Rango(eps[j].Severidad)
	})
	peor := eps[0].Severidad
	tr := func(es, en string) string {
		if idioma == "en" {
			return en
		}
		return es
	}

	var b strings.Builder
	for i, e := range eps {
		if i == topeEnMensaje {
			fmt.Fprintf(&b, tr("\n(y %d mas)", "\n(and %d more)"), len(eps)-topeEnMensaje)
			break
		}
		if i > 0 {
			b.WriteString("\n\n")
		}
		fmt.Fprintf(&b, tr("%s desde %s", "%s from %s"), strings.ToUpper(string(e.Severidad)), e.IP)
		if e.Pais != "" {
			fmt.Fprintf(&b, " (%s)", e.Pais)
		}
		// El resumen guardado esta en espanol; para "en" se rehace al vuelo.
		res := e.Resumen
		if idioma == "en" {
			res = episodio.Redactar(e.Episodio, idioma)
		}
		fmt.Fprintf(&b, tr("\n%s contra %s", "\n%s against %s"), res, e.Protocolo)
		if e.ISP != "" {
			fmt.Fprintf(&b, "\n%s", e.ISP)
		}
	}

	return Mensaje{
		Titulo:  titulo(eps, peor, idioma),
		Cuerpo:  b.String(),
		Urgente: episodio.Rango(peor) >= episodio.Rango(episodio.Intrusion),
		Enlace:  enlace,
	}, true
}

func titulo(eps []store.EpisodioFila, peor episodio.Severidad, idioma string) string {
	tr := func(es, en string) string {
		if idioma == "en" {
			return en
		}
		return es
	}
	que := tr("Acceso al honeypot", "Access to the honeypot")
	switch {
	case peor == episodio.Trampa:
		que = tr("Cebo mordido en el honeypot", "Bait taken in the honeypot")
	case peor == episodio.Intrusion:
		que = tr("Intrusion en el honeypot", "Intrusion in the honeypot")
	}
	if len(eps) == 1 {
		return fmt.Sprintf(tr("k0Pot: %s desde %s", "k0Pot: %s from %s"), que, eps[0].IP)
	}
	return fmt.Sprintf(tr("k0Pot: %s y %d ataques mas", "k0Pot: %s and %d more attacks"), que, len(eps)-1)
}

// DePrueba arma un aviso de ejemplo, para poder comprobar la configuracion
// sin esperar a que alguien ataque de verdad.
func DePrueba(enlace, idioma string) Mensaje {
	if idioma == "en" {
		return Mensaje{
			Titulo: "k0Pot: test alert",
			Cuerpo: "If you're reading this, alerts are set up correctly.\n\n" +
				"From now on you'll get one when someone gets into the honeypot " +
				"or uses it. Background noise -scans and default passwords- " +
				"triggers no alerts.",
			Enlace: enlace,
		}
	}
	return Mensaje{
		Titulo: "k0Pot: aviso de prueba",
		Cuerpo: "Si lees esto, los avisos estan bien configurados.\n\n" +
			"A partir de ahora recibiras uno cuando alguien consiga entrar " +
			"en el honeypot o se sirva de el. El ruido de fondo -escaneos y " +
			"contrasenas por defecto- no genera avisos.",
		Enlace: enlace,
	}
}
