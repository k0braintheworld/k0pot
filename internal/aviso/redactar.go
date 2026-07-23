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
func Redactar(eps []store.EpisodioFila, enlace string) (Mensaje, bool) {
	if len(eps) == 0 {
		return Mensaje{}, false
	}
	// Se ordena aqui con el mismo criterio que el panel: lo primero que se
	// lee en la notificacion tiene que ser lo mas grave.
	sort.SliceStable(eps, func(i, j int) bool {
		return episodio.Rango(eps[i].Severidad) > episodio.Rango(eps[j].Severidad)
	})
	peor := eps[0].Severidad

	var b strings.Builder
	for i, e := range eps {
		if i == topeEnMensaje {
			fmt.Fprintf(&b, "\n(y %d mas)", len(eps)-topeEnMensaje)
			break
		}
		if i > 0 {
			b.WriteString("\n\n")
		}
		fmt.Fprintf(&b, "%s desde %s", strings.ToUpper(string(e.Severidad)), e.IP)
		if e.Pais != "" {
			fmt.Fprintf(&b, " (%s)", e.Pais)
		}
		fmt.Fprintf(&b, "\n%s contra %s", e.Resumen, e.Protocolo)
		if e.ISP != "" {
			fmt.Fprintf(&b, "\n%s", e.ISP)
		}
	}

	return Mensaje{
		Titulo:  titulo(eps, peor),
		Cuerpo:  b.String(),
		Urgente: peor == episodio.Intrusion,
		Enlace:  enlace,
	}, true
}

func titulo(eps []store.EpisodioFila, peor episodio.Severidad) string {
	que := "Acceso al honeypot"
	if peor == episodio.Intrusion {
		que = "Intrusion en el honeypot"
	}
	if len(eps) == 1 {
		return fmt.Sprintf("k0Pot: %s desde %s", que, eps[0].IP)
	}
	return fmt.Sprintf("k0Pot: %s y %d ataques mas", que, len(eps)-1)
}

// DePrueba arma un aviso de ejemplo, para poder comprobar la configuracion
// sin esperar a que alguien ataque de verdad.
func DePrueba(enlace string) Mensaje {
	return Mensaje{
		Titulo: "k0Pot: aviso de prueba",
		Cuerpo: "Si lees esto, los avisos estan bien configurados.\n\n" +
			"A partir de ahora recibiras uno cuando alguien consiga entrar " +
			"en el honeypot o se sirva de el. El ruido de fondo -escaneos y " +
			"contrasenas por defecto- no genera avisos.",
		Enlace: enlace,
	}
}
