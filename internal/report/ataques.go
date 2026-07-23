package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/saber"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// topeAtaques acota cuantos ataques se le cuentan al modelo. Ordenados por
// gravedad, los primeros son los que importan; el resto solo engorda la
// factura sin cambiar el informe.
const topeAtaques = 12

// AtaquesComoTexto describe los ataques del periodo para el modelo.
//
// Es la seccion que mas cambia la calidad del informe. Con recuentos
// sueltos -"cuatro eventos con reputacion mala"- lo unico que puede hacer
// un modelo es parafrasear cifras. Con la secuencia de cada ataque puede
// hacer lo que de verdad aporta: contar que intentaban y por que.
//
// Cada observacion llega acompanada de lo que sabemos de ella, entre
// corchetes. No es adorno: sin esa anotacion el modelo explica de memoria
// que significa una ruta como /SDK/webLanguage, y lo hace con el mismo
// aplomo tanto si acierta como si no.
func AtaquesComoTexto(episodios []store.EpisodioFila) string {
	if len(episodios) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("ATAQUES DEL PERIODO (los mas graves primero).\n")
	b.WriteString("Lo que va [entre corchetes] es de nuestro catalogo, no lo cambies.\n\n")

	for i, e := range episodios {
		if i == topeAtaques {
			fmt.Fprintf(&b, "  (y %d ataques mas, todos de menor gravedad)\n",
				len(episodios)-topeAtaques)
			break
		}
		escribirAtaque(&b, e)
	}
	return b.String()
}

func escribirAtaque(b *strings.Builder, e store.EpisodioFila) {
	fmt.Fprintf(b, "- [%s] %s contra %s", strings.ToUpper(string(e.Severidad)), e.IP, e.Protocolo)
	if e.Pais != "" {
		fmt.Fprintf(b, ", pais %s", e.Pais)
	}
	if e.ISP != "" {
		fmt.Fprintf(b, ", proveedor %s", e.ISP)
		if n, hay := saber.DeProveedor(e.ISP); hay {
			fmt.Fprintf(b, " [%s: %s]", n.Que, n.Por)
		}
	}
	if e.Reputacion > 0 {
		fmt.Fprintf(b, ", reputacion %d/100", e.Reputacion)
	}
	b.WriteString("\n")

	fmt.Fprintf(b, "  cuando: %s, durante %s, %s\n",
		e.Inicio.Local().Format("02/01 15:04"), duracionLegible(e.Duracion()),
		plural(e.Eventos, "evento"))
	fmt.Fprintf(b, "  resumen: %s\n", e.Resumen)

	if e.LoginExitoso {
		b.WriteString("  CONSIGUIO ENTRAR\n")
	}
	if e.LoginsFallidos > 0 {
		fmt.Fprintf(b, "  credenciales probadas: %d intentos\n", e.LoginsFallidos)
	}

	conNotas(b, "  credenciales", e.Passwords, 5, func(v string) (saber.Nota, bool) {
		// Se prueba contra cada usuario visto: el diccionario identifica a
		// la familia de botnet aunque el usuario varie.
		for _, u := range e.Usuarios {
			if n, hay := saber.DeCredencial(u, v); hay {
				return n, true
			}
		}
		return saber.Nota{}, false
	})
	conNotas(b, "  comandos", e.Comandos, 8, saber.DeComando)
	conNotas(b, "  rutas pedidas", e.Rutas, 8, saber.DeRuta)
	conNotas(b, "  descargas", e.Descargas, 5, saber.DeRuta)
	b.WriteString("\n")
}

// conNotas escribe una lista anotando lo que se sabe de cada elemento.
func conNotas(b *strings.Builder, titulo string, valores []string, tope int,
	explicar func(string) (saber.Nota, bool)) {
	if len(valores) == 0 {
		return
	}
	fmt.Fprintf(b, "%s:\n", titulo)
	for i, v := range valores {
		if i == tope {
			fmt.Fprintf(b, "    (y %d mas)\n", len(valores)-tope)
			return
		}
		fmt.Fprintf(b, "    %s", v)
		if n, hay := explicar(v); hay {
			fmt.Fprintf(b, "  [%s: %s]", n.Que, n.Por)
		}
		b.WriteString("\n")
	}
}

func duracionLegible(d time.Duration) string {
	switch {
	case d < time.Second:
		// Un solo evento no dura nada; decir "0 segundos" suena a error.
		return "un instante"
	case d < time.Minute:
		return plural(int(d.Seconds()), "segundo")
	case d < time.Hour:
		return plural(int(d.Minutes()), "minuto")
	default:
		return fmt.Sprintf("%.1f horas", d.Hours())
	}
}
