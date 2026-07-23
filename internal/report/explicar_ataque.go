package report

import (
	"context"
	"fmt"
	"strings"

	"github.com/k0braintheworld/k0pot/internal/store"
)

// Explicador es un generador al que se le puede preguntar cualquier cosa,
// no solo el informe del periodo.
//
// Es una interfaz aparte y opcional a proposito: PorReglas no la cumple, y
// no deberia. Explicar un ataque concreto en lenguaje natural es justo lo
// que un modelo hace bien y unas reglas no pueden fingir.
type Explicador interface {
	Preguntar(ctx context.Context, sistema, usuario string, tope int) (string, error)
}

// sistemaAtaque encuadra la explicacion de UN ataque.
//
// Es mas corto y mas concreto que el del informe del periodo: aqui no hay
// que resumir cifras, hay que contar una historia que ya esta ordenada. El
// encuadre de senuelo se repite porque el modelo no ve el otro prompt.
const sistemaAtaque = `Explicas UN ataque concreto a alguien que administra
un servidor pequeno y no es experto en seguridad.

Esto es un SENUELO: una maquina puesta ahi a proposito para que la ataquen,
aislada y sin nada de valor. Que entren no es un incidente, es la trampa
funcionando. NUNCA recomiendes aislarla, reinstalarla, cambiar sus
contrasenas ni bloquear IPs en ella: eso seria cerrar la trampa.

Te dan la secuencia completa, paso a paso. Responde tres cosas, en este
orden y sin titulos ni listas:

1. QUE QUERIAN. El proposito, en una frase: reclutar el equipo en una
   botnet, minar, usarlo de pasarela, robar credenciales, buscar un fallo
   concreto.
2. QUE CONSIGUIERON. Si entraron o no, y hasta donde llegaron. Se claro:
   "no pasaron de llamar a la puerta" es una respuesta perfecta.
3. QUE SIGNIFICARIA EN UN SERVIDOR DE VERDAD, y que habria que mirar alli.
   Esa es la parte aprovechable.

Lo que va [entre corchetes] sale de nuestro catalogo y es fiable: usalo.
Para lo que no lo lleve, describe lo que se ve sin inventar que significa.

Espanol, tono tranquilo, sin jerga sin explicar, sin markdown. Entre 80 y
140 palabras. Si el ataque es un simple escaneo, dilo y se breve: no hay
que estirar lo que no da mas de si.`

// PasoDeAtaque es una linea de la narracion, tal y como se le cuenta al
// modelo.
type PasoDeAtaque struct {
	Hora  string
	Texto string
	// Nota es lo que sabemos de ese paso, si lo sabemos.
	Nota string
}

// ExplicarAtaque pide al modelo que cuente un ataque concreto.
func ExplicarAtaque(ctx context.Context, e Explicador, ep store.EpisodioFila,
	pasos []PasoDeAtaque, notaProveedor string, tope int) (string, error) {
	if e == nil {
		return "", fmt.Errorf("no hay ningun modelo configurado")
	}
	return e.Preguntar(ctx, sistemaAtaque, ataqueComoTexto(ep, pasos, notaProveedor), tope)
}

// ataqueComoTexto describe el ataque para el modelo.
func ataqueComoTexto(ep store.EpisodioFila, pasos []PasoDeAtaque, notaProveedor string) string {
	var b strings.Builder

	fmt.Fprintf(&b, "ATAQUE contra el servicio %s, gravedad %s\n",
		ep.Protocolo, strings.ToUpper(string(ep.Severidad)))
	fmt.Fprintf(&b, "Origen: %s", ep.IP)
	if ep.Pais != "" {
		fmt.Fprintf(&b, ", pais %s", ep.Pais)
	}
	if ep.ISP != "" {
		fmt.Fprintf(&b, ", proveedor %s", ep.ISP)
		if notaProveedor != "" {
			fmt.Fprintf(&b, " [%s]", notaProveedor)
		}
	}
	if ep.Reputacion > 0 {
		fmt.Fprintf(&b, ", reputacion %d/100 en AbuseIPDB", ep.Reputacion)
	}
	fmt.Fprintf(&b, "\nCuando: %s, durante %s\n\n",
		ep.Inicio.Local().Format("02/01 15:04"), duracionLegible(ep.Duracion()))

	b.WriteString("SECUENCIA COMPLETA:\n")
	for i, p := range pasos {
		if i == 60 {
			fmt.Fprintf(&b, "  (y %d pasos mas, del mismo tipo)\n", len(pasos)-60)
			break
		}
		fmt.Fprintf(&b, "  %s  %s\n", p.Hora, p.Texto)
		if p.Nota != "" {
			fmt.Fprintf(&b, "            [%s]\n", p.Nota)
		}
	}
	return b.String()
}
