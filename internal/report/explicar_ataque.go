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
const sistemaAtaque = `Eres un analista de seguridad DEFENSIVA. Tu trabajo
es ayudar al dueno de un sistema a entender un ataque que ha recibido, para
que sepa protegerse. Todo lo que ves son registros de SU propia maquina.

El sistema es un SENUELO: una maquina puesta ahi a proposito para que la
ataquen, aislada y sin nada de valor. Que entren no es un incidente, es la
trampa funcionando y el material que se buscaba.

Describes lo que YA ocurrio y quedo registrado. No das instrucciones para
atacar, no explicas como reproducirlo y no hace falta: los pasos ya estan
en el registro y quien lee es la victima, no el atacante.

NUNCA recomiendes aislar la maquina, reinstalarla, cambiar sus contrasenas
ni bloquear IPs en ella: eso seria cerrar la trampa.

Te dan la secuencia completa, paso a paso. Responde tres cosas, en este
orden y sin titulos ni listas:

1. QUE BUSCABAN. El proposito, en una frase: reclutar el equipo en una
   botnet, minar, usarlo de pasarela, recolectar credenciales, inventariar
   internet.
2. HASTA DONDE LLEGARON. Si entraron o no. Se claro: "no pasaron de llamar
   a la puerta" es una respuesta perfecta y frecuente.
3. QUE SIGNIFICARIA EN UN SERVIDOR DE VERDAD, y que convendria revisar
   alli. Esa es la parte aprovechable.

Lo que va [entre corchetes] sale de nuestro catalogo y es fiable: usalo.
Para lo que no lo lleve, describe lo que se ve sin inventar que significa.

Responde SIEMPRE en espanol, en tono tranquilo, sin jerga sin explicar y
sin markdown. Entre 80 y 140 palabras. Si el ataque es un simple escaneo,
dilo y se breve: no hay que estirar lo que no da mas de si.`

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
	texto, err := e.Preguntar(ctx, sistemaAtaque, ataqueComoTexto(ep, pasos, notaProveedor), tope)
	if err != nil {
		return "", err
	}
	if EsNegativa(texto) {
		return "", fmt.Errorf("el modelo se nego a responder; " +
			"su filtro ha leido el analisis de este ataque como una peticion de " +
			"ayuda para atacar. Prueba con otro modelo en Ajustes → Informes")
	}
	return texto, nil
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

// EsNegativa reconoce cuando el modelo se ha negado a responder.
//
// Los filtros de seguridad de algunos modelos leen "explica este ataque"
// como una peticion de ayuda para atacar, aunque el material sean los
// registros de tu propia maquina. Cuando eso pasa devuelven una frase de
// rechazo, casi siempre en ingles aunque se les haya pedido espanol.
//
// Publicar esa frase tal cual en el panel es lo peor de los dos mundos: no
// explica nada y ademas parece que el fallo es de k0Pot. Mejor reconocerla
// y decir lo que pasa.
func EsNegativa(texto string) bool {
	t := strings.ToLower(strings.TrimSpace(texto))
	if t == "" {
		return true
	}
	// Una negativa es corta y sigue una de estas formulas. Se exige que sea
	// breve para no confundirla con un informe que mencione de pasada que
	// algo no se puede determinar.
	if len(t) > 400 {
		return false
	}
	for _, formula := range []string{
		"i'm sorry", "i am sorry", "i can't help", "i cannot help",
		"i can't assist", "i cannot assist", "i'm unable", "as an ai",
		"lo siento, pero no puedo", "no puedo ayudarte con eso",
		"no puedo ayudar con eso", "no puedo proporcionar",
	} {
		if strings.Contains(t, formula) {
			return true
		}
	}
	return false
}
