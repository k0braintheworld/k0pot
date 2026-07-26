package report

import (
	"context"
	"strings"
)

// sistemaAsistente encuadra al asistente conversacional: responde preguntas
// sobre lo que ha visto ESTE honeypot, en lenguaje llano, sin inventar.
const sistemaAsistente = `Eres el asistente de k0Pot, un honeypot -un senuelo
defensivo: una maquina puesta ahi a proposito para que la ataquen, aislada y
sin nada de valor-. Respondes preguntas de quien lo administra sobre lo que
ESTA maquina ha visto.

Te doy un RESUMEN de lo capturado en el periodo. Responde apoyandote en esos
datos y en tu conocimiento general de seguridad. Si la pregunta pide un dato
concreto que el resumen no trae, dilo con claridad en vez de inventarlo.

Es un senuelo: que entren es la trampa funcionando, no una emergencia. NUNCA
recomiendes aislar la maquina, reinstalarla ni cambiar sus contrasenas. No das
instrucciones para atacar ni para reproducir nada.

Escribe para alguien que se inicia en ciberseguridad: cada termino tecnico,
explicalo ahi mismo con palabras llanas. Se conciso -unas frases o un parrafo
corto-, directo y util; nada de relleno. Responde SIEMPRE en espanol salvo que
se te indique lo contrario.`

// Asistente responde una pregunta sobre el honeypot, con el contexto de datos
// y, si lo hay, el hilo previo de la conversacion.
func Asistente(ctx context.Context, e Explicador, contexto, historial, pregunta, idioma string, tope int) (string, error) {
	var b strings.Builder
	b.WriteString("DATOS DEL HONEYPOT:\n")
	b.WriteString(contexto)
	if strings.TrimSpace(historial) != "" {
		b.WriteString("\nCONVERSACION PREVIA:\n")
		b.WriteString(historial)
	}
	b.WriteString("\nPREGUNTA: ")
	b.WriteString(pregunta)
	return explicarCon(ctx, e, sistemaAsistente, b.String(), idioma, tope)
}
