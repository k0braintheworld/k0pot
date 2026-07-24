package report

import (
	"strings"
	"testing"
)

// Los filtros de algunos modelos leen "explica este ataque" como una
// peticion de ayuda para atacar, aunque el material sean los registros de
// tu propia maquina. Paso de verdad: el panel llego a mostrar
// "I'm sorry, but I can't help with that" como si fuera el analisis.
func TestSeReconoceLaNegativaDelModelo(t *testing.T) {
	negativas := []string{
		"I'm sorry, but I can't help with that.",
		"I am sorry, I cannot help with this request.",
		"Sorry, I can't assist with that.",
		"Lo siento, pero no puedo ayudarte con eso.",
		"",
		"   ",
	}
	for _, n := range negativas {
		if !EsNegativa(n) {
			t.Errorf("no se reconocio como negativa: %q", n)
		}
	}
}

// Un analisis de verdad no puede confundirse con una negativa, ni aunque
// mencione de pasada que algo no se puede determinar.
func TestUnAnalisisRealNoSeTomaPorNegativa(t *testing.T) {
	buenos := []string{
		"Buscaban inventariar servidores SSH accesibles. No pasaron de llamar " +
			"a la puerta: se identificaron con una herramienta de escaneo y cerraron " +
			"la conexion sin probar credenciales. En un servidor real esto seria el " +
			"ruido habitual de internet y no requeriria ninguna accion.",
		strings.Repeat("Entraron como root y ejecutaron comandos. ", 12) +
			"I'm sorry no aplica aqui, es parte del texto.",
	}
	for _, b := range buenos {
		if EsNegativa(b) {
			t.Errorf("un analisis real se tomo por negativa: %.60s...", b)
		}
	}
}

// El encuadre defensivo tiene que estar, y por delante: sin el, el filtro
// del modelo lee la peticion como ayuda para atacar.
func TestElPromptDelAtaqueEncuadraQueEsDefensivo(t *testing.T) {
	// Los saltos de linea del prompt parten las frases, asi que se
	// normalizan antes de buscarlas: si no, el test falla por como esta
	// maquetado el texto y no por lo que dice.
	p := strings.Join(strings.Fields(strings.ToLower(sistemaAtaque)), " ")
	for _, imprescindible := range []string{
		"defensiva", "su propia maquina", "senuelo",
		"no das instrucciones para atacar", "victima",
	} {
		if !strings.Contains(p, imprescindible) {
			t.Errorf("el prompt no dice %q", imprescindible)
		}
	}
	// Y el encuadre va antes que la peticion, no al final.
	if strings.Index(p, "defensiva") > strings.Index(p, "te dan la secuencia completa") {
		t.Error("el encuadre deberia ir por delante de lo que se pide")
	}
}
