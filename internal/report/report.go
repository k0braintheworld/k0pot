// Package report convierte las cifras capturadas en algo que una persona
// entienda sin ser analista de seguridad.
//
// El diseno es hibrido a proposito:
//
//   - PorReglas es determinista, instantaneo y gratis. Cubre el semaforo
//     diario y todo lo rutinario, que es la inmensa mayoria de las veces
//     que se genera un informe.
//   - ConLLM solo entra donde el lenguaje natural aporta de verdad: el
//     resumen semanal y las alertas notables.
//
// Ambos cumplen la misma interfaz, asi que honey funciona igual sin
// conexion ni clave de API: solo cambia lo rico que suena el texto.
package report

import (
	"context"
	"fmt"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// Datos es todo lo que un informe necesita saber. Se construye una vez y
// lo comparten los dos generadores.
type Datos struct {
	Desde      time.Time
	Hasta      time.Time
	Resumen    *store.Resumen
	Niveles    map[model.Clasificacion]int
	Destacados []store.Destacado
	// Episodios son los ataques ya agrupados. Es lo que convierte el
	// informe en una narracion en vez de un parte de cifras.
	Episodios []store.EpisodioFila
}

// Resultado es un informe y la firma de quien lo redacto.
//
// La firma la devuelve la propia llamada, no una consulta aparte: si
// ConLLM se repliega en las reglas, el resultado tiene que decir que lo
// escribieron las reglas. Atribuir el texto a quien no lo produjo seria
// mentirle a quien lee el panel.
type Resultado struct {
	Texto     string
	Redactado string
}

// Generador produce el texto de un informe.
type Generador interface {
	Generar(ctx context.Context, d Datos) (Resultado, error)
	// Nombre es el generador configurado, que puede no ser el que acabe
	// redactando si hay que replegarse.
	Nombre() string
}

// Nivel resume en una palabra si hay algo de lo que preocuparse.
type Nivel string

const (
	Verde Nivel = "VERDE"
	Ambar Nivel = "AMBAR"
	Rojo  Nivel = "ROJO"
)

// NivelDe decide el color del semaforo a partir de los recuentos.
//
// La regla es deliberadamente simple: manda lo que el atacante hizo. Un
// solo evento notable pone el semaforo en rojo aunque haya diez mil
// eventos de ruido, porque diez mil bots llamando a la puerta importan
// menos que uno que entro.
func NivelDe(niveles map[model.Clasificacion]int) Nivel {
	switch {
	case niveles[model.Notable] > 0:
		return Rojo
	case niveles[model.Revisar] > 0:
		return Ambar
	default:
		return Verde
	}
}

// FraseSemaforo es la linea mas importante de cualquier informe: cuando no
// pasa nada hay que decirlo con claridad, no enterrar al lector en cifras.
func FraseSemaforo(niveles map[model.Clasificacion]int) string {
	notables := niveles[model.Notable]
	revisar := niveles[model.Revisar]

	switch NivelDe(niveles) {
	case Rojo:
		// "Piden que los mires", no "hay que actuar": en un senuelo que
		// alguien entre es la trampa funcionando, no una emergencia.
		return fmt.Sprintf("ROJO — %s merecen que los mires: "+
			"alguien no se limito a llamar a la puerta", plural(notables, "evento"))
	case Ambar:
		return fmt.Sprintf("AMBAR — %s se salen de lo normal, "+
			"pero nada indica que hayan entrado", plural(revisar, "evento"))
	default:
		return "VERDE — todo es ruido de fondo automatizado; " +
			"nada que mirar hoy"
	}
}

func plural(n int, palabra string) string {
	if n == 1 {
		return "1 " + palabra
	}
	return fmt.Sprintf("%d %ss", n, palabra)
}

// Total cuenta todos los eventos de un periodo.
func (d Datos) Total() int {
	if d.Resumen == nil {
		return 0
	}
	return d.Resumen.Total
}

// SinActividad indica que no hubo nada que contar.
func (d Datos) SinActividad() bool { return d.Total() == 0 }
