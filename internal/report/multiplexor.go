package report

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// ModeloGen es un modelo concreto dentro del multiplexor: su id (para el
// estado de tokens) y el generador que lo habla.
type ModeloGen struct {
	ID  string
	Gen Explicador
}

// Multiplexor usa varios modelos EN ORDEN: el primero con tokens disponibles.
// Si uno se agota (429), lo marca y sigue con el siguiente; cuando se recupera,
// vuelve a el por ser antes en la lista. Asi el failover es automatico y la
// prioridad la pone el orden.
type Multiplexor struct {
	Modelos []ModeloGen
	// Disponible dice si un modelo tiene tokens ahora (nil = siempre si).
	Disponible func(id string) bool
	// AlAgotar marca que un modelo se quedo sin tokens (un 429).
	AlAgotar func(id string, err error)
	// Respaldo redacta por reglas cuando no hay ningun modelo utilizable.
	Respaldo Generador
}

func (m *Multiplexor) Nombre() string { return "multi" }

func (m *Multiplexor) Preguntar(ctx context.Context, sistema, usuario string, tope int) (string, error) {
	var ultimo error
	probados := 0
	for _, mo := range m.Modelos {
		if m.Disponible != nil && !m.Disponible(mo.ID) {
			continue
		}
		probados++
		texto, err := mo.Gen.Preguntar(ctx, sistema, usuario, tope)
		if err == nil {
			return texto, nil
		}
		ultimo = err
		if EsLimiteDeRitmo(err) && m.AlAgotar != nil {
			m.AlAgotar(mo.ID, err)
		}
		// Cualquier error: se prueba el siguiente modelo.
	}
	if ultimo == nil {
		ultimo = fmt.Errorf("ningun modelo con tokens disponibles")
	}
	_ = probados
	return "", ultimo
}

// Generar (informe) usa el primer modelo disponible; si ninguno, las reglas.
func (m *Multiplexor) Generar(ctx context.Context, d Datos) (Resultado, error) {
	for _, mo := range m.Modelos {
		if m.Disponible != nil && !m.Disponible(mo.ID) {
			continue
		}
		if g, ok := mo.Gen.(Generador); ok {
			return g.Generar(ctx, d)
		}
	}
	if m.Respaldo != nil {
		return m.Respaldo.Generar(ctx, d)
	}
	return Resultado{}, fmt.Errorf("ningun modelo disponible")
}

// EsLimiteDeRitmo reconoce el 429 de cuota agotada del proveedor.
func EsLimiteDeRitmo(err error) bool {
	if err == nil {
		return false
	}
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "429") || strings.Contains(m, "rate limit") || strings.Contains(m, "too many requests")
}

var reLimiteDiario = regexp.MustCompile(`(?i)tokens per day.*?limit\s+(\d+)`)

// LimiteDiarioDeTokens extrae el tope de tokens POR DIA del mensaje 429, si lo
// trae. El por-minuto se ignora: interesa el presupuesto del dia.
func LimiteDiarioDeTokens(err error) int {
	if err == nil {
		return 0
	}
	if mm := reLimiteDiario.FindStringSubmatch(err.Error()); len(mm) == 2 {
		n, _ := strconv.Atoi(mm[1])
		return n
	}
	return 0
}
