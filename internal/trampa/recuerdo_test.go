package trampa

import (
	"testing"
	"time"
)

func TestEscaladoTarpit(t *testing.T) {
	casos := []struct {
		veces  int
		quiere time.Duration
	}{
		{0, 0}, {1, 0}, {3, 0}, // los primeros contactos no se castigan
		{4, tarpitPaso},
		{5, 2 * tarpitPaso},
		{1000, tarpitTope}, // con tope
	}
	for _, c := range casos {
		if got := escaladoTarpit(c.veces); got != c.quiere {
			t.Errorf("escaladoTarpit(%d) = %v, queria %v", c.veces, got, c.quiere)
		}
	}
}

// El primer contacto de una IP no debe tarpitear: solo la latencia creible.
func TestEsperarPrimerContactoEsBreve(t *testing.T) {
	r := &recuerdo{vistos: map[string]*visita{}}
	inicio := time.Now()
	r.esperar("9.9.9.9")
	if d := time.Since(inicio); d > 500*time.Millisecond {
		t.Fatalf("el primer contacto no deberia tarpitear: %v", d)
	}
}

// Quien vuelve tras la ventana de olvido empieza de cero, no arrastra castigo.
func TestRecuerdoOlvida(t *testing.T) {
	r := &recuerdo{vistos: map[string]*visita{}}
	r.vistos["1.2.3.4"] = &visita{veces: 50, ultima: time.Now().Add(-2 * ventanaOlvido)}
	r.esperar("1.2.3.4")
	if v := r.vistos["1.2.3.4"]; v.veces != 1 {
		t.Fatalf("tras olvidar deberia ser 1, fue %d", v.veces)
	}
}
