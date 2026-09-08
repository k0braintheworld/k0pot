package web

import (
	"testing"
	"time"
)

func TestRetrasoLogin(t *testing.T) {
	casos := []struct {
		n int
		d time.Duration
	}{
		{0, 0}, {5, 0}, // hasta el umbral, sin castigo
		{6, loginPaso},
		{7, 2 * loginPaso},
		{1000, loginTope}, // con tope
	}
	for _, c := range casos {
		if got := retrasoLogin(c.n); got != c.d {
			t.Errorf("retrasoLogin(%d) = %v, queria %v", c.n, got, c.d)
		}
	}
}

func TestLimitadorLoginFlujo(t *testing.T) {
	l := nuevoLimitadorLogin()
	ip := "203.0.113.7"
	if l.penalizacion(ip) != 0 {
		t.Fatal("sin fallos no deberia penalizar")
	}
	for i := 0; i < 7; i++ {
		l.fallo(ip)
	}
	if l.penalizacion(ip) == 0 {
		t.Fatal("tras 7 fallos deberia penalizar")
	}
	l.exito(ip)
	if l.penalizacion(ip) != 0 {
		t.Fatal("acertar deberia limpiar el historial")
	}
}
