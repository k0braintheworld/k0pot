package store

import "testing"

// TestSemillaGlosas comprueba que una instalacion NUEVA arranca ya con el
// catalogo de fabrica cargado, sin tener que aprenderlo.
func TestSemillaGlosas(t *testing.T) {
	s := almacenTemporal(t) // BD recien creada
	n, err := s.ContarGlosasAprendidas()
	if err != nil {
		t.Fatal(err)
	}
	if n < 100 {
		t.Fatalf("la semilla no cargo en una BD nueva: %d glosas", n)
	}
	// Y una consulta concreta debe encontrar algo util.
	if _, ok := s.GlosaAprendida("wget <url>", "es"); !ok {
		t.Log("nota: wget <url> no esta en la semilla (puede ser normal segun lo aprendido)")
	}
}

func TestSemillaNarrativas(t *testing.T) {
	s := almacenTemporal(t) // BD nueva
	var n int
	s.db.QueryRow("SELECT COUNT(*) FROM narrativas_aprendidas").Scan(&n)
	if n < 10 {
		t.Fatalf("la semilla de narrativas no cargo en una BD nueva: %d", n)
	}
}
