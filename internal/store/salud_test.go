package store

import "testing"

// En una base vacia MAX(timestamp) es NULL: hay que devolverlo como "sin
// eventos", no como error, o el autochequeo se rompe en instalaciones nuevas.
func TestUltimoEventoEnBaseVacia(t *testing.T) {
	s := almacenTemporal(t)
	_, hay, err := s.UltimoEventoEn()
	if err != nil {
		t.Fatalf("base vacia no deberia dar error: %v", err)
	}
	if hay {
		t.Fatal("base vacia no deberia reportar eventos")
	}
}
