package store

import "testing"

func TestGlosasAprendidasRoundTrip(t *testing.T) {
	s := almacenTemporal(t)
	// La BD nueva ya trae la semilla de fabrica; se mide en RELATIVO.
	inicial, _ := s.ContarGlosasAprendidas()
	const norm = "comando-de-prueba-unico <url>"

	if _, ok := s.GlosaAprendida(norm, "es"); ok {
		t.Fatal("ese comando de prueba no deberia estar aun")
	}
	if err := s.GuardarGlosaAprendida(norm, "es", "descarga el malware"); err != nil {
		t.Fatal(err)
	}
	g, ok := s.GlosaAprendida(norm, "es")
	if !ok || g != "descarga el malware" {
		t.Fatalf("no se recupero la glosa: %q %v", g, ok)
	}
	// El idioma separa: en ingles no existe todavia.
	if _, ok := s.GlosaAprendida(norm, "en"); ok {
		t.Fatal("el idioma deberia aislar las glosas")
	}
	// Reaprender la misma no duplica: cuenta una aparicion mas.
	if err := s.GuardarGlosaAprendida(norm, "es", "descarga el binario"); err != nil {
		t.Fatal(err)
	}
	n, err := s.ContarGlosasAprendidas()
	if err != nil || n != inicial+1 {
		t.Fatalf("esperaba %d entradas, hay %d (%v)", inicial+1, n, err)
	}
}
