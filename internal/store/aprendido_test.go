package store

import "testing"

func TestGlosasAprendidasRoundTrip(t *testing.T) {
	s := almacenTemporal(t)

	if _, ok := s.GlosaAprendida("wget <url>", "es"); ok {
		t.Fatal("no deberia haber nada aun")
	}
	if err := s.GuardarGlosaAprendida("wget <url>", "es", "descarga el malware"); err != nil {
		t.Fatal(err)
	}
	g, ok := s.GlosaAprendida("wget <url>", "es")
	if !ok || g != "descarga el malware" {
		t.Fatalf("no se recupero la glosa: %q %v", g, ok)
	}
	// El idioma separa: en ingles no existe todavia.
	if _, ok := s.GlosaAprendida("wget <url>", "en"); ok {
		t.Fatal("el idioma deberia aislar las glosas")
	}
	// Reaprender la misma no duplica: cuenta una aparicion mas.
	if err := s.GuardarGlosaAprendida("wget <url>", "es", "descarga el binario"); err != nil {
		t.Fatal(err)
	}
	n, err := s.ContarGlosasAprendidas()
	if err != nil || n != 1 {
		t.Fatalf("esperaba 1 entrada, hay %d (%v)", n, err)
	}
}
