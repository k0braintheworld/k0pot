package main

import "testing"

func TestFormatearCebos(t *testing.T) {
	cebo := map[string]string{"1.1.1.1": "la de BD", "2.2.2.2": "", "3.3.3.3": "la de Redis", "4.4.4.4": "x"}

	if s := formatearCebos(nil, cebo, "es"); s != "" {
		t.Errorf("sin cebos deberia ser vacio, fue %q", s)
	}
	if s := formatearCebos([]string{"1.1.1.1"}, cebo, "es"); s != "\U0001f36f 1 atacante(s) mordieron el cebo: 1.1.1.1 (la de BD)." {
		t.Errorf("uno: %q", s)
	}
	// El total cuenta todas; los ejemplos se cortan en 3.
	s := formatearCebos([]string{"1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4"}, cebo, "es")
	if want := "\U0001f36f 4 atacante(s) mordieron el cebo: 1.1.1.1 (la de BD), 2.2.2.2, 3.3.3.3 (la de Redis)."; s != want {
		t.Errorf("cuatro:\n got %q\nwant %q", s, want)
	}
	if s := formatearCebos([]string{"1.1.1.1"}, cebo, "en"); s != "\U0001f36f 1 attacker(s) took the bait: 1.1.1.1 (la de BD)." {
		t.Errorf("en: %q", s)
	}
}
