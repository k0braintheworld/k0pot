package report

import (
	"strings"
	"testing"
)

func TestRecortarPromptAcota(t *testing.T) {
	if s := "corto"; recortarPrompt(s) != s {
		t.Error("recorto algo que cabia")
	}
	largo := strings.Repeat("x", 20000)
	got := []rune(recortarPrompt(largo))
	// El aviso anade unos pocos caracteres; se comprueba el orden de magnitud.
	if len(got) > topeCaracteresPrompt+60 {
		t.Errorf("no acoto: %d caracteres", len(got))
	}
	if len(got) < topeCaracteresPrompt {
		t.Errorf("recorto de mas: %d caracteres", len(got))
	}
}

func TestRecortarLinea(t *testing.T) {
	if s := "abc"; recortarLinea(s, 10) != s {
		t.Error("recorto una linea corta")
	}
	got := recortarLinea(strings.Repeat("a", 100), 10)
	if !strings.HasPrefix(got, strings.Repeat("a", 10)) || !strings.Contains(got, "recortado") {
		t.Errorf("recorte de linea mal: %q", got)
	}
}
