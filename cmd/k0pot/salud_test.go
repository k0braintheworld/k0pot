package main

import (
	"testing"
	"time"

	"github.com/k0braintheworld/k0pot/internal/config"
)

func TestEvaluarSalud(t *testing.T) {
	c := config.Config{Idioma: "es"}
	ahora := time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)
	const gb = uint64(1) << 30

	casos := []struct {
		nombre     string
		discoLibre uint64
		ultimo     time.Time
		hay        bool
		quiere     []string // claves esperadas
	}{
		{"todo bien", 20 * gb, ahora.Add(-5 * time.Minute), true, nil},
		{"disco bajo", 1 * gb, ahora.Add(-time.Minute), true, []string{"salud_disco"}},
		{"captura parada", 20 * gb, ahora.Add(-13 * time.Hour), true, []string{"salud_captura"}},
		{"sin exponer aun", 20 * gb, time.Time{}, false, nil},
		{"retirado hace 40 dias", 20 * gb, ahora.AddDate(0, 0, -40), true, nil},
		{"statfs fallido (0)", 0, ahora.Add(-time.Minute), true, nil},
		{"disco bajo y captura parada", 1 * gb, ahora.Add(-13 * time.Hour), true, []string{"salud_disco", "salud_captura"}},
	}
	for _, k := range casos {
		t.Run(k.nombre, func(t *testing.T) {
			got := evaluarSalud(c, k.discoLibre, k.ultimo, k.hay, ahora)
			if len(got) != len(k.quiere) {
				t.Fatalf("%d avisos, esperaba %d: %+v", len(got), len(k.quiere), got)
			}
			for i, cl := range k.quiere {
				if got[i].clave != cl {
					t.Errorf("aviso %d: clave %q, esperaba %q", i, got[i].clave, cl)
				}
			}
		})
	}
}
