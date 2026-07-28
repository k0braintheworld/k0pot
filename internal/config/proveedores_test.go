package config

import "testing"

func TestModelosEfectivos(t *testing.T) {
	// Config antigua de un solo proveedor compatible (Groq): se migra sola.
	c := Config{UsarLLM: true, Proveedor: ProveedorCompatible, ClaveCompatible: "k",
		URLBase: "https://api.groq.com/openai/v1", Modelo: "x"}
	m := c.ModelosEfectivos()
	if len(m) != 1 || m[0].Proveedor != "groq" || m[0].Clave != "k" {
		t.Fatalf("migracion groq: %+v", m)
	}
	// La lista explicita manda sobre lo antiguo.
	c.Modelos = []ModeloIA{{Proveedor: "gemini", Clave: "g"}, {Proveedor: "anthropic", Clave: "a"}}
	m = c.ModelosEfectivos()
	if len(m) != 2 || m[0].Proveedor != "gemini" {
		t.Fatalf("lista explicita: %+v", m)
	}
	// El catalogo trae url y modelo por defecto.
	if p, ok := ProveedorPorID("gemini"); !ok || p.URLBase == "" || p.Modelo == "" {
		t.Fatalf("catalogo gemini incompleto: %+v", p)
	}
}
