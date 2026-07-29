package cebo

import "testing"

func TestEnTextoDetectaCanario(t *testing.T) {
	// Una credencial plantada, reutilizada literalmente, se detecta.
	if EnTexto("mysql -u acme_app -p'Pr0d_9xQZ!ktm2024'") == "" {
		t.Fatal("no detecto la contrasena de BD plantada")
	}
	// Ruido cualquiera no dispara.
	if EnTexto("uname -a && cat /etc/passwd") != "" {
		t.Fatal("falso positivo con trafico normal")
	}
}

func TestEnDetalleSoloMiraEntrada(t *testing.T) {
	// En una clave de entrada, muerde.
	if EnDetalle(map[string]string{"comando": "aws --key AKIA7ACMEQK2NR0PZ3XV"}) == "" {
		t.Fatal("no detecto el canario en 'comando'")
	}
	// La misma cadena en una clave de contenido servido NO cuenta: es el
	// cebo que nosotros mismos entregamos, no un mordisco.
	if EnDetalle(map[string]string{"cebo": "AKIA7ACMEQK2NR0PZ3XV"}) != "" {
		t.Fatal("detecto como mordisco el cebo servido por nosotros")
	}
}

func TestCatalogoTieneEntropia(t *testing.T) {
	// Guardarrail: un canario corto o vacio dispararia falsos positivos.
	for _, c := range Canarios() {
		if len(c.Valor) < 10 {
			t.Fatalf("canario demasiado corto, riesgo de falso positivo: %q", c.Valor)
		}
	}
}
