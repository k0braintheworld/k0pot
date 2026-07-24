package main

import "testing"

func TestRed24(t *testing.T) {
	casos := map[string]string{
		"192.168.10.5": "192.168.10.0/24",
		"192.168.20.5": "192.168.20.0/24",
		"10.0.0.5":     "10.0.0.0/24",
	}
	for ip, espera := range casos {
		if got := red24(ip); got != espera {
			t.Errorf("red24(%q) = %q, esperaba %q", ip, got, espera)
		}
	}
}

func TestSustituirDefines(t *testing.T) {
	plantilla := `define IP_GESTION  = 192.168.1.10
define IP_EXPUESTA = 192.168.100.10
define RED_GESTION = 192.168.1.0/24
define IF_EXPUESTA = "ens19"
define IF_GESTION  = "ens18"
define RED_INTERNA = { 192.168.1.0/24, 10.0.0.0/8 }
define PUERTOS_HONEYPOT = { 2222, 6379 }`

	got := sustituirDefines(plantilla, map[string]string{
		"IP_GESTION":  "192.168.10.5",
		"IP_EXPUESTA": "192.168.20.5",
		"RED_GESTION": "192.168.10.0/24",
		"IF_GESTION":  `"enp1s0"`,
		"IF_EXPUESTA": `"enp2s0"`,
	})

	debeContener := []string{
		"define IP_GESTION = 192.168.10.5",
		"define IP_EXPUESTA = 192.168.20.5",
		"define RED_GESTION = 192.168.10.0/24",
		`define IF_GESTION = "enp1s0"`,
		`define IF_EXPUESTA = "enp2s0"`,
		// intactos: no estan en el mapa
		"define RED_INTERNA = { 192.168.1.0/24, 10.0.0.0/8 }",
		"define PUERTOS_HONEYPOT = { 2222, 6379 }",
	}
	for _, sub := range debeContener {
		if !contieneLinea(got, sub) {
			t.Errorf("el resultado no contiene la linea %q\n---\n%s", sub, got)
		}
	}
	// Los valores de ejemplo deben haber desaparecido.
	for _, viejo := range []string{"192.168.1.10", "192.168.100.10", "ens18", "ens19"} {
		if contieneLinea(got, "= "+viejo) || contieneLinea(got, `"`+viejo+`"`) {
			t.Errorf("quedo un valor de ejemplo: %q\n%s", viejo, got)
		}
	}
}

func contieneLinea(texto, sub string) bool {
	for len(texto) > 0 {
		i := indexOf(texto, sub)
		if i >= 0 {
			return true
		}
		break
	}
	return false
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
