package web

import (
	"strings"
	"testing"
	"time"
)

func TestSTIXBundleValido(t *testing.T) {
	lista := []ioc{
		{clase: "ipv4-addr", valor: "203.0.113.7", primera: time.Now().Add(-time.Hour), ultima: time.Now(), pais: "CN", reput: 80, tor: true, etiqueta: "atacante observado (intrusion)"},
		{clase: "file", valor: strings.Repeat("a", 64), primera: time.Now(), ultima: time.Now(), etiqueta: "fichero capturado (1234 bytes)"},
		{clase: "url", valor: "http://evil.example/x.sh", primera: time.Now(), ultima: time.Now(), etiqueta: "URL desde la que se sirve malware"},
	}
	var sb strings.Builder
	escribirSTIX(&sb, lista)
	out := sb.String()
	for _, must := range []string{`"type": "bundle"`, `"type": "indicator"`, `[ipv4-addr:value = '203.0.113.7']`, `[file:hashes.'SHA-256' =`, `tor-exit-node`, `indicator--`} {
		if !strings.Contains(out, must) {
			t.Fatalf("falta %q en el bundle STIX", must)
		}
	}
	// id determinista: dos exportaciones del mismo IOC dan el mismo id.
	if uuid5("ipv4-addr|203.0.113.7") != uuid5("ipv4-addr|203.0.113.7") {
		t.Fatal("uuid5 no es determinista")
	}
	var csv strings.Builder
	escribirCSV(&csv, lista)
	if !strings.Contains(csv.String(), "203.0.113.7") || !strings.Contains(csv.String(), "tipo,indicador") {
		t.Fatalf("CSV incompleto: %q", csv.String())
	}
}
