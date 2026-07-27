package saber

import (
	"regexp"
	"strings"
)

var (
	reNormURL = regexp.MustCompile(`[a-z]+://[^\s'"]+`)
	reNormIP  = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)
	reNormHex = regexp.MustCompile(`\b[0-9a-f]{8,}\b`)
	reNormNum = regexp.MustCompile(`\b\d{4,}\b`)
	reNormEsp = regexp.MustCompile(`\s+`)
)

// NormalizarComando reduce un comando a su ESQUELETO: minusculas, sin las
// partes que cambian de una victima a otra (IPs, URLs, hashes, numeros
// largos) y con los espacios colapsados. Dos ordenes iguales salvo el
// servidor de descarga comparten asi una sola forma -y una sola glosa
// aprendida-. Es la clave del catalogo que k0pot se construye solo.
func NormalizarComando(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = reNormURL.ReplaceAllString(s, "<url>")
	s = reNormIP.ReplaceAllString(s, "<ip>")
	s = reNormHex.ReplaceAllString(s, "<hex>")
	s = reNormNum.ReplaceAllString(s, "<n>")
	s = reNormEsp.ReplaceAllString(s, " ")
	if len(s) > 400 {
		s = s[:400]
	}
	return s
}

// ComandoConocido dice si el catalogo FIJO ya sabe explicar un comando, para
// no gastar IA en lo que ya se conoce. Distingue shell de verbos de protocolo.
func ComandoConocido(protocolo, comando string) bool {
	if SinShell(protocolo) {
		_, ok := DeVerbo(protocolo, comando)
		return ok
	}
	_, ok := DeComando(comando)
	return ok
}
