package report

import (
	"regexp"
	"strings"
)

var reNumeroTrasPalabra = regexp.MustCompile(` \(\d+\)`)

// EsMalformada reconoce una respuesta corrupta que no sirve como explicacion.
// El sintoma observado en la practica: un numero entre parentesis detras de
// casi cada palabra ("dispositivos (139) del (140) hogar (141)..."), una
// generacion rota de algun modelo. Cachear eso dejaria una explicacion
// ilegible fija en el panel, asi que se rechaza para que se vuelva a generar.
//
// Se exige densidad -varios marcadores y que cubran buena parte del texto-
// para no confundirlo con un ano o una cifra sueltos entre parentesis en una
// frase normal.
func EsMalformada(texto string) bool {
	n := len(reNumeroTrasPalabra.FindAllString(texto, -1))
	if n < 5 {
		return false
	}
	palabras := len(strings.Fields(texto))
	return palabras > 0 && n*4 >= palabras
}
