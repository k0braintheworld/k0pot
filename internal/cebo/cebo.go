// Package cebo centraliza las credenciales y tokens FALSOS que k0Pot planta
// como senuelo -en el .env de la trampa HTTP y en el botin del sistema de
// ficheros de Cowrie- y detecta cuando vuelven.
//
// La idea, un honeytoken o "canary", es simple y potente: ninguna de estas
// cadenas abre nada real, pero son unicas y de alta entropia. Nadie las
// teclea por casualidad. Si una reaparece en lo que escribe un atacante -un
// login, un comando, un formulario- solo hay una explicacion: leyo el cebo
// que dejamos y volvio a usarlo. Es la senal mas limpia que puede dar un
// honeypot, y no necesita ningun servicio externo: la trampa y el aviso
// viven en la misma maquina.
package cebo

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed canarios.json
var canariosJSON []byte

// Canario es una cadena senuelo y su descripcion en llano.
type Canario struct {
	Valor    string `json:"valor"`
	Etiqueta string `json:"etiqueta"`
}

var canarios []Canario

func init() {
	if err := json.Unmarshal(canariosJSON, &canarios); err != nil {
		panic("cebo: canarios.json ilegible: " + err.Error())
	}
}

// Canarios devuelve una copia del catalogo, para quien necesite plantarlos.
func Canarios() []Canario {
	out := make([]Canario, len(canarios))
	copy(out, canarios)
	return out
}

// clavesEntrada son las claves de Detalle que contienen lo que ESCRIBE el
// atacante. Solo se buscan canarios ahi, nunca en contenido que nosotros
// servimos (por ejemplo la etiqueta "cebo"), para no confundir nuestro
// propio senuelo con un mordisco.
var clavesEntrada = map[string]bool{
	"comando": true, "input": true, "cuerpo": true,
	"usuario": true, "username": true, "password": true,
	"clave": true, "ruta": true, "destino": true,
	"argumentos": true, "datos": true, "query": true,
}

// EnTexto devuelve la etiqueta del primer canario presente en texto, o "".
// La comparacion distingue mayusculas: los valores son de alta entropia y
// buscamos la reutilizacion literal.
func EnTexto(texto string) string {
	for _, c := range canarios {
		if c.Valor != "" && strings.Contains(texto, c.Valor) {
			return c.Etiqueta
		}
	}
	return ""
}

// EnListas devuelve la etiqueta del primer canario hallado en cualquiera
// de las listas de texto que reciba (comandos, passwords, rutas...).
func EnListas(listas ...[]string) string {
	for _, l := range listas {
		for _, s := range l {
			if et := EnTexto(s); et != "" {
				return et
			}
		}
	}
	return ""
}

// EnDetalle busca canarios en las claves de entrada de un evento. Devuelve
// la etiqueta del cebo mordido, o "" si no hay ninguno.
func EnDetalle(detalle map[string]string) string {
	for clave, valor := range detalle {
		if clavesEntrada[clave] {
			if et := EnTexto(valor); et != "" {
				return et
			}
		}
	}
	return ""
}
