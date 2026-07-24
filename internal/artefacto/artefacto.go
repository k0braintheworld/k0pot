// Package artefacto identifica y resume, de forma SEGURA, los ficheros que un
// atacante intento dejar en el honeypot. No ejecuta ni interpreta nada: solo
// lee bytes crudos y los describe. Es la base para poder revisar una muestra
// -saber que es y que hace- sin llegar a lanzarla.
package artefacto

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// Tipo describe que es un fichero a partir de sus primeros bytes ("magic
// bytes"). Solo mira la cabecera; nunca abre nada como programa.
func Tipo(cabecera []byte) string {
	switch {
	case bytes.HasPrefix(cabecera, []byte("\x7fELF")):
		return "Ejecutable de Linux (ELF)" + arquitecturaELF(cabecera)
	case bytes.HasPrefix(cabecera, []byte("#!")):
		return "Script (" + primeraLinea(cabecera) + ")"
	case bytes.HasPrefix(cabecera, []byte{0x1f, 0x8b}):
		return "Comprimido gzip"
	case bytes.HasPrefix(cabecera, []byte("PK\x03\x04")):
		return "Comprimido ZIP"
	case bytes.HasPrefix(cabecera, []byte("MZ")):
		return "Ejecutable de Windows (PE)"
	case esTexto(cabecera):
		return "Texto"
	default:
		return "Binario sin identificar"
	}
}

// arquitecturaELF saca la arquitectura del binario, que dice mucho: un MIPS o
// un ARM es casi siempre un router o una camara de una botnet de IoT, no un
// servidor. Se lee del campo e_machine de la cabecera ELF.
func arquitecturaELF(b []byte) string {
	if len(b) < 20 {
		return ""
	}
	var m uint16
	if b[5] == 2 { // EI_DATA = 2: big-endian
		m = binary.BigEndian.Uint16(b[18:20])
	} else {
		m = binary.LittleEndian.Uint16(b[18:20])
	}
	nombre := map[uint16]string{
		0x02: "SPARC", 0x03: "x86", 0x08: "MIPS", 0x14: "PowerPC",
		0x15: "PowerPC64", 0x28: "ARM", 0x2a: "SuperH", 0x32: "IA-64",
		0x3e: "x86-64", 0xb7: "ARM64", 0xf3: "RISC-V",
	}[m]
	if nombre == "" {
		return ""
	}
	return ", arquitectura " + nombre
}

func primeraLinea(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	return strings.TrimSpace(string(b))
}

// EsTexto dice si unos bytes son texto imprimible (un script, un .sh),
// para poder ensenarlos tal cual en vez de solo sus cadenas sueltas.
func EsTexto(b []byte) bool { return esTexto(b) }

// esTexto decide si la cabecera es texto imprimible. Un binario tiene bytes
// nulos y de control por todas partes; el texto, no.
func esTexto(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c == 0 {
			return false
		}
		if c < 0x09 || (c > 0x0d && c < 0x20) {
			return false
		}
	}
	return true
}

// Cadenas extrae las secuencias de texto imprimible de un fichero, como el
// comando "strings". En un binario delatan URLs, direcciones de mando y
// control y comandos incrustados: dejan ver que hace la muestra sin
// ejecutarla. Devuelve hasta maxLineas cadenas de longitud >= 4.
func Cadenas(datos []byte, maxLineas int) []string {
	var out []string
	var actual []byte
	emitir := func() {
		if len(actual) >= 4 {
			out = append(out, string(actual))
		}
		actual = actual[:0]
	}
	for _, c := range datos {
		if c >= 0x20 && c < 0x7f {
			actual = append(actual, c)
			continue
		}
		emitir()
		if len(out) >= maxLineas {
			return out
		}
	}
	emitir()
	if len(out) > maxLineas {
		out = out[:maxLineas]
	}
	return out
}
