package artefacto

import (
	"strings"
	"testing"
)

func TestTipoELFArquitectura(t *testing.T) {
	// Cabecera ELF, little-endian, e_machine=0x08 (MIPS) en el offset 18.
	elf := make([]byte, 20)
	copy(elf, []byte("\x7fELF"))
	elf[4], elf[5] = 1, 1 // 32 bits, little-endian
	elf[18], elf[19] = 0x08, 0x00
	if got := Tipo(elf); got != "Ejecutable de Linux (ELF), arquitectura MIPS" {
		t.Errorf("Tipo(elf mips) = %q", got)
	}
}

func TestTipoVarios(t *testing.T) {
	casos := map[string]string{
		"#!/bin/sh\nrm -rf /":         "Script (#!/bin/sh)",
		"\x1f\x8bdatos comprimidos":   "Comprimido gzip",
		"MZ\x90\x00binario windows":   "Ejecutable de Windows (PE)",
		"solo texto plano aqui":       "Texto",
		"\x00\x01\x02\xff\xfe basura": "Binario sin identificar",
	}
	for entrada, espera := range casos {
		if got := Tipo([]byte(entrada)); got != espera {
			t.Errorf("Tipo(%q) = %q, esperaba %q", entrada, got, espera)
		}
	}
}

func TestCadenas(t *testing.T) {
	// URL y comando incrustados entre bytes binarios.
	datos := []byte("\x00\x01http://malo/x.sh\x00\xff\xfewget\x00abc")
	c := Cadenas(datos, 60)
	unido := strings.Join(c, "|")
	if !strings.Contains(unido, "http://malo/x.sh") {
		t.Errorf("no extrajo la URL: %v", c)
	}
	if !strings.Contains(unido, "wget") {
		t.Errorf("no extrajo el comando: %v", c)
	}
	// "abc" tiene 3 chars: por debajo del minimo de 4, no debe salir.
	for _, s := range c {
		if s == "abc" {
			t.Errorf("cadena demasiado corta incluida: %q", s)
		}
	}
}

func TestCadenasTope(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 100; i++ {
		b.WriteString("cadena\x00")
	}
	if c := Cadenas([]byte(b.String()), 10); len(c) != 10 {
		t.Errorf("respeta el tope: len = %d, esperaba 10", len(c))
	}
}
