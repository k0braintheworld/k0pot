package campana

import (
	"testing"
	"time"

	"github.com/k0braintheworld/k0pot/internal/episodio"
	"github.com/k0braintheworld/k0pot/internal/store"
)

func ep(ip string, ajustar func(*store.EpisodioFila)) store.EpisodioFila {
	e := store.EpisodioFila{
		Episodio: episodio.Episodio{
			Clave: ip, IP: ip, Protocolo: "ssh", Severidad: episodio.Tanteo,
			Inicio: time.Date(2026, 7, 23, 10, 0, 0, 0, time.UTC),
			Fin:    time.Date(2026, 7, 23, 10, 5, 0, 0, time.UTC),
		},
	}
	if ajustar != nil {
		ajustar(&e)
	}
	return e
}

// Lo que motiva el paquete: veinte IPs distintas probando el mismo
// diccionario no son veinte incidentes, son uno.
func TestElMismoDiccionarioDelataUnaBotnet(t *testing.T) {
	diccionario := []string{"xc3511", "vizxv", "admin", "888888"}
	var eps []store.EpisodioFila
	for _, ip := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		eps = append(eps, ep(ip, func(e *store.EpisodioFila) {
			e.Passwords = diccionario
			e.Usuarios = []string{"root"}
		}))
	}

	cs := Detectar(eps)
	if len(cs) != 1 {
		t.Fatalf("se esperaba 1 campana, hubo %d", len(cs))
	}
	if cs[0].Tipo != PorCredenciales {
		t.Errorf("tipo = %s", cs[0].Tipo)
	}
	if len(cs[0].IPs) != 3 {
		t.Errorf("IPs = %v, se esperaban 3", cs[0].IPs)
	}
}

// El orden del diccionario no importa: dos bots pueden recorrerlo distinto
// y sigue siendo el mismo diccionario.
func TestElOrdenDelDiccionarioNoRompeElGrupo(t *testing.T) {
	cs := Detectar([]store.EpisodioFila{
		ep("1.1.1.1", func(e *store.EpisodioFila) { e.Passwords = []string{"a", "b", "c"} }),
		ep("2.2.2.2", func(e *store.EpisodioFila) { e.Passwords = []string{"c", "a", "b"} }),
	})
	if len(cs) != 1 {
		t.Fatalf("no se agruparon: %d campanas", len(cs))
	}
}

// Un mismo fichero descargado desde dos sitios es la misma operacion sin
// ninguna duda, aunque solo haya un indicador.
func TestLaMismaDescargaAgrupaAunqueSeaUnSoloIndicador(t *testing.T) {
	cs := Detectar([]store.EpisodioFila{
		ep("1.1.1.1", func(e *store.EpisodioFila) {
			e.Descargas = []string{"http://198.51.100.7/bot.sh"}
			e.Severidad = episodio.Intrusion
		}),
		ep("2.2.2.2", func(e *store.EpisodioFila) {
			e.Descargas = []string{"http://198.51.100.7/bot.sh"}
		}),
	})
	if len(cs) != 1 || cs[0].Tipo != PorDescarga {
		t.Fatalf("no se detecto la descarga compartida: %+v", cs)
	}
	if cs[0].Severidad != episodio.Intrusion {
		t.Errorf("la campana debe heredar la peor severidad, dio %s", cs[0].Severidad)
	}
}

// Una sola IP no es una campana: es un ataque, y ya se ve en su lista.
func TestUnaSolaIPNoEsCampana(t *testing.T) {
	cs := Detectar([]store.EpisodioFila{
		ep("1.1.1.1", func(e *store.EpisodioFila) { e.Passwords = []string{"a", "b"} }),
		ep("1.1.1.1", func(e *store.EpisodioFila) { e.Passwords = []string{"a", "b"} }),
	})
	if len(cs) != 0 {
		t.Errorf("no deberia haber campanas: %+v", cs)
	}
}

// Que dos escaneres pidan "/" no significa nada. Agrupar por un indicador
// tan comun llenaria la pantalla de campanas inventadas, que es peor que
// no detectar ninguna.
func TestUnIndicadorTrivialNoInventaCampanas(t *testing.T) {
	cs := Detectar([]store.EpisodioFila{
		ep("1.1.1.1", func(e *store.EpisodioFila) { e.Rutas = []string{"/"} }),
		ep("2.2.2.2", func(e *store.EpisodioFila) { e.Rutas = []string{"/"} }),
		ep("3.3.3.3", func(e *store.EpisodioFila) { e.Passwords = []string{"admin"} }),
		ep("4.4.4.4", func(e *store.EpisodioFila) { e.Passwords = []string{"admin"} }),
	})
	if len(cs) != 0 {
		t.Errorf("un solo indicador comun no deberia agrupar: %+v", cs)
	}
}

// Con varias rutas coincidentes si es un guion reconocible.
func TestVariasRutasIgualesSiSonUnGuion(t *testing.T) {
	rutas := []string{"/.env", "/wp-admin", "/phpmyadmin"}
	cs := Detectar([]store.EpisodioFila{
		ep("1.1.1.1", func(e *store.EpisodioFila) { e.Protocolo = "http"; e.Rutas = rutas }),
		ep("2.2.2.2", func(e *store.EpisodioFila) { e.Protocolo = "http"; e.Rutas = rutas }),
	})
	if len(cs) != 1 || cs[0].Tipo != PorRutas {
		t.Fatalf("se esperaba una campana por rutas: %+v", cs)
	}
}

// Lo mas grave primero y, a igual gravedad, lo mas extendido.
func TestSeOrdenaPorGravedadYAlcance(t *testing.T) {
	cs := Detectar([]store.EpisodioFila{
		ep("1.1.1.1", func(e *store.EpisodioFila) { e.Rutas = []string{"/a", "/b"} }),
		ep("2.2.2.2", func(e *store.EpisodioFila) { e.Rutas = []string{"/a", "/b"} }),
		ep("3.3.3.3", func(e *store.EpisodioFila) {
			e.Descargas = []string{"http://x/bot.sh"}
			e.Severidad = episodio.Intrusion
		}),
		ep("4.4.4.4", func(e *store.EpisodioFila) { e.Descargas = []string{"http://x/bot.sh"} }),
	})
	if len(cs) != 2 {
		t.Fatalf("se esperaban 2 campanas, hubo %d", len(cs))
	}
	if cs[0].Severidad != episodio.Intrusion {
		t.Errorf("la grave deberia ir primero, salio %s", cs[0].Severidad)
	}
}

func TestSinAtaquesNoHayCampanas(t *testing.T) {
	if cs := Detectar(nil); len(cs) != 0 {
		t.Errorf("se esperaba vacio: %+v", cs)
	}
}

// A bajo volumen, agrupar dos escaneres de investigacion que hacen el mismo
// PING es cierto pero inutil: no aporta y ocupa sitio. Interesante() es lo
// que lo mantiene fuera del panel hasta que hay algo de verdad.
func TestSoloSonInteresantesLasCoordinadasDeVerdad(t *testing.T) {
	casos := []struct {
		nombre string
		c      Campana
		quiero bool
	}{
		{"dos IPs tanteando", Campana{Tipo: PorComandos, Severidad: episodio.Tanteo,
			IPs: []string{"1.1.1.1", "2.2.2.2"}}, false},
		{"la misma descarga", Campana{Tipo: PorDescarga, Severidad: episodio.Tanteo,
			IPs: []string{"1.1.1.1", "2.2.2.2"}}, true},
		{"cinco IPs iguales", Campana{Tipo: PorCredenciales, Severidad: episodio.Tanteo,
			IPs: []string{"1", "2", "3", "4", "5"}}, true},
		{"dos IPs pero entraron", Campana{Tipo: PorCredenciales, Severidad: episodio.Acceso,
			IPs: []string{"1.1.1.1", "2.2.2.2"}}, true},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			if c.c.Interesante() != c.quiero {
				t.Errorf("Interesante()=%v, se esperaba %v", c.c.Interesante(), c.quiero)
			}
		})
	}
}
