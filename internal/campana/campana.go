// Package campana agrupa ataques que vienen del mismo sitio aunque lleguen
// de IPs distintas.
//
// Una botnet no ataca desde una direccion: reparte el mismo trabajo entre
// cientos de equipos infectados. Vistos de uno en uno parecen cientos de
// incidentes sin relacion; vistos juntos son uno solo, y esa es la lectura
// que cambia lo que uno hace al respecto.
//
// Lo que los delata es que comparten guion. Los bots no improvisan:
// prueban el mismo diccionario en el mismo orden, piden las mismas rutas y
// se descargan el mismo fichero. Basta comparar esas huellas.
package campana

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/episodio"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// minimoIPs es cuantas direcciones distintas hacen falta para hablar de
// campana. Con una sola no hay nada que agrupar: es un ataque y ya.
const minimoIPs = 2

// Tipo es que comparten los ataques de una campana.
type Tipo string

const (
	// PorCredenciales: el mismo diccionario de usuario y contrasena.
	PorCredenciales Tipo = "credenciales"
	// PorDescarga: el mismo fichero que intentan traerse.
	PorDescarga Tipo = "descarga"
	// PorComandos: la misma secuencia tecleada.
	PorComandos Tipo = "comandos"
	// PorRutas: las mismas rutas web tanteadas.
	PorRutas Tipo = "rutas"
)

// Campana son varios ataques que comparten guion.
type Campana struct {
	Tipo Tipo `json:"tipo"`
	// Huella identifica el guion compartido, para poder agrupar.
	Huella string `json:"huella"`
	// Muestra es ese guion en legible, que es lo que se ensena.
	Muestra   string             `json:"muestra"`
	IPs       []string           `json:"ips"`
	Episodios int                `json:"episodios"`
	Desde     time.Time          `json:"desde"`
	Hasta     time.Time          `json:"hasta"`
	Severidad episodio.Severidad `json:"severidad"`
	Paises    []string           `json:"paises,omitempty"`
}

// Interesante dice si una campana merece salir en el panel.
//
// Detectar agrupa TODO lo que comparte guion, y a bajo volumen eso son
// sobre todo escaneres de investigacion haciendo el mismo PING/INFO: cierto,
// pero sin valor. Una campana solo importa si es lo bastante coordinada
// -muchas IPs- o lo bastante grave, o si comparten una descarga, que aunque
// sean dos delata la misma operacion sin duda.
func (c Campana) Interesante() bool {
	if c.Tipo == PorDescarga {
		return true // el mismo binario desde dos sitios ya es senal fuerte
	}
	if len(c.IPs) >= 5 {
		return true // una coincidencia amplia deja de ser casualidad
	}
	return episodio.Rango(c.Severidad) >= episodio.Rango(episodio.Acceso)
}

// Detectar busca campanas entre los ataques de un periodo.
func Detectar(episodios []store.EpisodioFila) []Campana {
	grupos := map[string]*Campana{}

	for _, e := range episodios {
		for _, s := range senales(e) {
			clave := string(s.tipo) + "|" + s.huella
			c, hay := grupos[clave]
			if !hay {
				c = &Campana{
					Tipo: s.tipo, Huella: s.huella, Muestra: s.muestra,
					Desde: e.Inicio, Hasta: e.Fin, Severidad: e.Severidad,
				}
				grupos[clave] = c
			}
			c.Episodios++
			anadir(&c.IPs, e.IP)
			anadir(&c.Paises, e.Pais)
			if e.Inicio.Before(c.Desde) {
				c.Desde = e.Inicio
			}
			if e.Fin.After(c.Hasta) {
				c.Hasta = e.Fin
			}
			c.Severidad = episodio.Peor(c.Severidad, e.Severidad)
		}
	}

	fin := make([]Campana, 0, len(grupos))
	for _, c := range grupos {
		if len(c.IPs) < minimoIPs {
			continue
		}
		sort.Strings(c.IPs)
		sort.Strings(c.Paises)
		fin = append(fin, *c)
	}
	// Primero lo mas grave y, a igual gravedad, lo mas extendido: una
	// campana con cincuenta IPs dice mas que una con dos.
	sort.SliceStable(fin, func(i, j int) bool {
		if fin[i].Severidad != fin[j].Severidad {
			return episodio.Peor(fin[i].Severidad, fin[j].Severidad) == fin[i].Severidad
		}
		return len(fin[i].IPs) > len(fin[j].IPs)
	})
	return fin
}

// EpisodiosDe devuelve los ataques que pertenecen a una campana concreta,
// identificada por su tipo y su huella. Usa la misma deteccion de senales que
// Detectar, de modo que lo que sale al abrir una campana coincide exactamente
// con lo que se conto en su resumen.
func EpisodiosDe(episodios []store.EpisodioFila, tipo Tipo, huella string) []store.EpisodioFila {
	var out []store.EpisodioFila
	for _, e := range episodios {
		for _, s := range senales(e) {
			if s.tipo == tipo && s.huella == huella {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

type senal struct {
	tipo    Tipo
	huella  string
	muestra string
}

// senales extrae de un ataque todo lo que podria delatar un guion comun.
// ContextoDe situa un episodio dentro de lo que se ve en el periodo: la
// mayor campana a la que pertenece -misma secuencia, mismo fichero, mismo
// diccionario o mismas rutas- y cuantas direcciones la comparten. Es lo que
// permite explicar un ataque como "el ruido habitual" o "esto es raro", en
// vez de contar cada uno como si fuera unico.
func ContextoDe(episodios []store.EpisodioFila, e store.EpisodioFila) (Campana, bool) {
	mias := map[string]bool{}
	for _, s := range senales(e) {
		mias[string(s.tipo)+"|"+s.huella] = true
	}
	if len(mias) == 0 {
		return Campana{}, false
	}
	var mejor Campana
	hay := false
	for _, c := range Detectar(episodios) {
		if mias[string(c.Tipo)+"|"+c.Huella] && (!hay || len(c.IPs) > len(mejor.IPs)) {
			mejor, hay = c, true
		}
	}
	return mejor, hay
}

func senales(e store.EpisodioFila) []senal {
	var out []senal

	// Un solo fichero descargado ya identifica: dos IPs que se traen el
	// mismo binario de la misma URL son la misma operacion, sin duda.
	for _, u := range e.Descargas {
		if u == "" {
			continue
		}
		out = append(out, senal{PorDescarga, huellaDe(u), u})
	}

	// Los conjuntos necesitan al menos dos elementos: que dos escaneres
	// pidan "/" no significa nada, y agruparlos por eso llenaria la
	// pantalla de campanas inventadas.
	if len(e.Passwords) >= 2 {
		out = append(out, senal{PorCredenciales,
			huellaDeLista(e.Passwords), resumirLista(e.Passwords, e.Usuarios)})
	}
	if len(e.Comandos) >= 2 {
		out = append(out, senal{PorComandos,
			huellaDeLista(e.Comandos), strings.Join(recortar(e.Comandos, 3), " ; ")})
	}
	if len(e.Rutas) >= 2 {
		out = append(out, senal{PorRutas,
			huellaDeLista(e.Rutas), strings.Join(recortar(e.Rutas, 4), "  ")})
	}
	return out
}

// huellaDeLista ordena antes de resumir: dos bots pueden recorrer el mismo
// diccionario en distinto orden y siguen siendo el mismo diccionario.
func huellaDeLista(v []string) string {
	copia := append([]string(nil), v...)
	sort.Strings(copia)
	return huellaDe(strings.Join(copia, "\n"))
}

func huellaDe(s string) string {
	suma := sha256.Sum256([]byte(s))
	return hex.EncodeToString(suma[:8])
}

func resumirLista(passwords, usuarios []string) string {
	m := strings.Join(recortar(passwords, 4), ", ")
	if len(usuarios) > 0 {
		return fmt.Sprintf("%s (usuarios: %s)", m, strings.Join(recortar(usuarios, 3), ", "))
	}
	return m
}

func recortar(v []string, n int) []string {
	if len(v) <= n {
		return v
	}
	return append(append([]string(nil), v[:n]...), "…")
}

func anadir(destino *[]string, v string) {
	if v == "" {
		return
	}
	for _, x := range *destino {
		if x == v {
			return
		}
	}
	*destino = append(*destino, v)
}
