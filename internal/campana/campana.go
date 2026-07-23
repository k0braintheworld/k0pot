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

type senal struct {
	tipo    Tipo
	huella  string
	muestra string
}

// senales extrae de un ataque todo lo que podria delatar un guion comun.
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
