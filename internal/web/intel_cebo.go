package web

import (
	"sort"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/cebo"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// Aqui se responde a la pregunta que el resto del panel no contesta: el cebo
// esta plantado, pero .funciona? Se mide como un embudo, porque el engano es
// una secuencia y lo interesante es donde se cae la gente:
//
//	llegan -> hablan -> entran -> ejecutan -> abren el botin -> muerden el cebo
//
// Que la ultima cifra sea baja no dice nada por si sola. Lo que dice algo es
// COMPARARLA con la anterior: si muchos abren el botin y ninguno reutiliza
// nada, el cebo se lee y se descarta; si ni lo abren, el botin no se esta
// encontrando y hay que hacerlo mas visible.

// FaseEmbudo es un escalon del embudo del engano.
type FaseEmbudo struct {
	Clave     string  `json:"clave"`
	Episodios int     `json:"episodios"`
	IPs       int     `json:"ips"`
	// Duracion es lo que duro de media un ataque que llego hasta aqui, en
	// segundos. Es la medida de si el cebo los ENTRETIENE.
	Duracion float64 `json:"duracion"`
	// Comandos es la media de ordenes por ataque en esta fase: si el botin
	// funciona, quien lo abre despliega mas arsenal que quien no.
	Comandos float64 `json:"comandos"`
}

// PiezaTocada cuenta cuanto se abre cada trozo del botin.
type PiezaTocada struct {
	Nombre    string `json:"nombre"`
	Episodios int    `json:"episodios"`
	IPs       int    `json:"ips"`
}

// Mordisco es una reutilizacion de una credencial senuelo.
type Mordisco struct {
	Cebo      string `json:"cebo"`
	IP        string `json:"ip"`
	Protocolo string `json:"protocolo"`
	Cuando    string `json:"cuando"`
	// LeidoAqui dice si esa misma IP habia abierto el botin antes en este
	// honeypot. Si es falso, la credencial le llego por otra via: el botin
	// salio de aqui y esta circulando.
	LeidoAqui bool `json:"leido_aqui"`
}

// InformeCebo es todo lo que el panel necesita para juzgar el engano.
type InformeCebo struct {
	Fases     []FaseEmbudo  `json:"fases"`
	Piezas    []PiezaTocada `json:"piezas"`
	Mordiscos []Mordisco    `json:"mordiscos"`
	// Circulando son los mordiscos de una IP que nunca leyo el botin aqui.
	Circulando int `json:"circulando"`
}

// calcularCebo recorre los episodios una vez y saca embudo, reparto del botin
// y trazabilidad de los mordiscos.
func calcularCebo(eps []store.EpisodioFila) InformeCebo {
	// Primera pasada: quien abrio el botin y cuando lo hizo por primera vez.
	// Hace falta ANTES de juzgar los mordiscos, porque un mordisco solo
	// cuenta como "leido aqui" si la lectura fue anterior.
	primeraLectura := map[string]time.Time{}
	for _, ep := range eps {
		if len(cebo.Tocados(ep.Comandos)) == 0 {
			continue
		}
		if t, hay := primeraLectura[ep.IP]; !hay || ep.Inicio.Before(t) {
			primeraLectura[ep.IP] = ep.Inicio
		}
	}

	type acum struct {
		n        int
		ips      map[string]bool
		segundos float64
		comandos int
	}
	nuevo := func() *acum { return &acum{ips: map[string]bool{}} }
	fases := map[string]*acum{
		"llegan": nuevo(), "hablan": nuevo(), "entran": nuevo(),
		"ejecutan": nuevo(), "tocan": nuevo(), "muerden": nuevo(),
	}
	sumar := func(clave string, ep store.EpisodioFila) {
		a := fases[clave]
		a.n++
		a.ips[ep.IP] = true
		a.segundos += ep.Fin.Sub(ep.Inicio).Seconds()
		a.comandos += len(ep.Comandos)
	}

	piezas := map[string]*acum{}
	var mordiscos []Mordisco
	circulando := 0

	for _, ep := range eps {
		sumar("llegan", ep)
		if !ep.SoloConexiones {
			sumar("hablan", ep)
		}
		if ep.LoginExitoso {
			sumar("entran", ep)
		}
		if len(ep.Comandos) > 0 {
			sumar("ejecutan", ep)
		}

		tocados := cebo.Tocados(ep.Comandos)
		if len(tocados) > 0 {
			sumar("tocan", ep)
			for _, nombre := range tocados {
				p := piezas[nombre]
				if p == nil {
					p = nuevo()
					piezas[nombre] = p
				}
				p.n++
				p.ips[ep.IP] = true
			}
		}

		// La severidad 'trampa' es la marca que SIEMPRE sobrevivio; la
		// etiqueta del cebo falta en los episodios anteriores a que se
		// guardara. Se mira la severidad para no perder aquellos.
		mordio := ep.CeboMordido != "" || string(ep.Severidad) == "trampa"
		if mordio {
			sumar("muerden", ep)
			// El mordisco cuenta como "leido aqui" solo si esa IP abrio el
			// botin en un momento ANTERIOR o en este mismo episodio.
			leido := len(tocados) > 0
			if !leido {
				if t, hay := primeraLectura[ep.IP]; hay && !t.After(ep.Fin) {
					leido = true
				}
			}
			if !leido {
				circulando++
			}
			etiqueta := ep.CeboMordido
			if etiqueta == "" {
				etiqueta = "cebo sin identificar"
			}
			mordiscos = append(mordiscos, Mordisco{
				Cebo:      etiqueta,
				IP:        ep.IP,
				Protocolo: ep.Protocolo,
				Cuando:    ep.Fin.UTC().Format(time.RFC3339),
				LeidoAqui: leido,
			})
		}
	}

	orden := []string{"llegan", "hablan", "entran", "ejecutan", "tocan", "muerden"}
	out := InformeCebo{Circulando: circulando, Mordiscos: mordiscos}
	for _, clave := range orden {
		a := fases[clave]
		f := FaseEmbudo{Clave: clave, Episodios: a.n, IPs: len(a.ips)}
		if a.n > 0 {
			f.Duracion = a.segundos / float64(a.n)
			f.Comandos = float64(a.comandos) / float64(a.n)
		}
		out.Fases = append(out.Fases, f)
	}

	for nombre, a := range piezas {
		out.Piezas = append(out.Piezas, PiezaTocada{
			Nombre: nombre, Episodios: a.n, IPs: len(a.ips),
		})
	}
	sort.Slice(out.Piezas, func(i, j int) bool {
		if out.Piezas[i].Episodios != out.Piezas[j].Episodios {
			return out.Piezas[i].Episodios > out.Piezas[j].Episodios
		}
		return out.Piezas[i].Nombre < out.Piezas[j].Nombre
	})

	// Lo mas reciente primero: un mordisco de hoy importa mas que uno de hace
	// dos meses.
	sort.Slice(out.Mordiscos, func(i, j int) bool {
		return strings.Compare(out.Mordiscos[i].Cuando, out.Mordiscos[j].Cuando) > 0
	})
	if len(out.Mordiscos) > 50 {
		out.Mordiscos = out.Mordiscos[:50]
	}
	return out
}
