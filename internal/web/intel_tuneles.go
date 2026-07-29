package web

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/store"
)

// DestinoTunel agrega los destinos a los que atacantes pidieron reenviar
// trafico, para ver que infraestructura real intentan alcanzar a traves
// del honeypot.
type DestinoTunel struct {
	Destino string   `json:"destino"`
	Veces   int      `json:"veces"`
	IPs     []string `json:"ips"`
	Primera string   `json:"primera,omitempty"`
	Ultima  string   `json:"ultima,omitempty"`
}

func (s *Servidor) tuneles(w http.ResponseWriter, r *http.Request) {
	desde := time.Now().AddDate(0, 0, -dias(r))
	eps, err := s.Almacen.Episodios(store.FiltroEpisodios{Desde: desde, Limite: 2000})
	if err != nil {
		http.Error(w, "no se pudieron leer los ataques", http.StatusInternalServerError)
		return
	}

	type agg struct {
		ips     map[string]bool
		veces   int
		primera time.Time
		ultima  time.Time
	}
	por := map[string]*agg{}

	for _, ep := range eps {
		for _, dest := range ep.Tuneles {
			dest = strings.TrimSpace(dest)
			if dest == "" {
				continue
			}
			a := por[dest]
			if a == nil {
				a = &agg{ips: map[string]bool{}}
				por[dest] = a
			}
			a.veces++
			a.ips[ep.IP] = true
			if a.primera.IsZero() || ep.Inicio.Before(a.primera) {
				a.primera = ep.Inicio
			}
			if ep.Fin.After(a.ultima) {
				a.ultima = ep.Fin
			}
		}
	}

	out := make([]DestinoTunel, 0, len(por))
	for dest, a := range por {
		ips := make([]string, 0, len(a.ips))
		for ip := range a.ips {
			ips = append(ips, ip)
		}
		sort.Strings(ips)
		out = append(out, DestinoTunel{
			Destino: dest,
			Veces:   a.veces,
			IPs:     ips,
			Primera: a.primera.UTC().Format(time.RFC3339),
			Ultima:  a.ultima.UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Veces != out[j].Veces {
			return out[i].Veces > out[j].Veces
		}
		return out[i].Destino < out[j].Destino
	})
	responderJSON(w, out)
}
