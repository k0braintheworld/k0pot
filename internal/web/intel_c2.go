package web

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/artefacto"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// NodoC2 es un host de infraestructura de atacante: un C2, un servidor de
// segunda fase o un punto de descarga de malware. Se agrega de todas las
// fuentes (muestras embebidas, callbacks de exploits, URLs de descarga)
// para dar una vista unica de "contra quien nos enfrentamos".
type NodoC2 struct {
	Host     string   `json:"host"`
	Fuentes  []string `json:"fuentes"`
	Veces    int      `json:"veces"`
	Primera  string   `json:"primera,omitempty"`
	Ultima   string   `json:"ultima,omitempty"`
	Familias []string `json:"familias,omitempty"`
}

func (s *Servidor) infraC2(w http.ResponseWriter, r *http.Request) {
	desde := time.Now().AddDate(0, 0, -dias(r))

	type entrada struct {
		fuentes  map[string]bool
		familias map[string]bool
		veces    int
		primera  time.Time
		ultima   time.Time
	}
	nodos := map[string]*entrada{}

	registrar := func(host, fuente, familia string, cuando time.Time) {
		host = strings.ToLower(strings.TrimSpace(host))
		if host == "" {
			return
		}
		e := nodos[host]
		if e == nil {
			e = &entrada{fuentes: map[string]bool{}, familias: map[string]bool{}}
			nodos[host] = e
		}
		e.fuentes[fuente] = true
		e.veces++
		if familia != "" {
			e.familias[familia] = true
		}
		if e.primera.IsZero() || cuando.Before(e.primera) {
			e.primera = cuando
		}
		if cuando.After(e.ultima) {
			e.ultima = cuando
		}
	}

	// 1) Callbacks de exploits (C2 directo)
	if cbs, err := s.Almacen.CallbacksDesde(desde); err == nil {
		for _, cb := range cbs {
			h := hostDeURL(cb.Destino)
			if h == "" {
				h = cb.Destino
			}
			registrar(h, "callback", cb.Exploit, cb.Primera)
		}
	}

	// 2) C2 embebido en muestras capturadas
	if s.DirDescargas != "" {
		if entradas, err := os.ReadDir(s.DirDescargas); err == nil {
			for _, e := range entradas {
				if e.IsDir() || !reHashArtefacto.MatchString(e.Name()) {
					continue
				}
				info, err := e.Info()
				if err != nil {
					continue
				}
				datos, err := leerAcotado(filepath.Join(s.DirDescargas, e.Name()), 4<<20)
				if err != nil {
					continue
				}
				ind := artefacto.IndicadoresDe(datos)
				cuando := info.ModTime()
				for _, ip := range ind.IPs {
					registrar(ip, "muestra", "", cuando)
				}
				for _, u := range ind.URLs {
					h := hostDeURL(u)
					registrar(h, "muestra", "", cuando)
				}
			}
		}
	}

	// 3) URLs de descarga de malware (servidores de distribución)
	eps, _ := s.Almacen.Episodios(store.FiltroEpisodios{Desde: desde, Limite: 2000})
	for _, ep := range eps {
		urls := append(append([]string{}, ep.Descargas...), urlsDeDescarga(ep.Comandos)...)
		for _, u := range urls {
			h := hostDeURL(u)
			registrar(h, "descarga", "", ep.Fin)
		}
	}

	out := make([]NodoC2, 0, len(nodos))
	for host, e := range nodos {
		n := NodoC2{
			Host:    host,
			Veces:   e.veces,
			Primera: e.primera.UTC().Format(time.RFC3339),
			Ultima:  e.ultima.UTC().Format(time.RFC3339),
		}
		for f := range e.fuentes {
			n.Fuentes = append(n.Fuentes, f)
		}
		sort.Strings(n.Fuentes)
		for f := range e.familias {
			n.Familias = append(n.Familias, f)
		}
		sort.Strings(n.Familias)
		out = append(out, n)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Veces != out[j].Veces {
			return out[i].Veces > out[j].Veces
		}
		return out[i].Host < out[j].Host
	})
	responderJSON(w, out)
}
