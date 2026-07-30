package web

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/k0braintheworld/k0pot/internal/artefacto"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// cacheIntel guarda los resultados de inteligencia precalculados para
// servirlos al instante en cada refresco del panel. Se recalculan cada
// pocos minutos en segundo plano; el coste de leer artefactos de disco y
// barrer 2000 episodios se paga una vez, no en cada peticion HTTP.
type cacheIntel struct {
	mu        sync.RWMutex
	c2        []NodoC2
	botnets   []FamiliaBotnet
	tuneles   []DestinoTunel
	calculado time.Time
}

const intervaloIntel = 5 * time.Minute

func (s *Servidor) IniciarCacheIntel() {
	s.intel.recalcular(s)
	go func() {
		for range time.Tick(intervaloIntel) {
			s.intel.recalcular(s)
		}
	}()
}

func (c *cacheIntel) recalcular(s *Servidor) {
	desde := time.Now().AddDate(0, 0, -90)
	eps, _ := s.Almacen.Episodios(store.FiltroEpisodios{Desde: desde, Limite: 2000})

	nuevoC2 := calcularC2(s, eps, desde)
	nuevoBot := calcularBotnets(eps)
	nuevoTun := calcularTuneles(eps)

	c.mu.Lock()
	c.c2 = nuevoC2
	c.botnets = nuevoBot
	c.tuneles = nuevoTun
	c.calculado = time.Now()
	c.mu.Unlock()
}

// ── Handlers: sirven desde cache ─────────────────────────────────────

func (s *Servidor) infraC2(w http.ResponseWriter, r *http.Request) {
	s.intel.mu.RLock()
	out := s.intel.c2
	s.intel.mu.RUnlock()
	if out == nil {
		out = []NodoC2{}
	}
	responderJSON(w, out)
}

func (s *Servidor) botnets(w http.ResponseWriter, r *http.Request) {
	s.intel.mu.RLock()
	out := s.intel.botnets
	s.intel.mu.RUnlock()
	if out == nil {
		out = []FamiliaBotnet{}
	}
	responderJSON(w, out)
}

func (s *Servidor) tuneles(w http.ResponseWriter, r *http.Request) {
	s.intel.mu.RLock()
	out := s.intel.tuneles
	s.intel.mu.RUnlock()
	if out == nil {
		out = []DestinoTunel{}
	}
	responderJSON(w, out)
}

// ── Calculo puro (sin HTTP) ──────────────────────────────────────────

func calcularC2(s *Servidor, eps []store.EpisodioFila, desde time.Time) []NodoC2 {
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

	if cbs, err := s.Almacen.CallbacksDesde(desde); err == nil {
		for _, cb := range cbs {
			h := hostDeURL(cb.Destino)
			if h == "" {
				h = cb.Destino
			}
			registrar(h, "callback", cb.Exploit, cb.Primera)
		}
	}

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
	return out
}

func calcularBotnets(eps []store.EpisodioFila) []FamiliaBotnet {
	type agg struct {
		familia string
		desc    string
		ips     map[string]bool
		n       int
		ejemplo []string
		primera time.Time
		ultima  time.Time
	}
	por := map[string]*agg{}

	for _, ep := range eps {
		if len(ep.Comandos) == 0 {
			continue
		}
		fam := clasificarBotnet(ep.Comandos)
		if fam == "" {
			continue
		}
		a := por[fam]
		if a == nil {
			var desc string
			for _, f := range firmasBotnet {
				if f.familia == fam {
					desc = f.desc
					break
				}
			}
			a = &agg{familia: fam, desc: desc, ips: map[string]bool{}}
			por[fam] = a
		}
		a.n++
		a.ips[ep.IP] = true
		if a.primera.IsZero() || ep.Inicio.Before(a.primera) {
			a.primera = ep.Inicio
		}
		if ep.Fin.After(a.ultima) {
			a.ultima = ep.Fin
		}
		if len(a.ejemplo) == 0 && len(ep.Comandos) > 0 {
			lim := ep.Comandos
			if len(lim) > 5 {
				lim = lim[:5]
			}
			a.ejemplo = lim
		}
	}

	out := make([]FamiliaBotnet, 0, len(por))
	for _, a := range por {
		out = append(out, FamiliaBotnet{
			Familia:     a.familia,
			Descripcion: a.desc,
			Episodios:   a.n,
			IPs:         len(a.ips),
			Ejemplo:     a.ejemplo,
			Primera:     a.primera.UTC().Format(time.RFC3339),
			Ultima:      a.ultima.UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Episodios > out[j].Episodios })
	return out
}

func calcularTuneles(eps []store.EpisodioFila) []DestinoTunel {
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
	return out
}
