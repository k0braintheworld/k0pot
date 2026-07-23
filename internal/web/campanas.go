package web

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/k0braintheworld/k0pot/internal/campana"
)

// campanas agrupa los ataques que comparten guion.
func (s *Servidor) campanas(w http.ResponseWriter, r *http.Request) {
	desde := time.Now().AddDate(0, 0, -dias(r))
	eps, err := s.Almacen.Episodios(desde, 500)
	if err != nil {
		http.Error(w, "no se pudieron leer los ataques", http.StatusInternalServerError)
		return
	}
	responderJSON(w, campana.Detectar(eps))
}

// Artefacto es algo que un atacante intento traerse al sistema.
type Artefacto struct {
	// URL de donde lo bajaba. Vacio si solo consta el fichero capturado.
	URL string `json:"url,omitempty"`
	// Fichero guardado en disco, si Cowrie llego a capturarlo.
	Fichero string    `json:"fichero,omitempty"`
	Bytes   int64     `json:"bytes,omitempty"`
	IPs     []string  `json:"ips,omitempty"`
	Momento time.Time `json:"momento"`
}

// artefactos lista lo que intentaron descargar.
//
// Es la evidencia de mas valor que deja un honeypot: la URL dice quien
// manda al bot y el fichero permite analizarlo. Se listan tambien los
// intentos fallidos -que son la mayoria- porque la URL sirve igual aunque
// la descarga no llegara a completarse.
func (s *Servidor) artefactos(w http.ResponseWriter, r *http.Request) {
	desde := time.Now().AddDate(0, 0, -dias(r))
	eps, err := s.Almacen.Episodios(desde, 500)
	if err != nil {
		http.Error(w, "no se pudieron leer los ataques", http.StatusInternalServerError)
		return
	}

	porURL := map[string]*Artefacto{}
	for _, e := range eps {
		for _, u := range e.Descargas {
			if u == "" {
				continue
			}
			a, hay := porURL[u]
			if !hay {
				a = &Artefacto{URL: u, Momento: e.Fin}
				porURL[u] = a
			}
			if e.Fin.After(a.Momento) {
				a.Momento = e.Fin
			}
			if !contiene(a.IPs, e.IP) {
				a.IPs = append(a.IPs, e.IP)
			}
		}
	}

	out := make([]Artefacto, 0, len(porURL))
	for _, a := range porURL {
		sort.Strings(a.IPs)
		out = append(out, *a)
	}
	out = append(out, ficherosCapturados(s.DirDescargas)...)

	sort.Slice(out, func(i, j int) bool { return out[i].Momento.After(out[j].Momento) })
	responderJSON(w, out)
}

// ficherosCapturados lista lo que Cowrie llego a guardar en disco.
//
// El nombre que les pone Cowrie es el resumen SHA-256 del contenido, asi
// que sirve tal cual para buscarlo en VirusTotal sin subir nada.
func ficherosCapturados(dir string) []Artefacto {
	if dir == "" {
		return nil
	}
	entradas, err := os.ReadDir(dir)
	if err != nil {
		return nil // que no exista aun es lo normal: solo aparece si capturan algo
	}
	var out []Artefacto
	for _, e := range entradas {
		if e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, Artefacto{
			Fichero: filepath.Base(e.Name()),
			Bytes:   info.Size(),
			Momento: info.ModTime(),
		})
	}
	return out
}

func contiene(v []string, s string) bool {
	for _, x := range v {
		if x == s {
			return true
		}
	}
	return false
}
