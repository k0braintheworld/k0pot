package web

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/artefacto"
	"github.com/k0braintheworld/k0pot/internal/campana"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// campanas agrupa los ataques que comparten guion.
func (s *Servidor) campanas(w http.ResponseWriter, r *http.Request) {
	desde := time.Now().AddDate(0, 0, -dias(r))
	eps, err := s.Almacen.Episodios(store.FiltroEpisodios{Desde: desde, Limite: 500})
	if err != nil {
		http.Error(w, "no se pudieron leer los ataques", http.StatusInternalServerError)
		return
	}
	// Solo las que aportan: a bajo volumen, agrupar escaneres de
	// investigacion que hacen el mismo PING es cierto pero inutil. El bloque
	// del panel se oculta solo cuando esto viene vacio.
	todas := campana.Detectar(eps)
	interesantes := todas[:0]
	for _, c := range todas {
		if c.Interesante() {
			interesantes = append(interesantes, c)
		}
	}
	responderJSON(w, interesantes)
}

// campana devuelve los ataques de UNA campana, para su detalle. Se identifica
// por tipo+huella, ambos ya presentes en el JSON de /api/campanas.
func (s *Servidor) campana(w http.ResponseWriter, r *http.Request) {
	tipo := campana.Tipo(strings.TrimSpace(r.URL.Query().Get("tipo")))
	huella := strings.TrimSpace(r.URL.Query().Get("huella"))
	if tipo == "" || huella == "" {
		responderError(w, http.StatusBadRequest, "faltan el tipo y la huella de la campana")
		return
	}
	desde := time.Now().AddDate(0, 0, -dias(r))
	eps, err := s.Almacen.Episodios(store.FiltroEpisodios{Desde: desde, Limite: 500})
	if err != nil {
		http.Error(w, "no se pudieron leer los ataques", http.StatusInternalServerError)
		return
	}
	responderJSON(w, campana.EpisodiosDe(eps, tipo, huella))
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
	eps, err := s.Almacen.Episodios(store.FiltroEpisodios{Desde: desde, Limite: 500})
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
		if e.IsDir() || !reHashArtefacto.MatchString(e.Name()) {
			// Solo los ficheros que Cowrie nombra con el SHA-256 son descargas
			// de verdad; los "redir__" de shell son ruido de 0 bytes.
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

// reHashArtefacto valida un SHA-256 hex. Es la unica entrada de la que se
// construye una ruta a disco, asi que el filtro es la barrera contra el path
// traversal: solo 64 caracteres hex, nada de barras ni puntos.
var reHashArtefacto = regexp.MustCompile(`^[a-f0-9]{64}$`)

// DetalleArtefacto describe un fichero capturado para revisarlo SIN ejecutarlo.
type DetalleArtefacto struct {
	SHA256  string    `json:"sha256"`
	Bytes   int64     `json:"bytes"`
	Tipo    string    `json:"tipo"`
	Cadenas []string  `json:"cadenas"`
	IPs     []string  `json:"ips,omitempty"`
	URLs    []string  `json:"urls,omitempty"`
	Primera time.Time `json:"primera,omitempty"`
	Ultima  time.Time `json:"ultima,omitempty"`
}

// rutaArtefacto valida el hash y devuelve la ruta al fichero, garantizando
// que cae dentro del directorio de descargas.
func (s *Servidor) rutaArtefacto(hash string) (string, bool) {
	if s.DirDescargas == "" || !reHashArtefacto.MatchString(hash) {
		return "", false
	}
	ruta := filepath.Join(s.DirDescargas, hash)
	// Defensa en profundidad: el hash validado ya lo impide, pero se confirma
	// que la ruta resuelta sigue dentro del directorio esperado.
	if filepath.Dir(ruta) != filepath.Clean(s.DirDescargas) {
		return "", false
	}
	return ruta, true
}

// artefacto describe una muestra: que es, que cadenas lleva dentro y quien la
// trajo. Nunca ejecuta el fichero; solo lee sus bytes.
func (s *Servidor) artefacto(w http.ResponseWriter, r *http.Request) {
	hash := strings.TrimSpace(r.URL.Query().Get("hash"))
	ruta, ok := s.rutaArtefacto(hash)
	if !ok {
		responderError(w, http.StatusBadRequest, "hash de artefacto invalido")
		return
	}
	info, err := os.Stat(ruta)
	if err != nil || info.IsDir() {
		responderError(w, http.StatusNotFound, "ese artefacto no existe")
		return
	}
	f, err := os.Open(ruta)
	if err != nil {
		http.Error(w, "no se pudo leer el artefacto", http.StatusInternalServerError)
		return
	}
	defer f.Close()
	// Solo los primeros 4 KB: basta para el tipo y una vista previa de cadenas.
	cabecera := make([]byte, 4096)
	n, _ := io.ReadFull(f, cabecera)
	cabecera = cabecera[:n]

	det := DetalleArtefacto{
		SHA256:  hash,
		Bytes:   info.Size(),
		Tipo:    artefacto.Tipo(cabecera),
		Cadenas: artefacto.Cadenas(cabecera, 60),
	}
	if fu, err := s.Almacen.FuentesDeArtefacto(hash); err == nil {
		det.IPs, det.URLs = fu.IPs, fu.URLs
		det.Primera, det.Ultima = fu.Primera, fu.Ultima
	}
	responderJSON(w, det)
}

// artefactoContenido entrega el fichero SIEMPRE como adjunto inerte: nunca con
// su tipo real, forzando la descarga y sin que el navegador adivine el tipo.
// Asi no hay forma de que se ejecute ni se interprete como HTML/JS al abrirlo.
// El servidor solo lee bytes; no lo abre como programa.
func (s *Servidor) artefactoContenido(w http.ResponseWriter, r *http.Request) {
	hash := strings.TrimSpace(r.URL.Query().Get("hash"))
	ruta, ok := s.rutaArtefacto(hash)
	if !ok {
		responderError(w, http.StatusBadRequest, "hash de artefacto invalido")
		return
	}
	f, err := os.Open(ruta)
	if err != nil {
		responderError(w, http.StatusNotFound, "ese artefacto no existe")
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", hash+".bin"))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	if info, err := f.Stat(); err == nil {
		w.Header().Set("Content-Length", strconv.FormatInt(info.Size(), 10))
	}
	io.Copy(w, f)
}
