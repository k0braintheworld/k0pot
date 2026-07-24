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
	"github.com/k0braintheworld/k0pot/internal/episodio"
	"github.com/k0braintheworld/k0pot/internal/report"
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
	respuesta := struct {
		Episodios   []store.EpisodioFila `json:"episodios"`
		Explicacion string               `json:"explicacion,omitempty"`
	}{Episodios: campana.EpisodiosDe(eps, tipo, huella)}
	idioma := idiomaDe(r)
	for i := range respuesta.Episodios {
		respuesta.Episodios[i].Resumen = episodio.Redactar(respuesta.Episodios[i].Episodio, idioma)
	}
	respuesta.Explicacion, _ = s.Almacen.ExplicacionDe("campana", string(tipo)+"|"+huella)
	responderJSON(w, respuesta)
}

// idiomaDe saca el idioma pedido para la explicacion con IA; por defecto
// espanol. Solo distingue "en"; cualquier otra cosa es espanol.
func idiomaDe(r *http.Request) string {
	if r.URL.Query().Get("idioma") == "en" {
		return "en"
	}
	return "es"
}

// queComparten pone en una frase lo que une a los ataques de una campana,
// para dárselo al modelo en lenguaje llano.
func queComparten(tipo campana.Tipo) string {
	switch tipo {
	case campana.PorCredenciales:
		return "el mismo diccionario de usuario y contrasena"
	case campana.PorDescarga:
		return "el mismo fichero que se traen"
	case campana.PorComandos:
		return "la misma secuencia de comandos"
	case campana.PorRutas:
		return "las mismas rutas web tanteadas"
	}
	return string(tipo)
}

// explicarCampana pide al modelo que cuente que operacion coordinada hay
// detras de una campana. Gasta cuota y guarda el resultado por su huella.
func (s *Servidor) explicarCampana(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, http.StatusMethodNotAllowed, "usa POST")
		return
	}
	tipo := campana.Tipo(strings.TrimSpace(r.URL.Query().Get("tipo")))
	huella := strings.TrimSpace(r.URL.Query().Get("huella"))
	if tipo == "" || huella == "" {
		responderError(w, http.StatusBadRequest, "faltan el tipo y la huella")
		return
	}
	desde := time.Now().AddDate(0, 0, -dias(r))
	eps, err := s.Almacen.Episodios(store.FiltroEpisodios{Desde: desde, Limite: 500})
	if err != nil {
		http.Error(w, "no se pudieron leer los ataques", http.StatusInternalServerError)
		return
	}
	var elegida campana.Campana
	hallada := false
	for _, c := range campana.Detectar(eps) {
		if c.Tipo == tipo && c.Huella == huella {
			elegida, hallada = c, true
			break
		}
	}
	if !hallada {
		responderError(w, http.StatusNotFound, "esa campana ya no existe en el periodo")
		return
	}
	explicador, ok := s.Generador.(report.Explicador)
	if !ok {
		responderError(w, http.StatusBadRequest,
			"no hay ningun modelo configurado: revisa Ajustes -> Informes")
		return
	}
	dia := time.Now().Format("2006-01-02")
	permitido, err := s.Almacen.ConsumirCuotaLLM(dia, s.Config.Actual().InformeTopeDiario)
	if err != nil {
		http.Error(w, "no se pudo comprobar la cuota", http.StatusInternalServerError)
		return
	}
	if !permitido {
		responderError(w, http.StatusTooManyRequests, "alcanzado el tope de IA de hoy")
		return
	}
	texto, err := report.ExplicarCampana(r.Context(), explicador,
		queComparten(tipo), elegida.Muestra, len(elegida.IPs),
		elegida.Paises, string(elegida.Severidad), idiomaDe(r), 2000)
	if err != nil {
		s.Almacen.DevolverCuotaLLM(dia)
		responderError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := s.Almacen.GuardarExplicacionDe("campana", string(tipo)+"|"+huella, texto); err != nil {
		http.Error(w, "no se pudo guardar la explicacion", http.StatusInternalServerError)
		return
	}
	responderJSON(w, map[string]string{"explicacion": texto})
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
		// Cowrie solo registra como "descarga" lo que llega a bajar; el
		// resto -la mayoria- queda escondido en los wget/curl/tftp que se
		// teclean, y ahi esta lo mas util: de donde se sirve el malware.
		fuentes := append(append([]string{}, e.Descargas...), urlsDeDescarga(e.Comandos)...)
		for _, u := range fuentes {
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
	out = append(out, s.ficherosCapturados()...)

	sort.Slice(out, func(i, j int) bool { return out[i].Momento.After(out[j].Momento) })
	responderJSON(w, out)
}

// ficherosCapturados lista lo que Cowrie llego a guardar en disco.
//
// El nombre que les pone Cowrie es el resumen SHA-256 del contenido, asi
// que sirve tal cual para buscarlo en VirusTotal sin subir nada.
func (s *Servidor) ficherosCapturados() []Artefacto {
	dir := s.DirDescargas
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
		a := Artefacto{
			Fichero: filepath.Base(e.Name()),
			Bytes:   info.Size(),
			Momento: info.ModTime(),
		}
		// De quien y cuando vino: sin esto, un fichero capturado es un hash
		// suelto sin decir cuantos lo trajeron ni desde donde.
		if fu, err := s.Almacen.FuentesDeArtefacto(e.Name()); err == nil {
			a.IPs = fu.IPs
			if !fu.Ultima.IsZero() {
				a.Momento = fu.Ultima
			}
		}
		out = append(out, a)
	}
	return out
}

// urlsDeDescarga saca las URLs de descarga que un atacante teclea en la
// shell (wget/curl/tftp). Es lo que separa "vimos 3 ficheros" de "estos son
// los servidores que reparten el malware", que es lo que de verdad importa.
func urlsDeDescarga(comandos []string) []string {
	vistas := map[string]bool{}
	var out []string
	add := func(u string) {
		if u != "" && !vistas[u] {
			vistas[u] = true
			out = append(out, u)
		}
	}
	for _, cmd := range comandos {
		for _, u := range reURLDescarga.FindAllString(cmd, -1) {
			add(strings.TrimRight(u, ".,)"))
		}
		for _, m := range reTFTP.FindAllStringSubmatch(cmd, -1) {
			add("tftp://" + m[1])
		}
	}
	return out
}

// reURLDescarga casa una URL http(s) dentro de una linea de shell, cortando
// en los caracteres que no pueden formar parte de ella (comillas, tuberias,
// separadores de comando).
var reURLDescarga = regexp.MustCompile("https?://[^\\s\x27\"|>&`;)]+")

// reTFTP saca la IP a la que se conecta un tftp: no lleva esquema http, asi
// que hay que reconocerlo por el verbo y la direccion.
var reTFTP = regexp.MustCompile(`(?i)\btftp\b[^\n]*?\b(\d{1,3}(?:\.\d{1,3}){3})\b`)

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
	SHA256      string    `json:"sha256"`
	Bytes       int64     `json:"bytes"`
	Tipo        string    `json:"tipo"`
	Cadenas     []string  `json:"cadenas"`
	IPs         []string  `json:"ips,omitempty"`
	URLs        []string  `json:"urls,omitempty"`
	Primera     time.Time `json:"primera,omitempty"`
	Ultima      time.Time `json:"ultima,omitempty"`
	Explicacion string    `json:"explicacion,omitempty"`
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
// detalleArtefacto arma la ficha de una muestra: tipo, tamano, cadenas y de
// donde vino. Solo lee bytes; nunca ejecuta el fichero. Lo comparten la ficha
// (GET) y la explicacion con IA (POST).
func (s *Servidor) detalleArtefacto(hash string) (DetalleArtefacto, bool) {
	ruta, ok := s.rutaArtefacto(hash)
	if !ok {
		return DetalleArtefacto{}, false
	}
	info, err := os.Stat(ruta)
	if err != nil || info.IsDir() {
		return DetalleArtefacto{}, false
	}
	f, err := os.Open(ruta)
	if err != nil {
		return DetalleArtefacto{}, false
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
	return det, true
}

func (s *Servidor) artefacto(w http.ResponseWriter, r *http.Request) {
	det, ok := s.detalleArtefacto(strings.TrimSpace(r.URL.Query().Get("hash")))
	if !ok {
		responderError(w, http.StatusNotFound, "ese artefacto no existe")
		return
	}
	det.Explicacion, _ = s.Almacen.ExplicacionDe("artefacto", det.SHA256)
	responderJSON(w, det)
}

// explicarArtefacto pide al modelo que cuente que es y que hace la muestra,
// a partir de su tipo y sus cadenas -sin ejecutarla-. Gasta cuota igual que
// la explicacion de un ataque, y guarda el resultado por su hash.
func (s *Servidor) explicarArtefacto(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, http.StatusMethodNotAllowed, "usa POST")
		return
	}
	det, ok := s.detalleArtefacto(strings.TrimSpace(r.URL.Query().Get("hash")))
	if !ok {
		responderError(w, http.StatusNotFound, "ese artefacto no existe")
		return
	}
	explicador, ok := s.Generador.(report.Explicador)
	if !ok {
		responderError(w, http.StatusBadRequest,
			"no hay ningun modelo configurado: revisa Ajustes -> Informes")
		return
	}
	dia := time.Now().Format("2006-01-02")
	permitido, err := s.Almacen.ConsumirCuotaLLM(dia, s.Config.Actual().InformeTopeDiario)
	if err != nil {
		http.Error(w, "no se pudo comprobar la cuota", http.StatusInternalServerError)
		return
	}
	if !permitido {
		responderError(w, http.StatusTooManyRequests, "alcanzado el tope de IA de hoy")
		return
	}
	texto, err := report.ExplicarArtefacto(r.Context(), explicador,
		det.Tipo, det.Bytes, det.Cadenas, det.URLs, idiomaDe(r), 2000)
	if err != nil {
		s.Almacen.DevolverCuotaLLM(dia)
		responderError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := s.Almacen.GuardarExplicacionDe("artefacto", det.SHA256, texto); err != nil {
		http.Error(w, "no se pudo guardar la explicacion", http.StatusInternalServerError)
		return
	}
	responderJSON(w, map[string]string{"explicacion": texto})
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
