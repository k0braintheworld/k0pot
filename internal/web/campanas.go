package web

import (
	"context"
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
	"github.com/k0braintheworld/k0pot/internal/enrich"
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
		Pendiente   bool                 `json:"pendiente,omitempty"`
		// Fichero enlaza una campana de descarga con el binario capturado,
		// para saltar de "se traen esto" a poder abrir y ver que era.
		Fichero string `json:"fichero,omitempty"`
	}{Episodios: campana.EpisodiosDe(eps, tipo, huella)}
	if tipo == campana.PorDescarga {
		for _, e := range respuesta.Episodios {
			for _, u := range e.Descargas {
				if sha, ok := s.Almacen.ShaDeURL(u); ok {
					respuesta.Fichero = sha
					break
				}
			}
			if respuesta.Fichero != "" {
				break
			}
		}
	}
	idioma := idiomaDe(r)
	for i := range respuesta.Episodios {
		respuesta.Episodios[i].Resumen = episodio.Redactar(respuesta.Episodios[i].Episodio, idioma)
	}
	respuesta.Explicacion, _ = s.Almacen.ExplicacionDe("campana", string(tipo)+"|"+huella)
	if respuesta.Explicacion == "" && s.puedeExplicar() {
		respuesta.Pendiente = true
		s.pedirExplicacion("campana|" + string(tipo) + "|" + huella)
	}
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
	Fichero string `json:"fichero,omitempty"`
	Bytes   int64  `json:"bytes,omitempty"`
	// Tipo es que es el fichero (ELF MIPS, script, texto...), leido de sus
	// bytes; o una marca de "prueba de escritura" para los triviales.
	Tipo string `json:"tipo,omitempty"`
	// Destino es donde el atacante intento dejarlo (/dev/.fxcat...).
	Destino string `json:"destino,omitempty"`
	// Amenaza es la clase de peligro (botnet, dropper, minero, webshell,
	// prueba, muestra), para triar y ordenar de un vistazo.
	Amenaza string `json:"amenaza,omitempty"`
	// C2 resume la infraestructura que la muestra lleva dentro (los hosts),
	// para verla en la lista sin abrir la ficha.
	C2      string    `json:"c2,omitempty"`
	IPs     []string  `json:"ips,omitempty"`
	Momento time.Time `json:"momento"`
	// FicheroDe es el SHA-256 del fichero que SI se capturo desde esta URL,
	// si alguno: enlaza el intento con la muestra que dejo.
	FicheroDe string `json:"fichero_de,omitempty"`
	// Explicacion guardada de la URL; se precarga para no re-gastar cuota al
	// reabrir el detalle.
	Explicacion string `json:"explicacion,omitempty"`
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
		if sha, ok := s.Almacen.ShaDeURL(a.URL); ok {
			a.FicheroDe = sha
		}
		a.Explicacion, _ = s.Almacen.ExplicacionDe("url", a.URL)
		out = append(out, *a)
	}
	out = append(out, s.ficherosCapturados()...)

	// Lo peligroso primero (una botnet pesa mas que una prueba de escritura),
	// y a igual peligro, lo mas reciente.
	sort.Slice(out, func(i, j int) bool {
		ri, rj := artefacto.RangoAmenaza(out[i].Amenaza), artefacto.RangoAmenaza(out[j].Amenaza)
		if ri != rj {
			return ri > rj
		}
		return out[i].Momento.After(out[j].Momento)
	})
	responderJSON(w, out)
}

// describirFichero dice QUE es una muestra (tipo) y QUE CLASE de amenaza
// es, leyendo sus bytes una sola vez, sin ejecutarla. Los ficheros
// minusculos casi siempre son una prueba de escritura de un bot (echo >
// /dev/.algo), no malware: se marcan como tal para no confundir.
func describirFichero(ruta string, tam int64) (tipo, amenaza, c2 string) {
	if tam <= 8 {
		return fmt.Sprintf("prueba de escritura (%d B)", tam), "prueba", ""
	}
	datos, err := leerAcotado(ruta, 128<<10)
	if err != nil {
		return "", "", ""
	}
	cab := datos
	if len(cab) > 512 {
		cab = cab[:512]
	}
	tipo = artefacto.Tipo(cab)
	return tipo, artefacto.Clasificar(datos, tipo, tam), c2DeMuestra(artefacto.IndicadoresDe(datos))
}

// c2DeMuestra resume en una linea los hosts (IPs y dominios) que una muestra
// lleva dentro, para ensenar la infraestructura del atacante en la lista.
func c2DeMuestra(ind artefacto.Indicadores) string {
	vistos := map[string]bool{}
	var hosts []string
	anade := func(h string) {
		h = strings.ToLower(h)
		if h != "" && !vistos[h] {
			vistos[h] = true
			hosts = append(hosts, h)
		}
	}
	for _, ip := range ind.IPs {
		anade(ip)
	}
	for _, u := range ind.URLs {
		anade(hostDeURL(u))
	}
	if len(hosts) == 0 {
		return ""
	}
	if len(hosts) > 2 {
		return fmt.Sprintf("%s +%d", strings.Join(hosts[:2], ", "), len(hosts)-2)
	}
	return strings.Join(hosts, ", ")
}

// hostDeURL saca el host de una URL (sin esquema, ruta ni puerto).
func hostDeURL(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return ""
	}
	h := u[i+3:]
	if j := strings.IndexAny(h, "/:?@"); j >= 0 {
		h = h[:j]
	}
	return h
}

// iocsEmbebidos saca la infraestructura que las muestras capturadas llevan
// ESCRITA dentro (el C2 de un dropper o un binario). Lee cada fichero hasta
// un tope y extrae sus URLs e IPs. Nunca ejecuta nada.
func (s *Servidor) iocsEmbebidos() []ioc {
	if s.DirDescargas == "" {
		return nil
	}
	entradas, err := os.ReadDir(s.DirDescargas)
	if err != nil {
		return nil
	}
	vistos := map[string]bool{}
	var out []ioc
	for _, e := range entradas {
		if e.IsDir() || !reHashArtefacto.MatchString(e.Name()) {
			continue
		}
		datos, err := leerAcotado(filepath.Join(s.DirDescargas, e.Name()), 4<<20)
		if err != nil {
			continue
		}
		var cuando time.Time
		if info, err := e.Info(); err == nil {
			cuando = info.ModTime()
		}
		ind := artefacto.IndicadoresDe(datos)
		anota := func(clase, valor string) {
			k := clase + "|" + valor
			if valor == "" || vistos[k] {
				return
			}
			vistos[k] = true
			out = append(out, ioc{clase: clase, valor: valor, primera: cuando, ultima: cuando,
				etiqueta: "hallado dentro de una muestra capturada"})
		}
		for _, u := range ind.URLs {
			anota("url", u)
		}
		for _, ip := range ind.IPs {
			anota("ipv4-addr", ip)
		}
	}
	return out
}

// leerAcotado lee hasta 'tope' bytes de un fichero, sin cargarlo entero.
func leerAcotado(ruta string, tope int) ([]byte, error) {
	f, err := os.Open(ruta)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, tope)
	n, _ := io.ReadFull(f, buf)
	return buf[:n], nil
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
		tipo, amenaza, c2 := describirFichero(filepath.Join(dir, e.Name()), info.Size())
		a := Artefacto{
			Fichero: filepath.Base(e.Name()),
			Bytes:   info.Size(),
			Momento: info.ModTime(),
			Tipo:    tipo,
			Amenaza: amenaza,
			C2:      c2,
		}
		// De quien y cuando vino: sin esto, un fichero capturado es un hash
		// suelto sin decir cuantos lo trajeron ni desde donde.
		if fu, err := s.Almacen.FuentesDeArtefacto(e.Name()); err == nil {
			a.IPs = fu.IPs
			if len(fu.Destinos) > 0 {
				a.Destino = fu.Destinos[0]
			}
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
	SHA256  string   `json:"sha256"`
	Bytes   int64    `json:"bytes"`
	Tipo    string   `json:"tipo"`
	Cadenas []string `json:"cadenas"`
	// Vista es el contenido tal cual cuando es texto (un script .sh se lee
	// entero); vacio si es binario, donde el volcado no dice nada.
	Vista string   `json:"vista,omitempty"`
	IPs   []string `json:"ips,omitempty"`
	URLs  []string `json:"urls,omitempty"`
	// URLsDentro / IPsDentro es la infraestructura que la muestra lleva
	// ESCRITA dentro (su C2, su segunda fase); distinto de URLs/IPs, que
	// son de donde vino y quien la trajo.
	URLsDentro  []string  `json:"urls_dentro,omitempty"`
	IPsDentro   []string  `json:"ips_dentro,omitempty"`
	Primera     time.Time `json:"primera,omitempty"`
	Ultima      time.Time `json:"ultima,omitempty"`
	Pendiente   bool      `json:"pendiente,omitempty"`
	Explicacion string    `json:"explicacion,omitempty"`
	// VT es el veredicto de VirusTotal por el hash, si hay clave configurada.
	VT *enrich.VeredictoVT `json:"vt,omitempty"`
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
	// Se leen hasta 4 MB: el tipo y la vista salen de la cabecera, pero la
	// infraestructura embebida (el C2) puede estar mas adentro. Nunca se
	// ejecuta: solo se leen bytes.
	contenido := make([]byte, 4<<20)
	n, _ := io.ReadFull(f, contenido)
	contenido = contenido[:n]
	cabecera := contenido
	if len(cabecera) > 4096 {
		cabecera = cabecera[:4096]
	}

	det := DetalleArtefacto{
		SHA256:  hash,
		Bytes:   info.Size(),
		Tipo:    artefacto.Tipo(cabecera),
		Cadenas: artefacto.Cadenas(cabecera, 60),
	}
	if artefacto.EsTexto(cabecera) {
		det.Vista = string(cabecera)
	}
	if ind := artefacto.IndicadoresDe(contenido); len(ind.URLs) > 0 || len(ind.IPs) > 0 {
		det.URLsDentro, det.IPsDentro = ind.URLs, ind.IPs
	}
	if fu, err := s.Almacen.FuentesDeArtefacto(hash); err == nil {
		det.IPs, det.URLs = fu.IPs, fu.URLs
		det.Primera, det.Ultima = fu.Primera, fu.Ultima
	}
	if clave := s.Config.Actual().ClaveVirusTotal; clave != "" {
		ctx, cancelar := context.WithTimeout(context.Background(), 9*time.Second)
		defer cancelar()
		if v, err := enrich.VirusTotal(ctx, nil, clave, hash); err == nil {
			det.VT = &v
		}
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
	if det.Explicacion == "" && s.puedeExplicar() {
		det.Pendiente = true
		s.pedirExplicacion("artefacto|" + det.SHA256)
	}
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

// explicarURL explica una direccion de descarga sin fichero capturado: lo unico
// que se puede contar de un intento sin muestra. Gasta cuota y guarda por URL.
func (s *Servidor) explicarURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, http.StatusMethodNotAllowed, "usa POST")
		return
	}
	url := strings.TrimSpace(r.URL.Query().Get("url"))
	if url == "" {
		responderError(w, http.StatusBadRequest, "falta la url")
		return
	}
	if len(url) > 2048 {
		url = url[:2048]
	}
	explicador, ok := s.Generador.(report.Explicador)
	if !ok {
		responderError(w, http.StatusBadRequest,
			"no hay ningun modelo configurado: revisa Ajustes -> Informes")
		return
	}
	ips, _ := strconv.Atoi(r.URL.Query().Get("ips"))
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
	texto, err := report.ExplicarURL(r.Context(), explicador, url, ips, idiomaDe(r), 2000)
	if err != nil {
		s.Almacen.DevolverCuotaLLM(dia)
		responderError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := s.Almacen.GuardarExplicacionDe("url", url, texto); err != nil {
		http.Error(w, "no se pudo guardar la explicacion", http.StatusInternalServerError)
		return
	}
	responderJSON(w, map[string]string{"explicacion": texto})
}

// reportarAbuse denuncia a AbuseIPDB las intrusiones recientes, para devolver
// al feed comunitario lo que el senuelo ha visto. Es una PUBLICACION externa:
// solo por POST y a peticion expresa del usuario, nunca automatica.
func (s *Servidor) reportarAbuse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, http.StatusMethodNotAllowed, "usa POST")
		return
	}
	if !mismoOrigen(r) {
		responderError(w, http.StatusForbidden, "origen no permitido")
		return
	}
	clave := s.Config.Actual().ClaveAbuseIPDB
	if clave == "" {
		responderError(w, http.StatusBadRequest, "no hay clave de AbuseIPDB configurada")
		return
	}
	ips, err := s.Almacen.IPsAtacantes(time.Now().AddDate(0, 0, -1), "intrusion")
	if err != nil {
		http.Error(w, "no se pudieron leer las IPs", http.StatusInternalServerError)
		return
	}
	if len(ips) > 40 {
		ips = ips[:40] // acotar por los limites de reporte de la API
	}
	cliente := &http.Client{Timeout: 10 * time.Second}
	reportadas := 0
	var ultimoErr string
	for _, ip := range ips {
		ctx, cancelar := context.WithTimeout(r.Context(), 12*time.Second)
		err := enrich.ReportarAbuseIPDB(ctx, cliente, clave, ip, "18,15,20",
			"Unauthorized access / intrusion against a honeypot (k0Pot).")
		cancelar()
		if err != nil {
			ultimoErr = err.Error()
			if strings.Contains(ultimoErr, "limite") {
				break
			}
			continue
		}
		reportadas++
	}
	responderJSON(w, map[string]any{"reportadas": reportadas, "total": len(ips), "error": ultimoErr})
}

// tocarURL dispara, en segundo plano, la explicacion de una URL de descarga
// sin fichero capturado cuando alguien la abre. No devuelve nada util: la
// explicacion aparece al reabrir, igual que en ataques y campanas.
func (s *Servidor) tocarURL(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, http.StatusMethodNotAllowed, "usa POST")
		return
	}
	url := strings.TrimSpace(r.URL.Query().Get("url"))
	if url == "" {
		responderError(w, http.StatusBadRequest, "falta la url")
		return
	}
	if len(url) > 2048 {
		url = url[:2048]
	}
	if ex, _ := s.Almacen.ExplicacionDe("url", url); ex != "" {
		responderJSON(w, map[string]any{"pendiente": false})
		return
	}
	pendiente := s.puedeExplicar()
	if pendiente {
		s.pedirExplicacion("url|" + url)
	}
	responderJSON(w, map[string]any{"pendiente": pendiente})
}
