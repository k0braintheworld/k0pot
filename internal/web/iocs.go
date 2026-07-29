package web

import (
	"crypto/sha1"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/episodio"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// Un IOC (indicador de compromiso) es un dato concreto y comprobable que
// delata un ataque: una IP, el hash de un fichero, una URL de malware. Es lo
// que k0pot puede APORTAR a la defensa de otras maquinas: se importa en un
// firewall, en un SIEM o en MISP y sirve para bloquear o cazar lo mismo en
// tu red real. Exportarlos convierte el honeypot en una fuente de inteligencia,
// no solo en un mirador.

// ioc es un indicador ya reunido y listo para volcar en cualquier formato.
type ioc struct {
	clase    string // "ipv4-addr" | "file" | "url"
	valor    string
	primera  time.Time
	ultima   time.Time
	pais     string
	isp      string
	reput    int
	tor      bool
	etiqueta string
}

// reunirIOCs junta las IPs que atacaron (con lo que ya sabemos de ellas por
// el enriquecimiento: pais, reputacion, si es salida Tor), los hashes de los
// ficheros capturados y las URLs desde donde se reparte el malware.
func (s *Servidor) reunirIOCs(desde time.Time) []ioc {
	eps, _ := s.Almacen.Episodios(store.FiltroEpisodios{Desde: desde, Limite: 2000})

	type agg struct {
		primera, ultima time.Time
		sev             episodio.Severidad
	}
	porIP := map[string]*agg{}
	urls := map[string]*ioc{}
	for _, e := range eps {
		a := porIP[e.IP]
		if a == nil {
			a = &agg{primera: e.Inicio, ultima: e.Fin, sev: e.Severidad}
			porIP[e.IP] = a
		}
		if !e.Inicio.IsZero() && e.Inicio.Before(a.primera) {
			a.primera = e.Inicio
		}
		if e.Fin.After(a.ultima) {
			a.ultima = e.Fin
		}
		a.sev = episodio.Peor(a.sev, e.Severidad)

		for _, u := range append(append([]string{}, e.Descargas...), urlsDeDescarga(e.Comandos)...) {
			if u == "" {
				continue
			}
			ic := urls[u]
			if ic == nil {
				ic = &ioc{clase: "url", valor: u, primera: e.Inicio, ultima: e.Fin,
					etiqueta: "URL desde la que se sirve malware"}
				urls[u] = ic
			}
			if e.Fin.After(ic.ultima) {
				ic.ultima = e.Fin
			}
		}
	}

	var out []ioc
	for ip, a := range porIP {
		// Solo lo que de verdad ataco: el ruido de fondo no es un IOC util.
		if episodio.Rango(a.sev) < episodio.Rango(episodio.Tanteo) {
			continue
		}
		ic := ioc{clase: "ipv4-addr", valor: ip, primera: a.primera, ultima: a.ultima,
			etiqueta: "atacante observado (" + string(a.sev) + ")"}
		if o, ok, _ := s.Almacen.OrigenDe(ip); ok {
			ic.pais, ic.isp, ic.reput, ic.tor = o.Pais, o.ISP, o.Reputacion, o.Tor
		}
		out = append(out, ic)
	}
	for _, ic := range urls {
		out = append(out, *ic)
	}
	// Callbacks de exploits: la infraestructura del propio atacante
	// (el C2 del Log4Shell, el host que sirve la segunda fase). Es el
	// indicador de mas valor que se puede exportar.
	if cbs, err := s.Almacen.CallbacksDesde(desde); err == nil {
		for _, cb := range cbs {
			et := "retrollamada de exploit (C2 o segunda fase)"
			if cb.Exploit != "" {
				et = cb.Exploit + " — C2/retrollamada capturada"
			}
			out = append(out, ioc{clase: "url", valor: cb.Destino,
				primera: cb.Primera, ultima: cb.Ultima, etiqueta: et})
		}
	}
	for _, f := range s.ficherosCapturados() {
		if f.Fichero == "" {
			continue
		}
		out = append(out, ioc{clase: "file", valor: f.Fichero, primera: f.Momento, ultima: f.Momento,
			etiqueta: fmt.Sprintf("fichero capturado (%d bytes)", f.Bytes)})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].clase != out[j].clase {
			return out[i].clase < out[j].clase
		}
		return out[i].valor < out[j].valor
	})
	return out
}

func (s *Servidor) iocs(w http.ResponseWriter, r *http.Request) {
	desde := time.Now().AddDate(0, 0, -dias(r))
	lista := s.reunirIOCs(desde)
	sello := time.Now().UTC().Format("20060102")
	if r.URL.Query().Get("formato") == "stix" {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf(`attachment; filename="k0pot-iocs-%s.json"`, sello))
		escribirSTIX(w, lista)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="k0pot-iocs-%s.csv"`, sello))
	escribirCSV(w, lista)
}

func iso(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func escribirCSV(w io.Writer, lista []ioc) {
	cw := csv.NewWriter(w)
	cw.Write([]string{"tipo", "indicador", "primera_vez", "ultima_vez",
		"pais", "isp", "reputacion", "tor", "descripcion"})
	for _, ic := range lista {
		tor := ""
		if ic.tor {
			tor = "si"
		}
		rep := ""
		if ic.clase == "ipv4-addr" {
			rep = strconv.Itoa(ic.reput)
		}
		cw.Write([]string{ic.clase, ic.valor, iso(ic.primera), iso(ic.ultima),
			ic.pais, ic.isp, rep, tor, ic.etiqueta})
	}
	cw.Flush()
}

// nsK0pot es un espacio de nombres fijo para generar identificadores STIX
// deterministas (UUIDv5): el mismo indicador exportado dos veces tiene
// siempre el mismo id, como pide el estandar para poder deduplicar.
var nsK0pot = [16]byte{0x6b, 0x30, 0x70, 0x6f, 0x74, 0x00, 0x11, 0x22,
	0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa}

func uuid5(nombre string) string {
	h := sha1.New()
	h.Write(nsK0pot[:])
	h.Write([]byte(nombre))
	b := h.Sum(nil)[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // variante RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// patronSTIX arma el patron de deteccion segun la clase del indicador.
func patronSTIX(ic ioc) string {
	v := strings.ReplaceAll(ic.valor, `'`, `\'`)
	switch ic.clase {
	case "ipv4-addr":
		return "[ipv4-addr:value = '" + v + "']"
	case "file":
		return "[file:hashes.'SHA-256' = '" + v + "']"
	case "url":
		return "[url:value = '" + v + "']"
	}
	return "[x-unknown:value = '" + v + "']"
}

// escribirSTIX vuelca un bundle STIX 2.1 con un objeto indicator por IOC,
// precedido de la identidad que los produjo. Es el formato que entienden
// MISP, OpenCTI y la mayoria de plataformas de inteligencia.
func escribirSTIX(w io.Writer, lista []ioc) {
	ahora := time.Now().UTC().Format("2006-01-02T15:04:05.000Z")
	identidad := map[string]any{
		"type":           "identity",
		"spec_version":   "2.1",
		"id":             "identity--" + uuid5("k0pot-identity"),
		"created":        ahora,
		"modified":       ahora,
		"name":           "k0Pot honeypot",
		"identity_class": "system",
	}
	objetos := []map[string]any{identidad}
	for _, ic := range lista {
		creado := ic.primera
		if creado.IsZero() {
			creado = ic.ultima
		}
		c := creado.UTC().Format("2006-01-02T15:04:05.000Z")
		m := ic.ultima
		if m.IsZero() {
			m = creado
		}
		ind := map[string]any{
			"type":            "indicator",
			"spec_version":    "2.1",
			"id":              "indicator--" + uuid5(ic.clase+"|"+ic.valor),
			"created_by_ref":  identidad["id"],
			"created":         c,
			"modified":        m.UTC().Format("2006-01-02T15:04:05.000Z"),
			"name":            ic.etiqueta,
			"indicator_types": []string{"malicious-activity"},
			"pattern":         patronSTIX(ic),
			"pattern_type":    "stix",
			"pattern_version": "2.1",
			"valid_from":      c,
		}
		etq := []string{}
		if ic.pais != "" {
			etq = append(etq, "country:"+ic.pais)
		}
		if ic.tor {
			etq = append(etq, "tor-exit-node")
		}
		if ic.reput > 0 {
			etq = append(etq, fmt.Sprintf("abuseipdb-score:%d", ic.reput))
		}
		if len(etq) > 0 {
			ind["labels"] = etq
		}
		objetos = append(objetos, ind)
	}
	bundle := map[string]any{
		"type":    "bundle",
		"id":      "bundle--" + uuid5("k0pot-bundle-"+ahora),
		"objects": objetos,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.Encode(bundle)
}
