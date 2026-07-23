package web

import (
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/episodio"
	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/report"
	"github.com/k0braintheworld/k0pot/internal/store"
)

//go:embed reporte.html
var plantillaReporte string

// La plantilla usa html/template, NO text/template: todo lo que sale de aqui
// -comandos, rutas, user-agents- lo escriben atacantes, y el auto-escapado
// es lo que impide que un payload con <script> se convierta en HTML. Es la
// misma garantia que da el panel, aplicada al informe exportable.
var tplReporte = template.Must(template.New("reporte").Parse(plantillaReporte))

// reporte genera un informe HTML completo y autocontenido: resumen, veredicto,
// y cada ataque con su secuencia entera y los comandos tal y como se
// capturaron. Se abre en el navegador y desde ahi "Imprimir → Guardar PDF"
// produce el PDF, sin que k0Pot tenga que traer un generador de PDF propio.
func (s *Servidor) reporte(w http.ResponseWriter, r *http.Request) {
	d := dias(r)
	desde := time.Now().AddDate(0, 0, -d)

	resumen, err := s.Almacen.Resumir(desde)
	if err != nil {
		http.Error(w, "no se pudo leer el resumen", http.StatusInternalServerError)
		return
	}
	niveles, err := s.Almacen.PorClasificacion(desde)
	if err != nil {
		http.Error(w, "no se pudo leer la clasificacion", http.StatusInternalServerError)
		return
	}
	ataques, err := s.Almacen.Episodios(store.FiltroEpisodios{Desde: desde, Limite: 500})
	if err != nil {
		http.Error(w, "no se pudieron leer los ataques", http.StatusInternalServerError)
		return
	}

	// El texto del informe: siempre por reglas, para no gastar cuota ni
	// depender de la IA al exportar. Es el mismo resumen del panel.
	res, _ := report.PorReglas{}.Generar(r.Context(), report.Datos{
		Desde: desde, Hasta: time.Now(),
		Resumen: resumen, Niveles: niveles, Episodios: ataques,
	})

	modelo := datosReporte(desde, resumen, niveles, ataques, res.Texto, s.Almacen)

	// El informe es un documento AUTOCONTENIDO: el estilo va en linea para
	// que siga funcionando al guardarlo y abrirlo sin servidor. La CSP del
	// panel -style-src 'self'- bloquea el estilo en linea, asi que aqui se
	// pone una propia con un nonce por peticion: permite justo este bloque
	// de estilo y script, y nada mas. No se afloja a 'unsafe-inline': los
	// datos de atacante ya los escapa html/template, pero un nonce no deja
	// margen ni a un descuido futuro.
	nonce, err := nonceAleatorio()
	if err != nil {
		http.Error(w, "no se pudo generar el informe", http.StatusInternalServerError)
		return
	}
	modelo.Nonce = template.HTMLAttr(fmt.Sprintf(`nonce="%s"`, nonce))

	w.Header().Set("Content-Security-Policy", fmt.Sprintf(
		"default-src 'none'; style-src 'nonce-%s'; script-src 'nonce-%s'; img-src data:",
		nonce, nonce))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tplReporte.Execute(w, modelo); err != nil {
		fmt.Printf("reporte: %v\n", err)
	}
}

// nonceAleatorio devuelve un valor de un solo uso para la CSP del informe.
func nonceAleatorio() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ── Modelo de la plantilla ──────────────────────────────────────────────

type reporteVista struct {
	Nonce                   template.HTMLAttr
	Desde, Hasta, Generado  string
	Nivel                   string
	NivelClase              string
	Informe                 []string
	Total, IPsUnicas        int
	NumAtaques, Intrusiones int
	Ataques                 []ataqueVista
	TopIPs                  []filaIP
	Credenciales            []filaCred
}

type ataqueVista struct {
	IP, Origen, Severidad, SevClase, Resumen, Cuando string
	Pasos                                            []pasoVista
}

type pasoVista struct {
	Hora, Texto, Nota, Crudo string
	Clave                    bool
}

type filaIP struct {
	IP, Contexto string
	Eventos      int
}
type filaCred struct {
	Usuario, Password string
	Veces             int
}

func datosReporte(desde time.Time, r *store.Resumen, niveles map[model.Clasificacion]int,
	ataques []store.EpisodioFila, textoInforme string, alm *store.Store) reporteVista {

	nivel := report.NivelDe(niveles)
	v := reporteVista{
		Desde:      desde.Local().Format("02/01/2006 15:04"),
		Hasta:      time.Now().Local().Format("02/01/2006 15:04"),
		Generado:   time.Now().Local().Format("02/01/2006 15:04"),
		Nivel:      strings.ToUpper(string(nivel)),
		NivelClase: strings.ToLower(string(nivel)),
		Total:      r.Total,
		IPsUnicas:  r.IPsUnicas,
		NumAtaques: len(ataques),
	}
	for _, l := range strings.Split(textoInforme, "\n") {
		if s := strings.TrimSpace(l); s != "" {
			v.Informe = append(v.Informe, s)
		}
	}

	for _, e := range ataques {
		if e.Severidad == episodio.Intrusion {
			v.Intrusiones++
		}
		v.Ataques = append(v.Ataques, ataqueDeEpisodio(e, alm))
	}
	for _, ip := range r.TopIPs {
		v.TopIPs = append(v.TopIPs, filaIP{IP: ip.IP, Eventos: ip.Eventos, Contexto: contextoDeIP(ip)})
	}
	// Usuarios y contrasenas se emparejan en la vista por su recuento: no
	// tenemos el par exacto, pero listarlos juntos ya orienta.
	max := len(r.TopUsuarios)
	if len(r.TopPasswords) > max {
		max = len(r.TopPasswords)
	}
	for i := 0; i < max; i++ {
		var f filaCred
		if i < len(r.TopUsuarios) {
			f.Usuario, f.Veces = r.TopUsuarios[i].Valor, r.TopUsuarios[i].N
		}
		if i < len(r.TopPasswords) {
			f.Password = r.TopPasswords[i].Valor
		}
		v.Credenciales = append(v.Credenciales, f)
	}
	return v
}

func ataqueDeEpisodio(e store.EpisodioFila, alm *store.Store) ataqueVista {
	origen := e.IP
	partes := []string{}
	if e.Pais != "" {
		partes = append(partes, e.Pais)
	}
	if e.ISP != "" {
		partes = append(partes, e.ISP)
	}
	if e.Reputacion > 0 {
		partes = append(partes, fmt.Sprintf("reputacion %d/100", e.Reputacion))
	}
	origen = strings.Join(partes, " · ")

	a := ataqueVista{
		IP: e.IP, Origen: origen, Resumen: e.Resumen,
		Severidad: strings.ToUpper(string(e.Severidad)),
		SevClase:  string(e.Severidad),
		Cuando: fmt.Sprintf("%s · durante %s · %d eventos",
			e.Inicio.Local().Format("02/01 15:04"), duracion(e.Duracion()), e.Eventos),
	}

	eventos, err := alm.EventosDeEpisodio(e.IP, e.Protocolo, e.Inicio, e.Fin)
	if err != nil {
		return a
	}
	for _, ev := range eventos {
		texto, clave := narrar(ev)
		p := pasoVista{
			Hora: ev.Timestamp.Local().Format("15:04:05"), Texto: texto,
			Clave: clave, Crudo: crudoDe(ev),
		}
		if n := notaDe(ev); n != nil {
			p.Nota = n.Que + " — " + n.Por
		}
		// Si el crudo es identico al texto, no se repite.
		if strings.Contains(texto, p.Crudo) {
			p.Crudo = ""
		}
		a.Pasos = append(a.Pasos, p)
	}
	return a
}

func duracion(d time.Duration) string {
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%d s", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%d min", int(d.Minutes()))
	default:
		return fmt.Sprintf("%.1f h", d.Hours())
	}
}

func contextoDeIP(ip store.IPActiva) string {
	partes := []string{}
	if ip.ISP != "" {
		partes = append(partes, ip.ISP)
	}
	if ip.Reputacion > 0 {
		partes = append(partes, fmt.Sprintf("%d/100", ip.Reputacion))
	}
	if len(partes) == 0 {
		return "sin datos publicos"
	}
	return strings.Join(partes, " · ")
}
