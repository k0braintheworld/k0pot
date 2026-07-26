package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/campana"
	"github.com/k0braintheworld/k0pot/internal/report"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// contextoAsistente arma un resumen compacto de lo que ha visto el honeypot en
// los ultimos 7 dias, para dárselo al modelo como base de sus respuestas.
func (s *Servidor) contextoAsistente() string {
	desde := time.Now().AddDate(0, 0, -7)
	var b strings.Builder
	b.WriteString("Periodo: ultimos 7 dias.\n")
	if r, err := s.Almacen.Resumir(desde); err == nil {
		fmt.Fprintf(&b, "Eventos totales: %d. IPs distintas: %d.\n", r.Total, r.IPsUnicas)
		listar := func(titulo string, vs []store.Recuento, n int) {
			if len(vs) == 0 {
				return
			}
			b.WriteString(titulo + ": ")
			for i, v := range vs {
				if i == n {
					break
				}
				fmt.Fprintf(&b, "%s ", v.Valor)
			}
			b.WriteString("\n")
		}
		if len(r.PorPais) > 0 {
			b.WriteString("Paises con mas actividad: ")
			for i, p := range r.PorPais {
				if i == 6 {
					break
				}
				fmt.Fprintf(&b, "%s(%d) ", p.Valor, p.N)
			}
			b.WriteString("\n")
		}
		listar("Usuarios mas probados", r.TopUsuarios, 8)
		listar("Contrasenas mas probadas", r.TopPasswords, 8)
		if len(r.TopIPs) > 0 {
			b.WriteString("IPs mas activas: ")
			for i, ip := range r.TopIPs {
				if i == 6 {
					break
				}
				fmt.Fprintf(&b, "%s(%d ev) ", ip.IP, ip.Eventos)
			}
			b.WriteString("\n")
		}
	}
	if sev, err := s.Almacen.EpisodiosDesde(desde); err == nil {
		fmt.Fprintf(&b, "Ataques por gravedad: roce=%d, tanteo=%d, acceso=%d, intrusion=%d.\n",
			sev["roce"], sev["tanteo"], sev["acceso"], sev["intrusion"])
	}
	eps, _ := s.Almacen.Episodios(store.FiltroEpisodios{Desde: desde, Limite: 500})
	if campanas := campana.Detectar(eps); len(campanas) > 0 {
		b.WriteString("Campanas (grupos de ataques que comparten guion):\n")
		for i, c := range campanas {
			if i == 5 {
				break
			}
			m := []rune(c.Muestra)
			if len(m) > 120 {
				m = append(m[:120], '…')
			}
			fmt.Fprintf(&b, "  - %d IPs comparten: %s\n", len(c.IPs), string(m))
		}
	}
	if nuevos, err := s.Almacen.ArtefactosNuevos(desde); err == nil {
		fmt.Fprintf(&b, "Ficheros de malware capturados por primera vez: %d.\n", len(nuevos))
	}
	return b.String()
}

// asistente responde una pregunta en lenguaje natural sobre el honeypot. Va por
// POST (gasta cuota) y solo si esta activado en Ajustes.
func (s *Servidor) asistente(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, http.StatusMethodNotAllowed, "usa POST")
		return
	}
	if !mismoOrigen(r) {
		responderError(w, http.StatusForbidden, "origen no permitido")
		return
	}
	if !s.Config.Actual().AsistenteActivo {
		responderError(w, http.StatusForbidden, "el asistente esta desactivado; actívalo en Ajustes")
		return
	}
	explicador, ok := s.Generador.(report.Explicador)
	if !ok {
		responderError(w, http.StatusBadRequest,
			"no hay ningun modelo configurado: revisa Ajustes -> Informes")
		return
	}
	var e struct {
		Pregunta  string `json:"pregunta"`
		Historial string `json:"historial"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8*1024)).Decode(&e); err != nil {
		responderError(w, http.StatusBadRequest, "peticion ilegible")
		return
	}
	e.Pregunta = strings.TrimSpace(e.Pregunta)
	if e.Pregunta == "" {
		responderError(w, http.StatusBadRequest, "falta la pregunta")
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
	texto, err := report.Asistente(r.Context(), explicador,
		s.contextoAsistente(), e.Historial, e.Pregunta, idiomaDe(r), 1200)
	if err != nil {
		s.Almacen.DevolverCuotaLLM(dia)
		responderError(w, http.StatusBadGateway, err.Error())
		return
	}
	responderJSON(w, map[string]string{"respuesta": texto})
}
