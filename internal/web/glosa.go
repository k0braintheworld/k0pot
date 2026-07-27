package web

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/report"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// glosarEpisodio explica, con IA y frase a frase, cada paso del ataque. Es lo
// que vuelve el replay didactico: no solo desfilan los comandos, sino que al
// lado de cada uno aparece que hace y para que. El resultado se cachea (el
// ataque no cambia una vez pasado) y gasta la misma cuota diaria que el
// informe.
func (s *Servidor) glosarEpisodio(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, http.StatusMethodNotAllowed, "usa POST")
		return
	}
	clave := r.URL.Query().Get("clave")
	if clave == "" {
		responderError(w, http.StatusBadRequest, "falta la clave del ataque")
		return
	}
	idioma := idiomaDe(r)
	cacheKey := "glosa:" + clave + ":" + idioma

	ep, hay, err := s.Almacen.EpisodioPorClave(clave)
	if err != nil || !hay {
		responderError(w, http.StatusNotFound, "ese ataque no existe")
		return
	}
	eventos, err := s.Almacen.EventosDeEpisodio(ep.IP, ep.Protocolo, ep.Inicio, ep.Fin)
	if err != nil {
		http.Error(w, "no se pudo leer la secuencia", http.StatusInternalServerError)
		return
	}
	lineas := lineasDeAtaque(ep, eventos, idioma)
	if len(lineas) == 0 {
		responderJSON(w, map[string]any{"glosas": []string{}})
		return
	}

	// Cache: si ya se gloso este ataque en este idioma, se sirve tal cual.
	if cache, _ := s.Almacen.LeerEstado(cacheKey); cache != "" {
		var g []string
		if json.Unmarshal([]byte(cache), &g) == nil && len(g) == len(lineas) {
			responderJSON(w, map[string]any{"glosas": g})
			return
		}
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
		responderError(w, http.StatusTooManyRequests,
			"alcanzado el tope de peticiones con IA de hoy")
		return
	}

	glosas, err := report.GlosarComandos(r.Context(), explicador, lineas, idioma, 2500)
	if err != nil {
		s.Almacen.DevolverCuotaLLM(dia)
		responderError(w, http.StatusBadGateway, err.Error())
		return
	}
	if data, e := json.Marshal(glosas); e == nil {
		_ = s.Almacen.GuardarEstado(cacheKey, string(data))
	}
	responderJSON(w, map[string]any{"glosas": glosas})
}

// lineasDeAtaque reproduce, en el MISMO orden que la vista de detalle y el
// replay, la linea que se ve por paso: lo crudo si lo hay, y si no la
// narracion. Asi las glosas encajan indice a indice con los pasos del cliente.
func lineasDeAtaque(ep store.EpisodioFila, eventos []model.Evento, idioma string) []string {
	tr := func(es, en string) string {
		if idioma == "en" {
			return en
		}
		return es
	}
	var lineas []string
	if ep.SoloConexiones && len(eventos) > 0 {
		lineas = append(lineas, tr(
			"sondeo de puertos: abrieron la conexion y la cerraron sin enviar nada",
			"port scan: they opened the connection and closed it without sending anything"))
	}
	for _, ev := range eventos {
		if c := crudoDe(ev); c != "" {
			lineas = append(lineas, c)
			continue
		}
		texto, _ := narrar(ev, idioma)
		lineas = append(lineas, texto)
	}
	return lineas
}
