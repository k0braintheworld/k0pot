package web

import (
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/report"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// pasoGlosable es un paso del ataque visto por el glosador: su linea, si es un
// comando (lo unico que se aprende) y si el catalogo fijo ya lo explica.
type pasoGlosable struct {
	linea    string
	comando  bool
	conocido bool
}

// glosarEpisodio explica el ataque paso a paso con el MINIMO de IA posible.
// Para cada comando decide de donde sale la explicacion, en este orden:
//  1. el catalogo fijo (saber) -> ya se ve como nota, no gasta nada;
//  2. lo que k0pot aprendio antes (glosas_aprendidas) -> gratis y al instante;
//  3. la IA, solo para lo que nadie conocia -> y se GUARDA para no repetir.
//
// Asi, cuanto mas ve k0pot, menos necesita preguntar.
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
	pasos := pasosGlosables(ep, eventos, idioma)
	if len(pasos) == 0 {
		responderJSON(w, map[string]any{"glosas": []string{}})
		return
	}

	glosas := make([]string, len(pasos))
	// Se agrupan los comandos desconocidos por su forma NORMALIZADA: los bots
	// repiten el mismo guion decenas de veces, asi que un ataque de cientos de
	// pasos suele tener un punado de comandos distintos. Se pregunta a la IA
	// una vez por cada forma, no por cada aparicion.
	porForma := map[string][]int{} // forma -> indices de pasos que la comparten
	repr := map[string]string{}    // forma -> una linea representativa
	var formas []string            // orden estable de formas por preguntar
	for i, p := range pasos {
		if p.conocido || !p.comando {
			continue // el catalogo ya lo explica, o no es un comando
		}
		norm := normalizarComando(p.linea)
		if norm == "" {
			continue
		}
		if g, ok := s.Almacen.GlosaAprendida(norm, idioma); ok {
			glosas[i] = g
			continue
		}
		if _, visto := porForma[norm]; !visto {
			formas = append(formas, norm)
			repr[norm] = p.linea
		}
		porForma[norm] = append(porForma[norm], i)
	}

	aprendidas, pendientes := 0, 0
	if len(formas) > 0 {
		// Tope por peticion: si un ataque trae MUCHOS comandos distintos, se
		// aprende a tandas (una por clic) para no mandar un prompt gigante que
		// el modelo trunca. Lo que sobra queda pendiente y se coge al reabrir.
		const maxPorTanda = 25
		pendientesFormas := formas
		if len(formas) > maxPorTanda {
			pendientes += len(formas) - maxPorTanda
			pendientesFormas = formas[:maxPorTanda]
		}

		explicador, ok := s.Generador.(report.Explicador)
		if !ok {
			pendientes += len(pendientesFormas)
		} else {
			dia := time.Now().Format("2006-01-02")
			permitido, err := s.Almacen.ConsumirCuotaLLM(dia, s.Config.Actual().InformeTopeDiario)
			if err != nil {
				http.Error(w, "no se pudo comprobar la cuota", http.StatusInternalServerError)
				return
			}
			if !permitido {
				pendientes += len(pendientesFormas)
			} else {
				lineas := make([]string, len(pendientesFormas))
				for k, n := range pendientesFormas {
					lineas[k] = repr[n]
				}
				nuevas, e := report.GlosarComandos(r.Context(), explicador, lineas, idioma, 3000)
				if e != nil {
					s.Almacen.DevolverCuotaLLM(dia)
					pendientes += len(pendientesFormas)
				} else {
					for k, n := range pendientesFormas {
						g := strings.TrimSpace(nuevas[k])
						if g == "" {
							pendientes++
							continue
						}
						aprendidas++
						_ = s.Almacen.GuardarGlosaAprendida(n, idioma, g)
						for _, idx := range porForma[n] {
							glosas[idx] = g // se aplica a TODAS sus apariciones
						}
					}
				}
			}
		}
	}

	total, _ := s.Almacen.ContarGlosasAprendidas()
	responderJSON(w, map[string]any{
		"glosas":     glosas,
		"aprendidas": aprendidas,
		"pendientes": pendientes,
		"total":      total,
	})
}

// pasosGlosables reproduce, en el MISMO orden que el detalle y el cliente, la
// linea de cada paso, marcando si es un comando y si el catalogo ya lo explica.
func pasosGlosables(ep store.EpisodioFila, eventos []model.Evento, idioma string) []pasoGlosable {
	tr := func(es, en string) string {
		if idioma == "en" {
			return en
		}
		return es
	}
	var pasos []pasoGlosable
	if ep.SoloConexiones && len(eventos) > 0 {
		pasos = append(pasos, pasoGlosable{
			linea: tr("sondeo de puertos: abrieron la conexion y la cerraron sin enviar nada",
				"port scan: they opened the connection and closed it without sending anything"),
			comando: false, conocido: true,
		})
	}
	for _, ev := range eventos {
		crudo := crudoDe(ev)
		linea := crudo
		if linea == "" {
			linea, _ = narrar(ev, idioma)
		}
		pasos = append(pasos, pasoGlosable{
			linea: linea,
			// Solo se glosan COMANDOS de shell. Un login (usuario:clave), una
			// huella de cliente o una ruta HTTP tienen crudo, pero no son algo
			// que -ejecute- nada: ya los explica su nota o la narracion. Sin
			// esto, una fuerza bruta con cientos de intentos contaria cada
			// -ENTRA con user:pass- como un comando por explicar.
			comando:  ev.Tipo == model.ComandoEjecutado,
			conocido: notaDe(ev, idioma) != nil,
		})
	}
	return pasos
}

var (
	reGlosaURL = regexp.MustCompile(`[a-z]+://[^\s'"]+`)
	reGlosaIP  = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)
	reGlosaHex = regexp.MustCompile(`\b[0-9a-f]{8,}\b`)
	reGlosaNum = regexp.MustCompile(`\b\d{4,}\b`)
	reGlosaEsp = regexp.MustCompile(`\s+`)
)

// normalizarComando reduce un comando a su ESQUELETO: minusculas, sin las
// partes que cambian de una victima a otra (IPs, URLs, hashes, numeros
// largos) y con los espacios colapsados. Asi dos ordenes iguales salvo el
// servidor de descarga comparten una sola glosa aprendida.
func normalizarComando(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = reGlosaURL.ReplaceAllString(s, "<url>")
	s = reGlosaIP.ReplaceAllString(s, "<ip>")
	s = reGlosaHex.ReplaceAllString(s, "<hex>")
	s = reGlosaNum.ReplaceAllString(s, "<n>")
	s = reGlosaEsp.ReplaceAllString(s, " ")
	if len(s) > 400 {
		s = s[:400]
	}
	return s
}
