package web

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/k0braintheworld/k0pot/internal/campana"
	"github.com/k0braintheworld/k0pot/internal/report"
	"github.com/k0braintheworld/k0pot/internal/saber"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// Las narrativas (la explicacion del ataque, la campana o el artefacto
// enteros) NO se generan al abrir: abrir nunca llama al modelo. Se cocinan en
// segundo plano -un barredor en el panel- y aparecen desde memoria. Lo que
// alguien abre y aun no tiene se pone en cabeza de la cola (explicacionesPedidas)
// para que salga en el siguiente barrido; mientras, el panel muestra
// "pendiente".
var explicacionesPedidas sync.Map // "tipo|clave" -> struct{}

// pedirExplicacion pone algo en cabeza de la cola del barredor.
func (s *Servidor) pedirExplicacion(tipoClave string) {
	explicacionesPedidas.Store(tipoClave, struct{}{})
}

// puedeExplicar dice si tiene sentido marcar algo como "pendiente": hay modelo
// y el aprendizaje automatico esta activo.
func (s *Servidor) puedeExplicar() bool {
	if !s.Config.Actual().AprendizajeAutomatico {
		return false
	}
	_, ok := s.Generador.(report.Explicador)
	return ok
}

// redactarExplicacionAtaque construye la narracion de pasos y pide al modelo la
// explicacion del ataque entero.
func (s *Servidor) redactarExplicacionAtaque(ctx context.Context, ex report.Explicador, ep store.EpisodioFila, idioma string) (string, error) {
	eventos, err := s.Almacen.EventosDeEpisodio(ep.IP, ep.Protocolo, ep.Inicio, ep.Fin)
	if err != nil {
		return "", err
	}
	pasos := make([]report.PasoDeAtaque, 0, len(eventos))
	for _, ev := range eventos {
		texto, _ := narrar(ev, idioma)
		p := report.PasoDeAtaque{Hora: ev.Timestamp.Local().Format("15:04:05"), Texto: texto}
		if n := notaDe(ev, idioma); n != nil {
			p.Nota = n.Que + ": " + n.Por
		}
		pasos = append(pasos, p)
	}
	var notaProv string
	if n, hay := saber.DeProveedor(ep.ISP); hay {
		n = n.En(idioma)
		notaProv = n.Que + ": " + n.Por
	}
	return report.ExplicarAtaque(ctx, ex, ep, pasos, notaProv, contextoCampana(s.Almacen, ep), idioma, 2000)
}

// BarrerExplicaciones es el bucle de fondo del panel: cada poco genera unas
// pocas narrativas que falten, empezando por lo que alguien acaba de abrir.
func (s *Servidor) BarrerExplicaciones(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(45 * time.Second):
		}
		s.generarNarrativasPendientes()
	}
}

func (s *Servidor) generarNarrativasPendientes() {
	c := s.Config.Actual()
	if !c.AprendizajeAutomatico {
		return
	}
	ex, ok := s.Generador.(report.Explicador)
	if !ok {
		return
	}
	idioma := c.Idioma
	if idioma == "" {
		idioma = "es"
	}
	dia := time.Now().Format("2006-01-02")
	topeFondo := c.InformeTopeDiario * 70 / 100 // reserva un 30% para lo que se pida
	if topeFondo < 1 {
		return
	}
	desde := time.Now().AddDate(0, 0, -7)

	hechas := 0
	const maxPorBarrido = 4
	// consumir intenta generar una narrativa. Devuelve false cuando ya no se
	// puede seguir: tope del barrido o presupuesto de fondo agotado.
	consumir := func(redactar func(context.Context, report.Explicador) (string, error), guardar func(string)) bool {
		if hechas >= maxPorBarrido {
			return false
		}
		if ok, _ := s.Almacen.ConsumirCuotaLLM(dia, topeFondo); !ok {
			return false
		}
		cctx, cancelar := context.WithTimeout(context.Background(), 120*time.Second)
		texto, err := redactar(cctx, ex)
		cancelar()
		if err != nil || texto == "" {
			s.Almacen.DevolverCuotaLLM(dia)
			return true // no cuenta, pero se sigue con otras
		}
		guardar(texto)
		hechas++
		time.Sleep(5 * time.Second) // espacia las llamadas para no reventar el TPM
		return true
	}

	generarUno := func(tipoClave string) bool {
		partes := strings.SplitN(tipoClave, "|", 2)
		if len(partes) != 2 {
			return true
		}
		clave := partes[1]
		switch partes[0] {
		case "ataque":
			ep, hay, _ := s.Almacen.EpisodioPorClave(clave)
			if !hay {
				return true
			}
			if ya, _ := s.Almacen.Explicacion(clave); ya != "" {
				return true
			}
			return consumir(
				func(ctx context.Context, ex report.Explicador) (string, error) {
					return s.redactarExplicacionAtaque(ctx, ex, ep, idioma)
				},
				func(t string) { _ = s.Almacen.GuardarExplicacion(clave, t) })
		case "campana":
			if ya, _ := s.Almacen.ExplicacionDe("campana", clave); ya != "" {
				return true
			}
			eps, _ := s.Almacen.Episodios(store.FiltroEpisodios{Desde: desde, Limite: 500})
			for _, cam := range campana.Detectar(eps) {
				if string(cam.Tipo)+"|"+cam.Huella != clave {
					continue
				}
				cam := cam
				return consumir(
					func(ctx context.Context, ex report.Explicador) (string, error) {
						return report.ExplicarCampana(ctx, ex, queComparten(cam.Tipo), cam.Muestra,
							len(cam.IPs), cam.Paises, string(cam.Severidad), idioma, 2000)
					},
					func(t string) { _ = s.Almacen.GuardarExplicacionDe("campana", clave, t) })
			}
			return true
		case "artefacto":
			if ya, _ := s.Almacen.ExplicacionDe("artefacto", clave); ya != "" {
				return true
			}
			det, ok := s.detalleArtefacto(clave)
			if !ok {
				return true
			}
			return consumir(
				func(ctx context.Context, ex report.Explicador) (string, error) {
					return report.ExplicarArtefacto(ctx, ex, det.Tipo, det.Bytes, det.Cadenas, det.URLs, idioma, 2000)
				},
				func(t string) { _ = s.Almacen.GuardarExplicacionDe("artefacto", det.SHA256, t) })
		case "url":
			if ya, _ := s.Almacen.ExplicacionDe("url", clave); ya != "" {
				return true
			}
			url := clave
			return consumir(
				func(ctx context.Context, ex report.Explicador) (string, error) {
					return report.ExplicarURL(ctx, ex, url, 0, idioma, 2000)
				},
				func(t string) { _ = s.Almacen.GuardarExplicacionDe("url", url, t) })
		}
		return true
	}

	// 1) Lo que alguien acaba de abrir (prioridad).
	explicacionesPedidas.Range(func(k, _ any) bool {
		explicacionesPedidas.Delete(k)
		return generarUno(k.(string))
	})

	// 2) Ataques notables recientes que aun no tienen narrativa.
	eps, _ := s.Almacen.EpisodiosNotablesSinExplicacion(desde, maxPorBarrido)
	for _, ep := range eps {
		ep := ep
		if ya, _ := s.Almacen.Explicacion(ep.Clave); ya != "" {
			continue
		}
		if !consumir(
			func(ctx context.Context, ex report.Explicador) (string, error) {
				return s.redactarExplicacionAtaque(ctx, ex, ep, idioma)
			},
			func(t string) { _ = s.Almacen.GuardarExplicacion(ep.Clave, t) }) {
			return
		}
	}
}

// explicacionEstado deja al cliente sondear si la narrativa que se cocina en
// segundo plano ya esta lista, para pintarla en el sitio sin reabrir.
func (s *Servidor) explicacionEstado(w http.ResponseWriter, r *http.Request) {
	tipo := strings.TrimSpace(r.URL.Query().Get("tipo"))
	clave := strings.TrimSpace(r.URL.Query().Get("clave"))
	if tipo == "" || clave == "" {
		responderError(w, http.StatusBadRequest, "faltan tipo y clave")
		return
	}
	var texto string
	if tipo == "ataque" {
		texto, _ = s.Almacen.Explicacion(clave)
	} else {
		texto, _ = s.Almacen.ExplicacionDe(tipo, clave)
	}
	responderJSON(w, map[string]any{"explicacion": texto})
}

// aprendizaje da el pulso para el indicador de la cabecera: cuantos comandos
// lleva aprendidos, la cuota de hoy y si el aprendizaje esta en pausa por
// haber agotado su presupuesto de fondo.
func (s *Servidor) aprendizaje(w http.ResponseWriter, r *http.Request) {
	total, _ := s.Almacen.ContarGlosasAprendidas()
	dia := time.Now().Format("2006-01-02")
	usadas, _ := s.Almacen.CuotaLLMUsada(dia)
	c := s.Config.Actual()
	_, hayModelo := s.Generador.(report.Explicador)
	activo := c.AprendizajeAutomatico && c.UsarLLM && hayModelo
	topeFondo := c.InformeTopeDiario * 70 / 100
	responderJSON(w, map[string]any{
		"total":   total,
		"hoy":     usadas,
		"tope":    c.InformeTopeDiario,
		"activo":  activo,
		"pausado": activo && usadas >= topeFondo,
	})
}
