package web

import (
	"context"
	"log"
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

// narrativaEnEspera frena el barredor tras un 429: el modelo gratis limita por
// tokens/dia, y una vez agotado no vale la pena reintentar cada 20 s. Solo la
// toca el barredor (una goroutine), asi que no necesita candado.
var narrativaEnEspera time.Time

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

// BarrerExplicaciones es el bucle de fondo del panel: genera UNA narrativa por
// tick, empezando por lo que alguien acaba de abrir. Una por tick a proposito:
// el modelo gratis limita por tokens/minuto, asi que ir en rafaga solo provoca
// errores 429; espaciando, cada explicacion sale y la que abres va primero.
func (s *Servidor) BarrerExplicaciones(ctx context.Context) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.generarUnaNarrativa(ctx)
		}
	}
}

func (s *Servidor) generarUnaNarrativa(ctx context.Context) {
	if time.Now().Before(narrativaEnEspera) {
		return // en pausa tras un 429; se reintenta cuando la ventana se libere
	}
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
	topeFondo := c.InformeTopeDiario * 70 / 100
	if topeFondo < 1 {
		return
	}
	desde := time.Now().AddDate(0, 0, -7)

	// Objetivo: primero lo que alguien acaba de abrir; si no, un ataque
	// notable reciente que aun no tenga narrativa.
	var objetivo string
	explicacionesPedidas.Range(func(k, _ any) bool {
		objetivo = k.(string)
		explicacionesPedidas.Delete(k)
		return false // uno por tick
	})
	if objetivo == "" {
		if eps, _ := s.Almacen.EpisodiosNotablesSinExplicacion(desde, 1); len(eps) > 0 {
			objetivo = "ataque|" + eps[0].Clave
		}
	}
	if objetivo == "" {
		return
	}

	partes := strings.SplitN(objetivo, "|", 2)
	if len(partes) != 2 {
		return
	}
	clave := partes[1]
	var redactar func(context.Context, report.Explicador) (string, error)
	var guardar func(string)
	switch partes[0] {
	case "ataque":
		ep, hay, _ := s.Almacen.EpisodioPorClave(clave)
		if !hay {
			return
		}
		if ya, _ := s.Almacen.Explicacion(clave); ya != "" {
			return
		}
		redactar = func(ctx context.Context, ex report.Explicador) (string, error) {
			return s.redactarExplicacionAtaque(ctx, ex, ep, idioma)
		}
		guardar = func(t string) { _ = s.Almacen.GuardarExplicacion(clave, t) }
	case "campana":
		if ya, _ := s.Almacen.ExplicacionDe("campana", clave); ya != "" {
			return
		}
		eps, _ := s.Almacen.Episodios(store.FiltroEpisodios{Desde: desde, Limite: 500})
		for _, cam := range campana.Detectar(eps) {
			if string(cam.Tipo)+"|"+cam.Huella != clave {
				continue
			}
			cam := cam
			redactar = func(ctx context.Context, ex report.Explicador) (string, error) {
				return report.ExplicarCampana(ctx, ex, queComparten(cam.Tipo), cam.Muestra,
					len(cam.IPs), cam.Paises, string(cam.Severidad), idioma, 2000)
			}
			guardar = func(t string) { _ = s.Almacen.GuardarExplicacionDe("campana", clave, t) }
			break
		}
	case "artefacto":
		if ya, _ := s.Almacen.ExplicacionDe("artefacto", clave); ya != "" {
			return
		}
		det, ok := s.detalleArtefacto(clave)
		if !ok {
			return
		}
		redactar = func(ctx context.Context, ex report.Explicador) (string, error) {
			return report.ExplicarArtefacto(ctx, ex, det.Tipo, det.Bytes, det.Cadenas, det.URLs, idioma, 2000)
		}
		guardar = func(t string) { _ = s.Almacen.GuardarExplicacionDe("artefacto", det.SHA256, t) }
	case "url":
		if ya, _ := s.Almacen.ExplicacionDe("url", clave); ya != "" {
			return
		}
		url := clave
		redactar = func(ctx context.Context, ex report.Explicador) (string, error) {
			return report.ExplicarURL(ctx, ex, url, 0, idioma, 2000)
		}
		guardar = func(t string) { _ = s.Almacen.GuardarExplicacionDe("url", url, t) }
	}
	if redactar == nil {
		return
	}
	if ok, _ := s.Almacen.ConsumirCuotaLLM(dia, topeFondo); !ok {
		return // presupuesto de fondo agotado hoy
	}
	// Marca "usando tokens ahora mismo", para que el indicador de la cabecera
	// muestre que esta aprendiendo mientras hay una llamada en vuelo.
	_ = s.Almacen.GuardarEstado("ia_activa_hasta", time.Now().Add(25*time.Second).UTC().Format(time.RFC3339))
	cctx, cancelar := context.WithTimeout(ctx, 90*time.Second)
	texto, err := redactar(cctx, ex)
	cancelar()
	if err != nil || texto == "" {
		s.Almacen.DevolverCuotaLLM(dia)
		if err != nil {
			if esLimiteDeRitmo(err) {
				narrativaEnEspera = time.Now().Add(5 * time.Minute)
				_ = s.Almacen.GuardarEstado("ia_pausa_hasta", narrativaEnEspera.UTC().Format(time.RFC3339))
				log.Printf("narrativa: limite del modelo alcanzado, pausa 5 min")
			} else {
				log.Printf("narrativa %s: %v", partes[0], err)
			}
		}
		return
	}
	guardar(texto)
	_ = s.Almacen.GuardarEstado("ia_pausa_hasta", "") // funciona: se rearma el aprendizaje
	log.Printf("narrativa %s generada", partes[0])
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
	sinTokens := false
	if v, _ := s.Almacen.LeerEstado("ia_pausa_hasta"); v != "" {
		if hasta, err := time.Parse(time.RFC3339, v); err == nil && time.Now().Before(hasta) {
			sinTokens = true
		}
	}
	generando := false
	if v, _ := s.Almacen.LeerEstado("ia_activa_hasta"); v != "" {
		if hasta, err := time.Parse(time.RFC3339, v); err == nil && time.Now().Before(hasta) {
			generando = true
		}
	}
	responderJSON(w, map[string]any{
		"total":      total,
		"hoy":        usadas,
		"tope":       c.InformeTopeDiario,
		"activo":     activo,
		"pausado":    activo && usadas >= topeFondo,
		"sin_tokens": activo && sinTokens,
		"generando":  activo && generando && !sinTokens,
	})
}

// esLimiteDeRitmo reconoce el 429 de -has gastado tu cuota de tokens- del
// proveedor, para pausar en vez de insistir.
func esLimiteDeRitmo(err error) bool {
	m := strings.ToLower(err.Error())
	return strings.Contains(m, "429") || strings.Contains(m, "rate limit") || strings.Contains(m, "too many requests")
}
