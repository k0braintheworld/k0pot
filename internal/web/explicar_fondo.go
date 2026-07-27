package web

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/k0braintheworld/k0pot/internal/episodio"
	"github.com/k0braintheworld/k0pot/internal/report"
	"github.com/k0braintheworld/k0pot/internal/saber"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// generandoExplicacion evita que dos aperturas del mismo ataque disparen dos
// generaciones a la vez.
var generandoExplicacion sync.Map // clave -> struct{}

// redactarExplicacionAtaque construye la narracion de pasos y pide al modelo
// la explicacion del ataque entero. Es el nucleo comun de la generacion, se
// dispare a peticion o sola al abrir.
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
	contexto := contextoCampana(s.Almacen, ep)
	return report.ExplicarAtaque(ctx, ex, ep, pasos, notaProv, contexto, idioma, 2000)
}

// generarExplicacionEnFondo redacta y guarda la explicacion de un ataque sin
// que nadie la pida: se llama al ABRIR un ataque notable que aun no la tiene.
// Que alguien lo abra es la mejor senal de que merece gastar cuota en el; y al
// hacerlo en segundo plano, la proxima vez -o al recargar- ya aparece hecha,
// sin boton ni espera.
func (s *Servidor) generarExplicacionEnFondo(clave, idioma string, ep store.EpisodioFila) bool {
	c := s.Config.Actual()
	if !c.AprendizajeAutomatico {
		return false
	}
	ex, ok := s.Generador.(report.Explicador)
	if !ok {
		return false
	}
	// Solo lo que de verdad importa: donde entraron o actuaron. El ruido no
	// merece una llamada al modelo.
	if episodio.Rango(ep.Severidad) < episodio.Rango(episodio.Acceso) {
		return false
	}
	if _, yaVa := generandoExplicacion.LoadOrStore("ataque|"+clave, struct{}{}); yaVa {
		return true // ya se esta generando; el cliente puede esperarla igual
	}
	go func() {
		defer generandoExplicacion.Delete("ataque|" + clave)
		dia := time.Now().Format("2006-01-02")
		if ok, _ := s.Almacen.ConsumirCuotaLLM(dia, c.InformeTopeDiario); !ok {
			return
		}
		ctx, cancelar := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancelar()
		texto, err := s.redactarExplicacionAtaque(ctx, ex, ep, idioma)
		if err != nil || texto == "" {
			s.Almacen.DevolverCuotaLLM(dia)
			return
		}
		_ = s.Almacen.GuardarExplicacion(clave, texto)
	}()
	return true
}

// aprendizaje devuelve el pulso del conocimiento acumulado, para el indicador
// de la cabecera: cuantos comandos lleva aprendidos y como va la cuota de hoy.
func (s *Servidor) aprendizaje(w http.ResponseWriter, r *http.Request) {
	total, _ := s.Almacen.ContarGlosasAprendidas()
	dia := time.Now().Format("2006-01-02")
	usadas, _ := s.Almacen.CuotaLLMUsada(dia)
	c := s.Config.Actual()
	_, hayModelo := s.Generador.(report.Explicador)
	responderJSON(w, map[string]any{
		"total":  total,
		"hoy":    usadas,
		"tope":   c.InformeTopeDiario,
		"activo": c.AprendizajeAutomatico && c.UsarLLM && hayModelo,
	})
}

// generarExplicacionDeEnFondo es la version generica para el cache por
// (tipo,clave) -campanas, artefactos, URLs-. Igual que la del ataque: al abrir
// algo que aun no esta explicado, se redacta solo en segundo plano y queda
// guardado para la proxima vez. Sin boton ni espera.
func (s *Servidor) generarExplicacionDeEnFondo(tipo, clave string, redactar func(context.Context, report.Explicador) (string, error)) bool {
	c := s.Config.Actual()
	if !c.AprendizajeAutomatico {
		return false
	}
	ex, ok := s.Generador.(report.Explicador)
	if !ok {
		return false
	}
	llave := tipo + "|" + clave
	if _, yaVa := generandoExplicacion.LoadOrStore(llave, struct{}{}); yaVa {
		return true
	}
	go func() {
		defer generandoExplicacion.Delete(llave)
		dia := time.Now().Format("2006-01-02")
		if ok, _ := s.Almacen.ConsumirCuotaLLM(dia, c.InformeTopeDiario); !ok {
			return
		}
		ctx, cancelar := context.WithTimeout(context.Background(), 120*time.Second)
		defer cancelar()
		texto, err := redactar(ctx, ex)
		if err != nil || texto == "" {
			s.Almacen.DevolverCuotaLLM(dia)
			return
		}
		_ = s.Almacen.GuardarExplicacionDe(tipo, clave, texto)
	}()
	return true
}

// explicacionEstado deja al cliente sondear si la explicacion que se generaba
// en segundo plano ya esta lista, para pintarla en el sitio sin reabrir.
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
