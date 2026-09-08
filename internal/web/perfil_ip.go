package web

import (
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/k0braintheworld/k0pot/internal/episodio"
	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/saber"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// PerfilIP es todo lo que sabemos de una direccion.
//
// Existe para responder la pregunta que un ataque suelto no puede: ¿esta
// IP ya habia venido? Sin esto, una direccion que vuelve manana produce dos
// episodios sin relacion aparente, y lo que distingue a un escaner de paso
// de alguien que insiste es justamente eso.
type PerfilIP struct {
	IP     string       `json:"ip"`
	Origen model.Origen `json:"origen"`
	// NotaProveedor explica quien opera la direccion, cuando se sabe.
	NotaProveedor *saber.Nota `json:"nota_proveedor,omitempty"`

	Vista        time.Time `json:"vista"`
	UltimaVez    time.Time `json:"ultima_vez"`
	Episodios    int       `json:"episodios"`
	Eventos      int       `json:"eventos"`
	Servicios    []string  `json:"servicios"`
	PeorHasta    string    `json:"peor_hasta"`
	LlegoAEntrar bool      `json:"llego_a_entrar"`
	// Escalo dice si fue a mas con el tiempo: su primer episodio fue mas
	// leve que el ultimo. Es la diferencia entre insistir y progresar.
	Escalo bool `json:"escalo"`

	// Cruce con la inteligencia: lo que sabemos de ESTA direccion mas alla
	// de sus ataques sueltos. Es lo que convierte una lista en un retrato:
	// no solo -vino mucho-, sino -es de Mirai, mordio el cebo y quiso
	// tunelizar a este SMTP-.
	CeboMordido string   `json:"cebo_mordido,omitempty"`
	Familia     string   `json:"familia,omitempty"`
	Tuneles     []string `json:"tuneles,omitempty"`
	// DiasActivo son los dias DISTINTOS con actividad: distingue un
	// arreon de una tarde de alguien que vuelve un mes seguido.
	DiasActivo int `json:"dias_activo"`

	Ataques []store.EpisodioFila `json:"ataques"`
}

func (s *Servidor) perfilIP(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	idioma := idiomaDe(r)
	if net.ParseIP(ip) == nil {
		responderError(w, http.StatusBadRequest, "eso no es una direccion IP")
		return
	}

	// Sin recorte por fecha: la gracia de una ficha es ver todo lo que ha
	// hecho esa direccion, no solo lo del periodo que haya en pantalla.
	ataques, err := s.Almacen.Episodios(store.FiltroEpisodios{IP: ip, Limite: 500})
	if err != nil {
		http.Error(w, "no se pudieron leer sus ataques", http.StatusInternalServerError)
		return
	}
	for i := range ataques {
		ataques[i].Resumen = episodio.Redactar(ataques[i].Episodio, idioma)
	}
	origen, _, err := s.Almacen.OrigenDe(ip)
	if err != nil {
		http.Error(w, "no se pudo leer el contexto de la IP", http.StatusInternalServerError)
		return
	}

	p := PerfilIP{IP: ip, Origen: origen, Episodios: len(ataques), Ataques: ataques}
	if n, hay := saber.DeProveedor(origen.ISP); hay {
		nn := n.En(idioma)
		p.NotaProveedor = &nn
	}

	peor := episodio.Roce
	var comandos []string
	diasVistos := map[string]bool{}
	for i, e := range ataques {
		p.Eventos += e.Eventos
		if i == 0 || e.Inicio.Before(p.Vista) {
			p.Vista = e.Inicio
		}
		if e.Fin.After(p.UltimaVez) {
			p.UltimaVez = e.Fin
		}
		if !contiene(p.Servicios, e.Protocolo) {
			p.Servicios = append(p.Servicios, e.Protocolo)
		}
		peor = episodio.Peor(peor, e.Severidad)
		if e.LoginExitoso {
			p.LlegoAEntrar = true
		}
		comandos = append(comandos, e.Comandos...)
		// El cebo del episodio mas grave (los ataques vienen por severidad)
		// es el que mejor retrata a la direccion.
		if e.CeboMordido != "" && p.CeboMordido == "" {
			p.CeboMordido = e.CeboMordido
		}
		for _, dst := range e.Tuneles {
			if !contiene(p.Tuneles, dst) {
				p.Tuneles = append(p.Tuneles, dst)
			}
		}
		diasVistos[e.Inicio.UTC().Format("2006-01-02")] = true
	}
	sort.Strings(p.Servicios)
	sort.Strings(p.Tuneles)
	p.PeorHasta = string(peor)
	p.DiasActivo = len(diasVistos)
	// La familia se deduce de la firma de sus comandos, la misma que usa
	// el panel de botnets: asi la ficha y el agregado cuentan lo mismo.
	p.Familia = clasificarBotnet(comandos)

	// Escalo se mide comparando el primero en el tiempo con el peor: si el
	// primero fue lo mas grave, insistio; si lo peor vino despues, progreso.
	if len(ataques) > 1 {
		porFecha := append([]store.EpisodioFila(nil), ataques...)
		sort.Slice(porFecha, func(i, j int) bool { return porFecha[i].Inicio.Before(porFecha[j].Inicio) })
		p.Escalo = episodio.Rango(peor) > episodio.Rango(porFecha[0].Severidad)
	}

	responderJSON(w, p)
}
