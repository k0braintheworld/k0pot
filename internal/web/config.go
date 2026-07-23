package web

import (
	"encoding/json"
	"net"
	"net/http"

	"github.com/k0braintheworld/k0pot/internal/config"
)

// ajustes lee y escribe la configuracion.
//
// GET devuelve la vista publica, con las claves enmascaradas: el panel ve
// que hay clave y sus ultimos cuatro caracteres, nunca su valor.
func (s *Servidor) ajustes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		responderJSON(w, s.Config.Actual().ParaPanel())

	case http.MethodPost:
		if !mismoOrigen(r) {
			responderError(w, http.StatusForbidden, "origen no permitido")
			return
		}
		s.guardarAjustes(w, r)

	default:
		responderError(w, http.StatusMethodNotAllowed, "usa GET o POST")
	}
}

// entradaAjustes usa punteros para distinguir "no me lo mandaron" de "me
// mandaron el valor cero". Sin eso, no enviar un campo lo pondria a cero y
// dejar una clave vacia seria indistinguible de no querer tocarla.
type entradaAjustes struct {
	ReputacionAlta   *int                       `json:"reputacion_alta"`
	DenunciasAltas   *int                       `json:"denuncias_altas"`
	EnriquecerActivo *bool                      `json:"enriquecer_activo"`
	CaducidadIPDias  *int                       `json:"caducidad_ip_dias"`
	ReservaCuota     *int                       `json:"reserva_cuota"`
	UsarLLM          *bool                      `json:"usar_llm"`
	Proveedor        *string                    `json:"proveedor"`
	Modelo           *string                    `json:"modelo"`
	URLBase          *string                    `json:"url_base"`
	RefrescoSegundos *int                       `json:"refresco_segundos"`
	PaisPropio       *string                    `json:"pais_propio"`
	RetencionDias    *int                       `json:"retencion_dias"`
	EscuchaPanel     *string                    `json:"escucha_panel"`
	EscuchaHoneypots *string                    `json:"escucha_honeypots"`
	Servicios        map[string]config.Servicio `json:"servicios"`

	// Claves: cadena vacia o ausente = dejar la que hay. Para borrar una
	// clave existe el campo explicito de abajo.
	ClaveAbuseIPDB   *string `json:"clave_abuseipdb"`
	ClaveAnthropic   *string `json:"clave_anthropic"`
	ClaveCompatible  *string `json:"clave_compatible"`
	BorrarAbuseIPDB  bool    `json:"borrar_abuseipdb"`
	BorrarAnthropic  bool    `json:"borrar_anthropic"`
	BorrarCompatible bool    `json:"borrar_compatible"`
}

func (s *Servidor) guardarAjustes(w http.ResponseWriter, r *http.Request) {
	var e entradaAjustes
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16*1024)).Decode(&e); err != nil {
		responderError(w, http.StatusBadRequest, "peticion ilegible")
		return
	}

	c := s.Config.Actual()

	aplicarInt := func(destino *int, origen *int) {
		if origen != nil {
			*destino = *origen
		}
	}
	aplicarInt(&c.ReputacionAlta, e.ReputacionAlta)
	aplicarInt(&c.DenunciasAltas, e.DenunciasAltas)
	aplicarInt(&c.CaducidadIPDias, e.CaducidadIPDias)
	aplicarInt(&c.ReservaCuota, e.ReservaCuota)
	aplicarInt(&c.RefrescoSegundos, e.RefrescoSegundos)
	aplicarInt(&c.RetencionDias, e.RetencionDias)

	if e.EnriquecerActivo != nil {
		c.EnriquecerActivo = *e.EnriquecerActivo
	}
	if e.UsarLLM != nil {
		c.UsarLLM = *e.UsarLLM
	}
	if e.Proveedor != nil {
		c.Proveedor = *e.Proveedor
	}
	if e.Modelo != nil {
		c.Modelo = *e.Modelo
	}
	if e.URLBase != nil {
		c.URLBase = *e.URLBase
	}
	if e.PaisPropio != nil {
		c.PaisPropio = *e.PaisPropio
	}
	if e.EscuchaPanel != nil {
		c.EscuchaPanel = *e.EscuchaPanel
	}
	if e.EscuchaHoneypots != nil {
		c.EscuchaHoneypots = *e.EscuchaHoneypots
	}
	if e.Servicios != nil {
		c.Servicios = e.Servicios
	}

	// Una clave solo se toca si llega con contenido, o si se pide borrarla
	// explicitamente. Asi el panel puede reenviar el formulario entero con
	// el campo de clave vacio sin cargarse la que ya habia.
	if e.BorrarAbuseIPDB {
		c.ClaveAbuseIPDB = ""
	} else if e.ClaveAbuseIPDB != nil && *e.ClaveAbuseIPDB != "" {
		c.ClaveAbuseIPDB = *e.ClaveAbuseIPDB
	}
	if e.BorrarAnthropic {
		c.ClaveAnthropic = ""
	} else if e.ClaveAnthropic != nil && *e.ClaveAnthropic != "" {
		c.ClaveAnthropic = *e.ClaveAnthropic
	}
	if e.BorrarCompatible {
		c.ClaveCompatible = ""
	} else if e.ClaveCompatible != nil && *e.ClaveCompatible != "" {
		c.ClaveCompatible = *e.ClaveCompatible
	}

	if err := s.Config.Guardar(c); err != nil {
		responderError(w, http.StatusBadRequest, err.Error())
		return
	}

	// El generador de informes depende del modelo y de la clave, asi que
	// se reconstruye para que el cambio surta efecto sin reiniciar.
	if s.AlCambiarConfig != nil {
		s.AlCambiarConfig(c)
	}
	responderJSON(w, s.Config.Actual().ParaPanel())
}

// valoresPorDefecto deja al panel ofrecer un "restaurar".
func (s *Servidor) valoresPorDefecto(w http.ResponseWriter, r *http.Request) {
	responderJSON(w, config.PorDefecto().ParaPanel())
}

// servicios describe las trampas disponibles y su estado configurado.
//
// El panel necesita saber, ademas de si estan activas, en que puerto
// escuchan: es el dato que hace falta para redirigir el trafico desde fuera.
func (s *Servidor) servicios(w http.ResponseWriter, r *http.Request) {
	c := s.Config.Actual()

	tipo := struct {
		EscuchaHoneypots string          `json:"escucha_honeypots"`
		EscuchaPanel     string          `json:"escucha_panel"`
		Servicios        []servicioPanel `json:"servicios"`
		Interfaces       []interfazPanel `json:"interfaces"`
	}{
		EscuchaHoneypots: c.EscuchaHoneypots,
		EscuchaPanel:     c.EscuchaPanel,
		Interfaces:       interfacesDelSistema(),
	}

	for _, t := range s.Trampas {
		sv, hay := c.Servicios[t.ID()]
		if !hay {
			sv = config.Servicio{Puerto: t.PuertoPorDefecto()}
		}
		tipo.Servicios = append(tipo.Servicios, servicioPanel{
			ID: t.ID(), Nombre: t.Nombre(), Descripcion: t.Descripcion(),
			Puerto: sv.Puerto, PuertoPorDefecto: t.PuertoPorDefecto(),
			Activo: sv.Activo,
		})
	}
	responderJSON(w, tipo)
}

type servicioPanel struct {
	ID               string `json:"id"`
	Nombre           string `json:"nombre"`
	Descripcion      string `json:"descripcion"`
	Puerto           int    `json:"puerto"`
	PuertoPorDefecto int    `json:"puerto_por_defecto"`
	Activo           bool   `json:"activo"`
}

type interfazPanel struct {
	Nombre string `json:"nombre"`
	IP     string `json:"ip"`
}

// interfacesDelSistema lista las direcciones donde se puede escuchar, para
// que el panel las ofrezca en vez de obligar a teclearlas.
func interfacesDelSistema() []interfazPanel {
	out := []interfazPanel{{Nombre: "todas", IP: "0.0.0.0"}}

	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifa := range ifaces {
		if ifa.Flags&net.FlagUp == 0 || ifa.Flags&net.FlagLoopback != 0 {
			continue
		}
		dirs, err := ifa.Addrs()
		if err != nil {
			continue
		}
		for _, d := range dirs {
			ipnet, ok := d.(*net.IPNet)
			if !ok || ipnet.IP.To4() == nil {
				continue // IPv6 aparte, que complica mas de lo que aporta aqui
			}
			out = append(out, interfazPanel{Nombre: ifa.Name, IP: ipnet.IP.String()})
		}
	}
	return out
}
