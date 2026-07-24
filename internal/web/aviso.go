package web

import (
	"encoding/json"
	"net/http"

	"github.com/k0braintheworld/k0pot/internal/aviso"
)

// probarAviso manda una notificacion de ejemplo con la configuracion
// guardada.
//
// Existe porque la alternativa es esperar a que alguien ataque de verdad
// para descubrir que el token estaba mal. Un aviso que no llega el dia que
// hace falta no se distingue de no tener avisos.
func (s *Servidor) probarAviso(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, http.StatusMethodNotAllowed, "usa POST")
		return
	}
	c := s.Config.Actual()

	canal, err := aviso.De(aviso.Config{
		Canal: c.AvisoCanal, Destino: c.AvisoDestino,
		Clave: c.ClaveAviso, Servidor: c.AvisoServidor, Enlace: c.AvisoEnlace,
	}, nil)
	if err != nil {
		responderError(w, http.StatusBadRequest, err.Error())
		return
	}
	if canal == nil {
		responderError(w, http.StatusBadRequest,
			"no hay ningun canal configurado; guarda los ajustes primero")
		return
	}

	if err := canal.Enviar(r.Context(), aviso.DePrueba(c.AvisoEnlace, c.Idioma)); err != nil {
		// El motivo del servicio se publica tal cual: "chat not found"
		// dice donde mirar, "no se pudo enviar" no dice nada.
		responderError(w, http.StatusBadGateway, err.Error())
		return
	}
	responderJSON(w, map[string]string{"enviado": canal.Nombre()})
}


// fijarIdioma guarda el idioma elegido en el panel para que los avisos, que
// salen sin que nadie los mire, lleguen en ese mismo idioma.
func (s *Servidor) fijarIdioma(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, http.StatusMethodNotAllowed, "usa POST")
		return
	}
	if !mismoOrigen(r) {
		responderError(w, http.StatusForbidden, "origen no permitido")
		return
	}
	var e struct {
		Idioma string `json:"idioma"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024)).Decode(&e); err != nil {
		responderError(w, http.StatusBadRequest, "peticion ilegible")
		return
	}
	if e.Idioma != "es" && e.Idioma != "en" {
		responderError(w, http.StatusBadRequest, "idioma no valido")
		return
	}
	c := s.Config.Actual()
	c.Idioma = e.Idioma
	if err := s.Config.Guardar(c); err != nil {
		responderError(w, http.StatusInternalServerError, "no se pudo guardar el idioma")
		return
	}
	responderJSON(w, map[string]string{"idioma": e.Idioma})
}
