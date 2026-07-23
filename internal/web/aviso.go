package web

import (
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

	if err := canal.Enviar(r.Context(), aviso.DePrueba(c.AvisoEnlace)); err != nil {
		// El motivo del servicio se publica tal cual: "chat not found"
		// dice donde mirar, "no se pudo enviar" no dice nada.
		responderError(w, http.StatusBadGateway, err.Error())
		return
	}
	responderJSON(w, map[string]string{"enviado": canal.Nombre()})
}
