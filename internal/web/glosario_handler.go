package web

import (
	"net/http"
	"time"
)

func (s *Servidor) glosario(w http.ResponseWriter, r *http.Request) {
	idioma := idiomaDe(r)
	desde := time.Now().AddDate(0, 0, -dias(r))

	comandos, err := s.Almacen.ListarGlosasAprendidas(idioma)
	if err != nil {
		comandos = nil
	}

	ataques, err := s.Almacen.ResumenTiposAtaque(desde)
	if err != nil {
		ataques = nil
	}

	responderJSON(w, map[string]any{
		"comandos": comandos,
		"ataques":  ataques,
	})
}
