package web

import (
	"net/http"
	"time"

	"github.com/k0braintheworld/k0pot/internal/episodio"
)

// Novedades es lo que ha pasado desde la ultima vez que el usuario miro.
//
// Sin esto el panel ensena siempre la misma lista y no hay forma de saber
// que es nuevo: se relee lo mismo cada vez y se acaba dejando de leer.
type Novedades struct {
	// Desde es el corte. El panel lo usa para marcar las filas nuevas, asi
	// que el criterio de "nuevo" es el mismo en el recuento y en la lista.
	Desde time.Time `json:"desde"`
	// Total y Graves separan "ha pasado algo" de "ha pasado algo que
	// importa": son preguntas distintas y merecen numeros distintos.
	Total  int `json:"total"`
	Graves int `json:"graves"`
	// PrimeraVez avisa de que aun no hay historial de revisiones, para que
	// el panel no anuncie novedades que en realidad son todo lo capturado.
	PrimeraVez bool `json:"primera_vez"`
}

func (s *Servidor) novedades(w http.ResponseWriter, r *http.Request) {
	u, ok := s.usuarioDe(r)
	if !ok {
		responderError(w, http.StatusUnauthorized, "sesion requerida")
		return
	}

	desde, err := s.Almacen.UltimaRevision(u.ID)
	if err != nil {
		http.Error(w, "no se pudo leer la ultima revision", http.StatusInternalServerError)
		return
	}
	porSeveridad, err := s.Almacen.EpisodiosDesde(desde)
	if err != nil {
		http.Error(w, "no se pudieron contar los ataques", http.StatusInternalServerError)
		return
	}

	n := Novedades{Desde: desde}
	for sev, c := range porSeveridad {
		n.Total += c
		if episodio.Rango(episodio.Severidad(sev)) >= episodio.Rango(episodio.Acceso) {
			n.Graves += c
		}
	}
	responderJSON(w, n)
}

// visto marca todo lo capturado hasta ahora como ya mirado.
//
// Es explicito y no automatico al cargar la pagina: si se marcara solo, el
// aviso desapareceria antes de que nadie lo leyera y el contador no
// serviria para nada.
func (s *Servidor) visto(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, http.StatusMethodNotAllowed, "usa POST")
		return
	}
	u, ok := s.usuarioDe(r)
	if !ok {
		responderError(w, http.StatusUnauthorized, "sesion requerida")
		return
	}
	ahora := time.Now()
	if err := s.Almacen.MarcarRevisado(u.ID, ahora); err != nil {
		http.Error(w, "no se pudo guardar", http.StatusInternalServerError)
		return
	}
	responderJSON(w, Novedades{Desde: ahora})
}
