package web

import (
	"encoding/json"
	"net/http"

	"github.com/k0braintheworld/k0pot/internal/red"
)

// redEstado es lo que el panel necesita para pintar la pantalla de red.
type redEstado struct {
	Interfaces []red.Interfaz `json:"interfaces"`
	// Aplicable dice si el ayudante privilegiado esta instalado. Si no lo
	// esta, el panel deja editar y generar, pero no aplicar.
	Aplicable bool   `json:"aplicable"`
	YAML      string `json:"yaml"`
	Aviso     string `json:"aviso,omitempty"`
}

func (s *Servidor) red(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.redActual(w, r)
	case http.MethodPost:
		if !mismoOrigen(r) {
			responderError(w, http.StatusForbidden, "origen no permitido")
			return
		}
		s.redAplicar(w, r)
	default:
		responderError(w, http.StatusMethodNotAllowed, "usa GET o POST")
	}
}

func (s *Servidor) redActual(w http.ResponseWriter, r *http.Request) {
	ifaces, err := red.Listar(nil)
	if err != nil {
		responderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	estado := redEstado{Interfaces: ifaces, Aplicable: red.Disponible()}
	if estado.Aplicable {
		estado.YAML, _ = red.Actual(r.Context())
	} else {
		estado.Aviso = "El ayudante privilegiado no esta instalado: se puede " +
			"generar la configuracion, pero hay que aplicarla a mano. " +
			"Instrucciones en deploy/k0pot-red.sudoers."
	}
	responderJSON(w, estado)
}

type peticionRed struct {
	// Accion: "generar" (solo devuelve el YAML), "aplicar", "confirmar",
	// "revertir". Generar no toca nada del sistema.
	Accion     string       `json:"accion"`
	Interfaces []red.Config `json:"interfaces"`
}

func (s *Servidor) redAplicar(w http.ResponseWriter, r *http.Request) {
	var p peticionRed
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32*1024)).Decode(&p); err != nil {
		responderError(w, http.StatusBadRequest, "peticion ilegible")
		return
	}

	switch p.Accion {
	case "confirmar":
		salida, err := red.Confirmar(r.Context())
		responderAyudante(w, salida, err)
		return
	case "revertir":
		salida, err := red.Revertir(r.Context())
		responderAyudante(w, salida, err)
		return
	}

	yaml, err := red.GenerarYAML(p.Interfaces)
	if err != nil {
		responderError(w, http.StatusBadRequest, err.Error())
		return
	}

	if p.Accion == "generar" {
		responderJSON(w, map[string]any{"yaml": yaml, "aplicado": false})
		return
	}

	if !red.Disponible() {
		// Sin ayudante se devuelve el YAML igualmente: es util aunque haya
		// que copiarlo a mano.
		responderJSON(w, map[string]any{
			"yaml":     yaml,
			"aplicado": false,
			"aviso": "No se puede aplicar desde aqui: falta el ayudante privilegiado. " +
				"Copia este contenido a /etc/netplan/90-k0pot.yaml y ejecuta " +
				"sudo netplan apply.",
		})
		return
	}

	salida, err := red.Aplicar(r.Context(), yaml)
	if err != nil {
		responderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	responderJSON(w, map[string]any{
		"yaml": yaml, "aplicado": true, "salida": salida,
		"aviso": "Si has cambiado la IP por la que entras al panel, vuelve a " +
			"abrirlo en la nueva y confirma. Sin confirmar, la red se revierte sola.",
	})
}

func responderAyudante(w http.ResponseWriter, salida string, err error) {
	if err != nil {
		responderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	responderJSON(w, map[string]any{"salida": salida})
}
