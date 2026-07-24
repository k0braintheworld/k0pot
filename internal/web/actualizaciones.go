package web

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// topeDeb acota la subida. Un .deb de k0Pot ronda los 6 MB; el margen es
// generoso pero atajado, para que nadie llene el disco subiendo basura.
const topeDeb = 100 << 20

// rutaActualizacion es donde queda el .deb subido, a la espera de que el
// administrador lo aplique con "sudo k0pot-actualizar". Va junto a la base de
// datos, el unico directorio donde el panel -sin privilegios- puede escribir.
func (s *Servidor) rutaActualizacion() string {
	return filepath.Join(filepath.Dir(s.RutaBD), "actualizacion.deb")
}

type estadoActualizacion struct {
	Version   string        `json:"version"`
	Comando   string        `json:"comando"`
	Pendiente *debPreparado `json:"pendiente,omitempty"`
}

type debPreparado struct {
	Bytes   int64     `json:"bytes"`
	Momento time.Time `json:"momento"`
}

// actualizacion informa de la version y de si hay un .deb preparado, acepta
// la subida de uno nuevo (POST) o descarta el pendiente (DELETE).
//
// Deliberadamente NO instala nada: el panel corre como un usuario sin
// privilegios, e instalar un .deb es ejecutar codigo como root. Que el panel
// pudiera hacerlo convertiria un acceso al panel en root del host. Por eso el
// panel solo deja el paquete preparado; instalarlo es un paso que da el
// administrador a mano, con su contrasena.
func (s *Servidor) actualizacion(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		est := estadoActualizacion{Version: s.Version, Comando: "sudo k0pot-actualizar"}
		if info, err := os.Stat(s.rutaActualizacion()); err == nil {
			est.Pendiente = &debPreparado{Bytes: info.Size(), Momento: info.ModTime()}
		}
		responderJSON(w, est)
	case http.MethodPost:
		s.subirActualizacion(w, r)
	case http.MethodDelete:
		if !mismoOrigen(r) {
			responderError(w, http.StatusForbidden, "origen no permitido")
			return
		}
		os.Remove(s.rutaActualizacion())
		responderJSON(w, map[string]bool{"ok": true})
	default:
		responderError(w, http.StatusMethodNotAllowed, "metodo no permitido")
	}
}

func (s *Servidor) subirActualizacion(w http.ResponseWriter, r *http.Request) {
	if !mismoOrigen(r) {
		responderError(w, http.StatusForbidden, "origen no permitido")
		return
	}
	dir := filepath.Dir(s.RutaBD)
	tmp, err := os.CreateTemp(dir, "actualizacion-*.tmp")
	if err != nil {
		http.Error(w, "no se pudo preparar la subida", http.StatusInternalServerError)
		return
	}
	tmpNombre := tmp.Name()
	limpiar := true
	defer func() {
		tmp.Close()
		if limpiar {
			os.Remove(tmpNombre)
		}
	}()

	// El cuerpo se escribe a disco por streaming, con tope: no se monta un
	// formulario en memoria ni se duplica el fichero.
	cuerpo := http.MaxBytesReader(w, r.Body, topeDeb)
	if _, err := io.Copy(tmp, cuerpo); err != nil {
		responderError(w, http.StatusRequestEntityTooLarge,
			"el fichero es demasiado grande o la subida fallo")
		return
	}
	if err := tmp.Close(); err != nil {
		http.Error(w, "no se pudo guardar la subida", http.StatusInternalServerError)
		return
	}
	if !esPaqueteDebian(tmpNombre) {
		responderError(w, http.StatusBadRequest, "eso no parece un paquete .deb")
		return
	}
	if err := os.Rename(tmpNombre, s.rutaActualizacion()); err != nil {
		http.Error(w, "no se pudo dejar la actualizacion preparada",
			http.StatusInternalServerError)
		return
	}
	limpiar = false
	os.Chmod(s.rutaActualizacion(), 0o640)

	var bytes int64
	if info, err := os.Stat(s.rutaActualizacion()); err == nil {
		bytes = info.Size()
	}
	responderJSON(w, map[string]any{
		"ok":      true,
		"bytes":   bytes,
		"comando": "sudo k0pot-actualizar",
	})
}

// esPaqueteDebian comprueba la firma de un .deb: es un archivo "ar" cuyo
// primer miembro es "debian-binary". No es una validacion fuerte -la de
// verdad la hace dpkg al instalarlo con sudo, que ademas confirma que es el
// paquete k0pot-; solo evita guardar algo que no sea un paquete.
func esPaqueteDebian(ruta string) bool {
	f, err := os.Open(ruta)
	if err != nil {
		return false
	}
	defer f.Close()
	cab := make([]byte, 68)
	n, _ := io.ReadFull(f, cab)
	texto := string(cab[:n])
	return strings.HasPrefix(texto, "!<arch>\n") && strings.Contains(texto, "debian-binary")
}
