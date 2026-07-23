package web

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/k0braintheworld/k0pot/internal/geoip"
)

// topeGeoIP acota el tamano de la subida. La GeoLite2-City ronda los 60 MB;
// 256 da margen de sobra sin dejar que una subida enorme llene el disco.
const topeGeoIP = 256 << 20

// subirGeoIP recibe el fichero .mmdb, lo valida y lo deja operativo.
//
// Existe para que no haya que teclear rutas ni tocar el servidor por SSH: se
// arrastra el fichero al panel y queda funcionando. Se valida ANTES de dar
// nada por bueno -que sea una base de ciudad de verdad- porque aceptar un
// fichero equivocado dejaria el mapa sin ciudades sin decir por que.
func (s *Servidor) subirGeoIP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, http.StatusMethodNotAllowed, "usa POST")
		return
	}
	if s.RutaBD == "" {
		responderError(w, http.StatusInternalServerError, "no se sabe donde guardar la base")
		return
	}
	dir := filepath.Dir(s.RutaBD)
	destino := filepath.Join(dir, "GeoLite2-City.mmdb")

	// A un temporal primero: si la subida se corta o el fichero no vale, la
	// base que ya hubiera no se toca. El nombre es fijo, nunca el que mande
	// el cliente, para que no pueda escribir fuera del directorio.
	tmp, err := os.CreateTemp(dir, "geoip-*.tmp")
	if err != nil {
		responderError(w, http.StatusInternalServerError, "no se pudo crear el fichero: "+err.Error())
		return
	}
	tmpNombre := tmp.Name()
	limpiar := true
	defer func() {
		if limpiar {
			os.Remove(tmpNombre)
		}
	}()

	// Se copia por streaming, sin cargar los 60 MB en memoria. El tope corta
	// una subida abusiva antes de llenar el disco.
	cuerpo := http.MaxBytesReader(w, r.Body, topeGeoIP)
	if _, err := io.Copy(tmp, cuerpo); err != nil {
		tmp.Close()
		responderError(w, http.StatusBadRequest, "fallo al recibir el fichero (¿supera los 256 MB?): "+err.Error())
		return
	}
	tmp.Close()

	tipo, err := geoip.Validar(tmpNombre)
	if err != nil {
		responderError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Rename atomico: en ningun instante hay un fichero a medias en su sitio.
	if err := os.Rename(tmpNombre, destino); err != nil {
		responderError(w, http.StatusInternalServerError, "no se pudo colocar la base: "+err.Error())
		return
	}
	limpiar = false
	if err := os.Chmod(destino, 0o640); err != nil {
		// No es critico; se registra y se sigue.
		fmt.Printf("aviso: no se pudieron ajustar permisos de %s: %v\n", destino, err)
	}

	// Se registra la ruta en la configuracion. El collector la recoge en su
	// proximo ciclo, recarga la base y sitúa las IP que ya tenia sin ubicar.
	c := s.Config.Actual()
	c.RutaGeoIP = destino
	if err := s.Config.Guardar(c); err != nil {
		responderError(w, http.StatusInternalServerError, "guardada la base pero no la ruta: "+err.Error())
		return
	}
	if s.AlCambiarConfig != nil {
		s.AlCambiarConfig(c)
	}

	responderJSON(w, map[string]any{
		"tipo":  tipo,
		"ruta":  destino,
		"aviso": "base cargada; el mapa empezara a situar por ciudad en unos segundos",
	})
}
