package web

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"
)

// estadoSistema reune lo que hace falta para ver de un vistazo, sin SSH, que
// k0Pot se cuida solo: cuando fue la ultima copia y cuantas hay, cuanto disco
// queda, lo que ocupa la base y si sigue entrando actividad.
func (s *Servidor) estadoSistema(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}

	rutaBD := s.RutaBD
	if rutaBD == "" {
		rutaBD = "data/honey.db"
	}
	if fi, err := os.Stat(rutaBD); err == nil {
		out["bd_bytes"] = fi.Size()
	}

	dir := filepath.Dir(rutaBD)
	if libre, total, err := discoInfo(dir); err == nil {
		out["disco_libre"] = libre
		out["disco_total"] = total
	}

	copias, _ := filepath.Glob(filepath.Join(dir, "backups", "honey-*.db"))
	out["copias"] = len(copias)
	if len(copias) > 0 {
		sort.Strings(copias) // el nombre lleva la fecha: orden = cronologico
		if fi, err := os.Stat(copias[len(copias)-1]); err == nil {
			out["ultima_copia"] = fi.ModTime().UTC().Format(time.RFC3339)
		}
	}

	if t, hay, err := s.Almacen.UltimoEventoEn(); err == nil && hay {
		out["ultimo_evento"] = t.UTC().Format(time.RFC3339)
	}

	responderJSON(w, out)
}

// discoInfo son los bytes libres y totales de la particion de una ruta.
func discoInfo(ruta string) (libre, total uint64, err error) {
	var st syscall.Statfs_t
	if err = syscall.Statfs(ruta, &st); err != nil {
		return 0, 0, err
	}
	return st.Bavail * uint64(st.Bsize), st.Blocks * uint64(st.Bsize), nil
}
