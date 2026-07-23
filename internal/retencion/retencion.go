// Package retencion decide que se conserva y que se tira.
//
// Un honeypot expuesto no para de escribir. Los eventos son lo que mas
// crece en numero, pero lo que ocupa de verdad son las grabaciones de
// sesion y los binarios que captura Cowrie: un evento son unos cientos de
// bytes, una grabacion puede ser megas.
//
// Se separan dos plazos a proposito:
//
//   - Los EVENTOS son el detalle. Caducan pronto: nadie consulta la linea
//     exacta de un escaneo de hace tres meses.
//   - Los EPISODIOS son el resumen y ocupan una fraccion. Conviene
//     conservarlos mucho mas, porque son los que responden "¿esta IP ya
//     habia venido?", y esa pregunta se hace justo con las que vuelven
//     despues de mucho tiempo.
//
// Tirar los dos con el mismo plazo es lo intuitivo y lo peor: se pierde la
// memoria larga para ahorrar lo que no ocupaba.
package retencion

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Politica son los plazos configurados. 0 significa conservar siempre.
type Politica struct {
	EventosDias   int
	EpisodiosDias int
	// DirCowrie es donde Cowrie deja grabaciones y descargas.
	DirCowrie string
}

// Almacen es lo que hace falta de la base de datos.
type Almacen interface {
	PurgarEventos(antesDe time.Time) (int64, error)
	PurgarEpisodios(antesDe time.Time) (int64, error)
}

// Resultado cuenta que se ha borrado, para poder decirlo en el log.
type Resultado struct {
	Eventos    int64
	Episodios  int64
	Ficheros   int
	BytesLibre int64
}

func (r Resultado) Vacio() bool {
	return r.Eventos == 0 && r.Episodios == 0 && r.Ficheros == 0
}

func (r Resultado) String() string {
	return fmt.Sprintf("%d eventos, %d ataques y %d ficheros (%s)",
		r.Eventos, r.Episodios, r.Ficheros, EnBytes(r.BytesLibre))
}

// Aplicar borra lo que ya ha caducado.
func Aplicar(alm Almacen, p Politica, ahora time.Time) (Resultado, error) {
	var r Resultado

	if p.EventosDias > 0 {
		corte := ahora.AddDate(0, 0, -p.EventosDias)
		n, err := alm.PurgarEventos(corte)
		if err != nil {
			return r, err
		}
		r.Eventos = n

		// Las grabaciones y descargas siguen la suerte de los eventos: son
		// el detalle de esas mismas sesiones y no se pueden interpretar sin
		// ellos.
		f, b, err := purgarFicheros(p.DirCowrie, corte)
		if err != nil {
			return r, err
		}
		r.Ficheros, r.BytesLibre = f, b
	}

	if p.EpisodiosDias > 0 {
		n, err := alm.PurgarEpisodios(ahora.AddDate(0, 0, -p.EpisodiosDias))
		if err != nil {
			return r, err
		}
		r.Episodios = n
	}
	return r, nil
}

// purgarFicheros borra las grabaciones y descargas anteriores al corte.
func purgarFicheros(dirCowrie string, corte time.Time) (int, int64, error) {
	if dirCowrie == "" {
		return 0, 0, nil
	}
	var n int
	var bytes int64

	for _, sub := range []string{"tty", "downloads"} {
		dir := filepath.Join(dirCowrie, sub)
		entradas, err := os.ReadDir(dir)
		if err != nil {
			// Que no exista es lo normal hasta que se captura algo.
			continue
		}
		for _, e := range entradas {
			if e.IsDir() {
				continue
			}
			info, err := e.Info()
			if err != nil || !info.ModTime().Before(corte) {
				continue
			}
			ruta := filepath.Join(dir, e.Name())
			if err := os.Remove(ruta); err != nil {
				return n, bytes, fmt.Errorf("borrando %s: %w", ruta, err)
			}
			n++
			bytes += info.Size()
		}
	}
	return n, bytes, nil
}

// Uso describe cuanto ocupa cada cosa, para poder elegir el plazo con datos
// en vez de a ojo.
type Uso struct {
	BaseDatos   int64 `json:"base_datos"`
	Grabaciones int64 `json:"grabaciones"`
	Descargas   int64 `json:"descargas"`
	Total       int64 `json:"total"`
	// Legible trae ya los tamanos escritos, para no repetir el formateo en
	// el navegador y que acaben divergiendo.
	Legible map[string]string `json:"legible"`
}

// Medir suma lo que ocupa cada parte.
func Medir(rutaBD, dirCowrie string) Uso {
	var u Uso
	// El -wal cuenta: puede ser mayor que la propia base y es espacio real
	// en disco, aunque no lo parezca al mirar solo el fichero principal.
	u.BaseDatos = tamano(rutaBD) + tamano(rutaBD+"-wal") + tamano(rutaBD+"-shm")
	if dirCowrie != "" {
		u.Grabaciones = tamanoDe(filepath.Join(dirCowrie, "tty"))
		u.Descargas = tamanoDe(filepath.Join(dirCowrie, "downloads"))
	}
	u.Total = u.BaseDatos + u.Grabaciones + u.Descargas
	u.Legible = map[string]string{
		"base_datos":  EnBytes(u.BaseDatos),
		"grabaciones": EnBytes(u.Grabaciones),
		"descargas":   EnBytes(u.Descargas),
		"total":       EnBytes(u.Total),
	}
	return u
}

func tamano(ruta string) int64 {
	info, err := os.Stat(ruta)
	if err != nil {
		return 0
	}
	return info.Size()
}

func tamanoDe(dir string) int64 {
	var total int64
	entradas, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	for _, e := range entradas {
		if info, err := e.Info(); err == nil && !e.IsDir() {
			total += info.Size()
		}
	}
	return total
}

// EnBytes escribe un tamano como lo leeria una persona.
func EnBytes(b int64) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%d B", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.0f KB", float64(b)/1024)
	case b < 1024*1024*1024:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	default:
		return fmt.Sprintf("%.1f GB", float64(b)/(1024*1024*1024))
	}
}
