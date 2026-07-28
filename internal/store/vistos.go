package store

import (
	"fmt"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// artefactos_vistos recuerda que ficheros ha ABIERTO ya el usuario, para que
// dejen de salir en "novedades / nunca vistos": una novedad deja de serlo en
// cuanto la miras.
const esquemaVistos = `
CREATE TABLE IF NOT EXISTS artefactos_vistos (
    sha   TEXT PRIMARY KEY,
    visto DATETIME NOT NULL
);`

// MarcarArtefactoVisto anota que el usuario ha abierto ese fichero.
func (s *Store) MarcarArtefactoVisto(sha string) error {
	_, err := s.db.Exec(
		`INSERT INTO artefactos_vistos (sha, visto) VALUES (?, ?)
		 ON CONFLICT(sha) DO NOTHING`,
		sha, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// ArtefactosNuevosSinVer es como ArtefactosNuevos pero descartando los que el
// usuario ya ha abierto: es lo que alimenta el radar de novedades.
func (s *Store) ArtefactosNuevosSinVer(desde time.Time) ([]ArtefactoNuevo, error) {
	filas, err := s.db.Query(
		`SELECT sha, primera, ips FROM (
		   SELECT json_extract(detalle,'$.sha256') AS sha,
		          MIN(timestamp) AS primera,
		          COUNT(DISTINCT ip) AS ips
		     FROM eventos
		    WHERE tipo = ? AND json_extract(detalle,'$.sha256') IS NOT NULL
		    GROUP BY sha
		 ) WHERE primera >= ?
		   AND sha NOT IN (SELECT sha FROM artefactos_vistos)
		 ORDER BY primera DESC`,
		string(model.DescargaFichero), desde.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("artefactos nuevos sin ver: %w", err)
	}
	defer filas.Close()
	var out []ArtefactoNuevo
	for filas.Next() {
		var a ArtefactoNuevo
		var ts string
		if err := filas.Scan(&a.SHA256, &ts, &a.IPs); err != nil {
			return nil, err
		}
		a.Primera, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, a)
	}
	return out, filas.Err()
}
