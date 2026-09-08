package store

import (
	"database/sql"
	"fmt"
	"time"
)

// UltimoEventoEn devuelve la marca de tiempo del evento mas reciente. El bool
// es falso si la base no tiene ningun evento todavia -una instalacion recien
// puesta que aun no se ha expuesto-, para que el autochequeo NO confunda "aun
// no ha empezado" con "dejo de capturar".
func (s *Store) UltimoEventoEn() (time.Time, bool, error) {
	var ts sql.NullString
	if err := s.db.QueryRow(`SELECT MAX(timestamp) FROM eventos`).Scan(&ts); err != nil {
		return time.Time{}, false, fmt.Errorf("salud: ultimo evento: %w", err)
	}
	if !ts.Valid || ts.String == "" {
		return time.Time{}, false, nil
	}
	t, err := time.Parse(time.RFC3339Nano, ts.String)
	if err != nil {
		return time.Time{}, false, fmt.Errorf("salud: fecha del ultimo evento: %w", err)
	}
	return t, true, nil
}
