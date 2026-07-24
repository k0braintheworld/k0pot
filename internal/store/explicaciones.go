package store

import (
	"database/sql"
	"fmt"
)

// esquemaExplicaciones guarda las explicaciones con IA de cosas que no son un
// episodio (un artefacto por su hash, una campana por su huella). Las de los
// ataques viven en la tabla episodios; esta es para todo lo demas, para no
// volver a gastar cuota al reabrir el mismo detalle.
const esquemaExplicaciones = `
CREATE TABLE IF NOT EXISTS explicaciones (
    tipo  TEXT NOT NULL,
    clave TEXT NOT NULL,
    texto TEXT NOT NULL,
    PRIMARY KEY (tipo, clave)
);`

// GuardarExplicacionDe guarda o reemplaza la explicacion de un artefacto o
// una campana.
func (s *Store) GuardarExplicacionDe(tipo, clave, texto string) error {
	_, err := s.db.Exec(
		`INSERT INTO explicaciones (tipo, clave, texto) VALUES (?,?,?)
		 ON CONFLICT(tipo, clave) DO UPDATE SET texto = excluded.texto`,
		tipo, clave, texto)
	if err != nil {
		return fmt.Errorf("guardando la explicacion: %w", err)
	}
	return nil
}

// ExplicacionDe devuelve la explicacion guardada, o "" si aun no hay.
func (s *Store) ExplicacionDe(tipo, clave string) (string, error) {
	var texto string
	err := s.db.QueryRow(
		`SELECT texto FROM explicaciones WHERE tipo = ? AND clave = ?`,
		tipo, clave).Scan(&texto)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("leyendo la explicacion: %w", err)
	}
	return texto, nil
}
