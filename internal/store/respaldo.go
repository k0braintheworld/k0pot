package store

import (
	"database/sql"
	"fmt"
	"strings"
)

// RespaldarEn escribe una copia consistente y compactada de la base en la ruta
// dada, en CALIENTE: no hace falta parar el collector.
//
// Usa VACUUM INTO desde una conexion PROPIA, no la del pool. En WAL ese lector
// ve una instantanea coherente mientras el collector sigue escribiendo, asi que
// el respaldo ni bloquea la ingesta ni sale a medias. El fichero destino no
// puede existir: VACUUM INTO se niega a sobrescribir, lo que evita pisar una
// copia buena por error.
func (s *Store) RespaldarEn(destino string) error {
	if s.ruta == "" {
		return fmt.Errorf("respaldo: no se conoce la ruta de la base")
	}
	origen, err := sql.Open("sqlite", s.ruta+"?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return fmt.Errorf("respaldo: abriendo la base: %w", err)
	}
	defer origen.Close()
	// El destino lo genera k0pot (ruta con marca de tiempo), no viene de fuera;
	// aun asi se escapan las comillas, porque VACUUM INTO no admite parametro y
	// hay que interpolar el literal.
	lit := strings.ReplaceAll(destino, "'", "''")
	if _, err := origen.Exec("VACUUM INTO '" + lit + "'"); err != nil {
		return fmt.Errorf("respaldo: copiando la base: %w", err)
	}
	return nil
}
