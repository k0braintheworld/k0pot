package store

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"time"
)

// glosasSemilla es el catalogo de comandos que k0pot ya trae APRENDIDO de
// fabrica: lo que otras instalaciones han explicado antes. Asi una instalacion
// nueva arranca sabiendo lo de siempre (Mirai, droppers, reconocimiento...) y
// no gasta IA en re-explicarlo.
//
//go:embed glosas_semilla.json
var glosasSemilla []byte

type glosaSemilla struct {
	Norm   string `json:"norm"`
	Idioma string `json:"idioma"`
	Glosa  string `json:"glosa"`
}

// sembrarGlosas precarga el catalogo de fabrica sin pisar NUNCA lo aprendido en
// local: ante conflicto gana la maquina, que conoce su modelo y su idioma. Es
// idempotente, asi que correrlo en cada arranque no hace dano.
func (s *Store) sembrarGlosas() error {
	if len(glosasSemilla) == 0 {
		return nil
	}
	var lista []glosaSemilla
	if err := json.Unmarshal(glosasSemilla, &lista); err != nil {
		return fmt.Errorf("semilla de glosas: %w", err)
	}
	if len(lista) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.Prepare(
		`INSERT INTO glosas_aprendidas (norm, idioma, glosa, veces, creado)
		      VALUES (?, ?, ?, 1, ?)
		 ON CONFLICT(norm, idioma) DO NOTHING`)
	if err != nil {
		return err
	}
	defer st.Close()
	ahora := time.Now().UTC().Format(time.RFC3339Nano)
	for _, g := range lista {
		if g.Norm == "" || g.Glosa == "" {
			continue
		}
		idioma := g.Idioma
		if idioma == "" {
			idioma = "es"
		}
		if _, err := st.Exec(g.Norm, idioma, g.Glosa, ahora); err != nil {
			return err
		}
	}
	return tx.Commit()
}
