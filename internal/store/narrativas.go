package store

import (
	"time"

	"github.com/k0braintheworld/k0pot/internal/episodio"
)

// narrativas_aprendidas guarda la explicacion del ATAQUE ENTERO por su FIRMA:
// la forma normalizada de lo que hizo (protocolo + comandos + rutas, sin IPs
// ni hashes concretos). Como los bots repiten el mismo guion desde miles de
// IPs, dos ataques con la misma firma comparten narrativa: el primero la
// genera con IA y todos los demas la reutilizan gratis y al instante.
const esquemaNarrativas = `
CREATE TABLE IF NOT EXISTS narrativas_aprendidas (
    firma  TEXT NOT NULL,
    idioma TEXT NOT NULL,
    texto  TEXT NOT NULL,
    veces  INTEGER NOT NULL DEFAULT 1,
    creado DATETIME NOT NULL,
    PRIMARY KEY (firma, idioma)
);`

// NarrativaAprendida devuelve la explicacion guardada para una firma de ataque.
func (s *Store) NarrativaAprendida(firma, idioma string) (string, bool) {
	var t string
	err := s.db.QueryRow(
		`SELECT texto FROM narrativas_aprendidas WHERE firma = ? AND idioma = ?`,
		firma, idioma).Scan(&t)
	if err != nil || t == "" {
		return "", false
	}
	return t, true
}

// GuardarNarrativaAprendida anota la narrativa de una forma de ataque nueva.
func (s *Store) GuardarNarrativaAprendida(firma, idioma, texto string) error {
	_, err := s.db.Exec(
		`INSERT INTO narrativas_aprendidas (firma, idioma, texto, veces, creado)
		      VALUES (?, ?, ?, 1, ?)
		 ON CONFLICT(firma, idioma)
		 DO UPDATE SET texto = excluded.texto, veces = veces + 1`,
		firma, idioma, texto, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// EpisodioExplicado es un episodio con su narrativa ya redactada, con lo justo
// para calcular su firma y sembrar la memoria de narrativas.
type EpisodioExplicado struct {
	EpisodioFila
	Explicacion string
}

// EpisodiosExplicados devuelve los ataques que ya tienen narrativa, para
// sembrar con ellos la memoria por firma la primera vez.
func (s *Store) EpisodiosExplicados() ([]EpisodioExplicado, error) {
	filas, err := s.db.Query(
		`SELECT protocolo, severidad, login_exitoso, comandos, rutas, explicacion
		   FROM episodios WHERE explicacion <> ''`)
	if err != nil {
		return nil, err
	}
	defer filas.Close()
	var out []EpisodioExplicado
	for filas.Next() {
		var e EpisodioExplicado
		var sev, comandos, rutas string
		if err := filas.Scan(&e.Protocolo, &sev, &e.LoginExitoso, &comandos, &rutas, &e.Explicacion); err != nil {
			return nil, err
		}
		e.Severidad = episodio.Severidad(sev)
		e.Comandos = listaDeJSON(comandos)
		e.Rutas = listaDeJSON(rutas)
		out = append(out, e)
	}
	return out, filas.Err()
}
