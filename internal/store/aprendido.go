package store

import (
	"fmt"
	"strings"
	"time"
)

// glosas_aprendidas es el catalogo que k0pot APRENDE solo. Cuando la vista
// -explicar paso a paso- se topa con un comando que ni el catalogo fijo ni
// esta tabla conocen, se lo pregunta a la IA UNA vez y guarda aqui la
// respuesta. La proxima vez que aparezca -en este ataque o en otro- se sirve
// de aqui, gratis y al instante. Asi el conocimiento crece con lo que ve.
//
// La clave es el comando NORMALIZADO (sin IPs, URLs ni hashes concretos), de
// modo que "wget http://1.2.3.4/a" y "wget http://5.6.7.8/b" comparten glosa.
const esquemaAprendido = `
CREATE TABLE IF NOT EXISTS glosas_aprendidas (
    norm    TEXT NOT NULL,
    idioma  TEXT NOT NULL,
    glosa   TEXT NOT NULL,
    veces   INTEGER NOT NULL DEFAULT 1,
    creado  DATETIME NOT NULL,
    PRIMARY KEY (norm, idioma)
);`

// GlosaAprendida devuelve la explicacion guardada de un comando normalizado.
func (s *Store) GlosaAprendida(norm, idioma string) (string, bool) {
	var g string
	err := s.db.QueryRow(
		`SELECT glosa FROM glosas_aprendidas WHERE norm = ? AND idioma = ?`,
		norm, idioma).Scan(&g)
	if err != nil || g == "" {
		return "", false
	}
	return g, true
}

// GuardarGlosaAprendida anota lo que la IA explico de un comando nuevo. Si ya
// existia, la refresca y cuenta una aparicion mas.
func (s *Store) GuardarGlosaAprendida(norm, idioma, glosa string) error {
	_, err := s.db.Exec(
		`INSERT INTO glosas_aprendidas (norm, idioma, glosa, veces, creado)
		      VALUES (?, ?, ?, 1, ?)
		 ON CONFLICT(norm, idioma)
		 DO UPDATE SET glosa = excluded.glosa, veces = veces + 1`,
		norm, idioma, glosa, time.Now().UTC().Format(time.RFC3339Nano))
	return err
}

// ContarGlosasAprendidas es cuanto conocimiento lleva acumulado k0pot.
func (s *Store) ContarGlosasAprendidas() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM glosas_aprendidas`).Scan(&n)
	return n, err
}

// ComandoAgrupado es un comando distinto y cuantas veces se ha visto.
type ComandoAgrupado struct {
	Protocolo string
	Comando   string
	Veces     int
}

// ComandosRecientesAgrupados devuelve los comandos ejecutados desde una fecha,
// SIN repetir el texto exacto y con su recuento. Agrupar en SQL por el detalle
// evita traer a Go miles de copias identicas (un bot repite el mismo comando
// cientos de veces): asi el aprendiz en segundo plano procesa poco.
func (s *Store) ComandosRecientesAgrupados(desde time.Time) ([]ComandoAgrupado, error) {
	filas, err := s.db.Query(
		`SELECT protocolo, json_extract(detalle,'$.comando') AS cmd, COUNT(*)
		   FROM eventos
		  WHERE tipo = 'comando_ejecutado' AND timestamp >= ? AND cmd IS NOT NULL
		  GROUP BY protocolo, cmd`,
		desde.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("comandos agrupados: %w", err)
	}
	defer filas.Close()
	var out []ComandoAgrupado
	for filas.Next() {
		var c ComandoAgrupado
		if err := filas.Scan(&c.Protocolo, &c.Comando, &c.Veces); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, filas.Err()
}

// GlosasAprendidasDe busca de golpe las glosas de varias formas normalizadas.
// Es para pintar el detalle de un ataque: una sola consulta en vez de una por
// comando, que con cientos de pasos ahogaria la unica conexion de la BD.
func (s *Store) GlosasAprendidasDe(normas []string, idioma string) (map[string]string, error) {
	out := map[string]string{}
	if len(normas) == 0 {
		return out, nil
	}
	marcadores := make([]string, len(normas))
	args := make([]any, 0, len(normas)+1)
	for i, n := range normas {
		marcadores[i] = "?"
		args = append(args, n)
	}
	args = append(args, idioma)
	q := "SELECT norm, glosa FROM glosas_aprendidas WHERE norm IN (" +
		strings.Join(marcadores, ",") + ") AND idioma = ?"
	filas, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("glosas aprendidas de: %w", err)
	}
	defer filas.Close()
	for filas.Next() {
		var norm, glosa string
		if err := filas.Scan(&norm, &glosa); err != nil {
			return nil, err
		}
		out[norm] = glosa
	}
	return out, filas.Err()
}
