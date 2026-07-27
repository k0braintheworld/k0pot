package store

import "time"

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
