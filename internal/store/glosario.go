package store

import (
	"fmt"
	"time"
)

type GlosaListada struct {
	Norm   string `json:"norm"`
	Glosa  string `json:"glosa"`
	Veces  int    `json:"veces"`
	Creado string `json:"creado"`
}

func (s *Store) ListarGlosasAprendidas(idioma string) ([]GlosaListada, error) {
	filas, err := s.db.Query(
		`SELECT norm, glosa, veces, creado FROM glosas_aprendidas
		  WHERE idioma = ? ORDER BY veces DESC, norm`,
		idioma)
	if err != nil {
		return nil, fmt.Errorf("listar glosas: %w", err)
	}
	defer filas.Close()
	var out []GlosaListada
	for filas.Next() {
		var g GlosaListada
		if err := filas.Scan(&g.Norm, &g.Glosa, &g.Veces, &g.Creado); err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, filas.Err()
}

type TipoAtaqueConteo struct {
	Severidad string `json:"severidad"`
	Protocolo string `json:"protocolo"`
	Episodios int    `json:"episodios"`
	IPs       int    `json:"ips"`
	Ejemplo   string `json:"ejemplo"`
}

func (s *Store) ResumenTiposAtaque(desde time.Time) ([]TipoAtaqueConteo, error) {
	filas, err := s.db.Query(
		`SELECT severidad, protocolo, COUNT(*) AS n, COUNT(DISTINCT ip) AS nip,
		        (SELECT resumen FROM episodios e2
		          WHERE e2.severidad = e.severidad AND e2.protocolo = e.protocolo
		          ORDER BY e2.fin DESC LIMIT 1) AS ej
		   FROM episodios e
		  WHERE fin >= ?
		  GROUP BY severidad, protocolo
		  ORDER BY `+fmt.Sprintf(rangoSeveridad, "severidad")+` DESC, n DESC`,
		desde.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("tipos ataque: %w", err)
	}
	defer filas.Close()
	var out []TipoAtaqueConteo
	for filas.Next() {
		var t TipoAtaqueConteo
		if err := filas.Scan(&t.Severidad, &t.Protocolo, &t.Episodios, &t.IPs, &t.Ejemplo); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, filas.Err()
}
