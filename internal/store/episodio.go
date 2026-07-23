package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/k0braintheworld/k0pot/internal/episodio"
	"github.com/k0braintheworld/k0pot/internal/model"
)

const esquemaEpisodio = `
-- Los episodios son datos DERIVADOS de eventos: se pueden reconstruir
-- enteros en cualquier momento. Por eso la clave es la del calculo y no un
-- autoincremento: rehacerlos actualiza en vez de duplicar.
CREATE TABLE IF NOT EXISTS episodios (
    clave           TEXT PRIMARY KEY,
    ip              TEXT     NOT NULL,
    protocolo       TEXT     NOT NULL,
    inicio          DATETIME NOT NULL,
    fin             DATETIME NOT NULL,
    eventos         INTEGER  NOT NULL,
    severidad       TEXT     NOT NULL,
    logins_fallidos INTEGER  NOT NULL,
    login_exitoso   INTEGER  NOT NULL,
    usuarios        TEXT     NOT NULL,
    passwords       TEXT     NOT NULL,
    comandos        TEXT     NOT NULL,
    rutas           TEXT     NOT NULL,
    descargas       TEXT     NOT NULL,
    motivos         TEXT     NOT NULL DEFAULT '[]',
    puerto          TEXT     NOT NULL DEFAULT '',
    solo_conexiones INTEGER  NOT NULL DEFAULT 0,
    avisado         TEXT     NOT NULL DEFAULT '',
    explicacion     TEXT     NOT NULL DEFAULT '',
    resumen         TEXT     NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_episodios_fin ON episodios (fin);
CREATE INDEX IF NOT EXISTS idx_episodios_ip  ON episodios (ip);
`

// EpisodioFila es un episodio tal y como sale de la base, con lo que se
// sabe de la IP ya incorporado para no consultarlo por separado.
type EpisodioFila struct {
	episodio.Episodio
	Pais       string `json:"pais"`
	ISP        string `json:"isp"`
	Reputacion int    `json:"reputacion"`
}

// EventosDesde devuelve los eventos a partir de una fecha, en orden
// cronologico, que es como los necesita la reconstruccion de episodios.
func (s *Store) EventosDesde(desde time.Time) ([]model.Evento, error) {
	filas, err := s.db.Query(
		`SELECT id, timestamp, COALESCE(protocolo,''), ip, tipo,
		        COALESCE(detalle,''), clasificacion, COALESCE(motivo,'')
		   FROM eventos WHERE timestamp >= ?
		  ORDER BY timestamp`, desde.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("leyendo eventos desde %s: %w", desde, err)
	}
	defer filas.Close()

	var out []model.Evento
	for filas.Next() {
		e, err := escanearEvento(filas)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, filas.Err()
}

// EventosDeEpisodio devuelve la secuencia completa de un episodio: es la
// narracion que se ensena al abrirlo.
func (s *Store) EventosDeEpisodio(ip, protocolo string, inicio, fin time.Time) ([]model.Evento, error) {
	filas, err := s.db.Query(
		`SELECT id, timestamp, COALESCE(protocolo,''), ip, tipo,
		        COALESCE(detalle,''), clasificacion, COALESCE(motivo,'')
		   FROM eventos
		  WHERE ip = ? AND protocolo = ? AND timestamp >= ? AND timestamp <= ?
		  ORDER BY timestamp`,
		ip, protocolo,
		inicio.UTC().Format(time.RFC3339Nano), fin.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("leyendo los eventos del episodio: %w", err)
	}
	defer filas.Close()

	out := []model.Evento{}
	for filas.Next() {
		e, err := escanearEvento(filas)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, filas.Err()
}

type escaneable interface {
	Scan(dest ...any) error
}

func escanearEvento(f escaneable) (model.Evento, error) {
	var e model.Evento
	var ts, tipo, detalle, clas string
	if err := f.Scan(&e.ID, &ts, &e.Protocolo, &e.IP, &tipo, &detalle, &clas,
		&e.Motivo); err != nil {
		return e, err
	}
	e.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
	e.Tipo = model.TipoEvento(tipo)
	e.Clasificacion = model.Clasificacion(clas)
	if detalle != "" {
		if err := json.Unmarshal([]byte(detalle), &e.Detalle); err != nil {
			return e, fmt.Errorf("detalle ilegible del evento %d: %w", e.ID, err)
		}
	}
	return e, nil
}

// GuardarEpisodios inserta o actualiza. Un episodio en curso se recalcula
// en cada pasada y crece; la clave estable hace que se actualice la misma
// fila en vez de acumular copias parciales del mismo ataque.
func (s *Store) GuardarEpisodios(es []episodio.Episodio) error {
	if len(es) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("abriendo transaccion de episodios: %w", err)
	}
	defer tx.Rollback()

	sent, err := tx.Prepare(
		`INSERT INTO episodios (clave, ip, protocolo, inicio, fin, eventos,
		     severidad, logins_fallidos, login_exitoso, usuarios, passwords,
		     comandos, rutas, descargas, motivos, puerto, solo_conexiones,
		     resumen)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(clave) DO UPDATE SET
		     fin = excluded.fin, eventos = excluded.eventos,
		     severidad = excluded.severidad,
		     logins_fallidos = excluded.logins_fallidos,
		     login_exitoso = excluded.login_exitoso,
		     usuarios = excluded.usuarios, passwords = excluded.passwords,
		     comandos = excluded.comandos, rutas = excluded.rutas,
		     descargas = excluded.descargas, motivos = excluded.motivos,
		     puerto = excluded.puerto, solo_conexiones = excluded.solo_conexiones,
		     resumen = excluded.resumen`)
	if err != nil {
		return fmt.Errorf("preparando la insercion de episodios: %w", err)
	}
	defer sent.Close()

	for _, e := range es {
		if _, err := sent.Exec(
			e.Clave, e.IP, e.Protocolo,
			e.Inicio.UTC().Format(time.RFC3339Nano),
			e.Fin.UTC().Format(time.RFC3339Nano),
			e.Eventos, string(e.Severidad), e.LoginsFallidos, e.LoginExitoso,
			listaJSON(e.Usuarios), listaJSON(e.Passwords), listaJSON(e.Comandos),
			listaJSON(e.Rutas), listaJSON(e.Descargas), listaJSON(e.Motivos),
			e.Puerto, e.SoloConexiones, e.Resumen,
		); err != nil {
			return fmt.Errorf("guardando el episodio %s: %w", e.Clave, err)
		}
	}
	return tx.Commit()
}

// Episodios devuelve los ataques del periodo, los mas graves primero.
func (s *Store) Episodios(desde time.Time, limite int) ([]EpisodioFila, error) {
	filas, err := s.db.Query(selectEpisodio+
		` WHERE e.fin >= ?
		  ORDER BY CASE e.severidad
		             WHEN 'intrusion' THEN 3 WHEN 'acceso' THEN 2
		             WHEN 'tanteo'    THEN 1 ELSE 0 END DESC,
		           e.fin DESC
		  LIMIT ?`, desde.UTC().Format(time.RFC3339Nano), limite)
	if err != nil {
		return nil, fmt.Errorf("consultando episodios: %w", err)
	}
	defer filas.Close()

	out := []EpisodioFila{}
	for filas.Next() {
		f, err := escanearEpisodio(filas)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, filas.Err()
}

// selectEpisodio es la proyeccion comun: el orden de las columnas y
// escanearEpisodio tienen que moverse juntos.
const selectEpisodio = `
	SELECT e.clave, e.ip, e.protocolo, e.inicio, e.fin, e.eventos,
	       e.severidad, e.logins_fallidos, e.login_exitoso,
	       e.usuarios, e.passwords, e.comandos, e.rutas, e.descargas,
	       e.motivos, e.puerto, e.solo_conexiones, e.resumen,
	       COALESCE(i.pais,''), COALESCE(i.isp,''), COALESCE(i.reputacion,0)
	  FROM episodios e
	  LEFT JOIN ips i ON i.ip = e.ip`

func escanearEpisodio(f escaneable) (EpisodioFila, error) {
	var e EpisodioFila
	var inicio, fin, sev string
	var usuarios, passwords, comandos, rutas, descargas, motivos string
	if err := f.Scan(
		&e.Clave, &e.IP, &e.Protocolo, &inicio, &fin, &e.Eventos,
		&sev, &e.LoginsFallidos, &e.LoginExitoso,
		&usuarios, &passwords, &comandos, &rutas, &descargas, &motivos,
		&e.Puerto, &e.SoloConexiones, &e.Resumen,
		&e.Pais, &e.ISP, &e.Reputacion,
	); err != nil {
		return e, err
	}
	e.Inicio, _ = time.Parse(time.RFC3339Nano, inicio)
	e.Fin, _ = time.Parse(time.RFC3339Nano, fin)
	e.Severidad = episodio.Severidad(sev)
	e.Usuarios = listaDeJSON(usuarios)
	e.Passwords = listaDeJSON(passwords)
	e.Comandos = listaDeJSON(comandos)
	e.Rutas = listaDeJSON(rutas)
	e.Descargas = listaDeJSON(descargas)
	e.Motivos = listaDeJSON(motivos)
	return e, nil
}

// EpisodioPorClave busca uno concreto, para poder abrirlo.
func (s *Store) EpisodioPorClave(clave string) (EpisodioFila, bool, error) {
	filas, err := s.db.Query(selectEpisodio+` WHERE e.clave = ?`, clave)
	if err != nil {
		return EpisodioFila{}, false, fmt.Errorf("buscando el episodio: %w", err)
	}
	defer filas.Close()
	if !filas.Next() {
		return EpisodioFila{}, false, filas.Err()
	}
	f, err := escanearEpisodio(filas)
	return f, err == nil, err
}

// PurgarEpisodios borra los anteriores a una fecha, igual que los eventos.
func (s *Store) PurgarEpisodios(antesDe time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM episodios WHERE fin < ?`,
		antesDe.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("purgando episodios: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

func listaJSON(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func listaDeJSON(s string) []string {
	if s == "" {
		return nil
	}
	var v []string
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil
	}
	return v
}

// NovedadesDesde dice hasta que ID hay eventos y cual es la fecha del mas
// antiguo posterior a ultimoID. Con eso basta para saber si hay trabajo y,
// si lo hay, desde donde hace falta releer.
func (s *Store) NovedadesDesde(ultimoID int64) (maxID int64, minNuevo time.Time, err error) {
	var max, min any
	err = s.db.QueryRow(
		`SELECT MAX(id), MIN(CASE WHEN id > ? THEN timestamp END) FROM eventos`,
		ultimoID).Scan(&max, &min)
	if err != nil {
		return ultimoID, time.Time{}, fmt.Errorf("buscando eventos nuevos: %w", err)
	}
	if max == nil {
		return 0, time.Time{}, nil // la tabla esta vacia
	}
	switch v := max.(type) {
	case int64:
		maxID = v
	default:
		return ultimoID, time.Time{}, fmt.Errorf("id maximo inesperado: %T", max)
	}
	if texto, ok := min.(string); ok {
		minNuevo, _ = time.Parse(time.RFC3339Nano, texto)
	}
	return maxID, minNuevo, nil
}

// rangoSeveridad ordena las severidades dentro de SQL. Tiene que coincidir
// con episodio.orden; si divergen, el panel y los avisos discreparian sobre
// que es mas grave.
const rangoSeveridad = `CASE %s WHEN 'intrusion' THEN 3 WHEN 'acceso' THEN 2
                                WHEN 'tanteo' THEN 1 ELSE 0 END`

// EpisodiosPorAvisar devuelve los ataques que alcanzan la severidad minima
// y de los que aun no se ha avisado.
//
// Se compara con la severidad ya avisada, no con un simple "avisado si o
// no": un ataque que empezo como acceso y acabo en intrusion merece un
// segundo aviso, porque la situacion ha cambiado. Uno que sigue igual, no.
func (s *Store) EpisodiosPorAvisar(minima string) ([]EpisodioFila, error) {
	consulta := fmt.Sprintf(selectEpisodio+`
		 WHERE %s >= %s
		   AND %s > %s
		 ORDER BY e.fin`,
		fmt.Sprintf(rangoSeveridad, "e.severidad"), fmt.Sprintf(rangoSeveridad, "?"),
		fmt.Sprintf(rangoSeveridad, "e.severidad"), fmt.Sprintf(rangoSeveridad, "e.avisado"))

	filas, err := s.db.Query(consulta, minima)
	if err != nil {
		return nil, fmt.Errorf("buscando ataques por avisar: %w", err)
	}
	defer filas.Close()

	out := []EpisodioFila{}
	for filas.Next() {
		e, err := escanearEpisodio(filas)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, filas.Err()
}

// MarcarAvisados deja constancia de con que severidad se aviso, para no
// repetir el mismo aviso en cada ciclo.
func (s *Store) MarcarAvisados(eps []EpisodioFila) error {
	if len(eps) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, e := range eps {
		if _, err := tx.Exec(`UPDATE episodios SET avisado = ? WHERE clave = ?`,
			string(e.Severidad), e.Clave); err != nil {
			return fmt.Errorf("marcando %s como avisado: %w", e.Clave, err)
		}
	}
	return tx.Commit()
}

// GuardarExplicacion asocia al ataque el texto que redacto el modelo.
//
// Se guarda para que reabrir el dialogo no vuelva a gastar cuota: la
// explicacion de un ataque terminado no cambia por volver a mirarla.
func (s *Store) GuardarExplicacion(clave, texto string) error {
	_, err := s.db.Exec(`UPDATE episodios SET explicacion = ? WHERE clave = ?`, texto, clave)
	if err != nil {
		return fmt.Errorf("guardando la explicacion: %w", err)
	}
	return nil
}

// Explicacion devuelve la que hubiera guardada.
func (s *Store) Explicacion(clave string) (string, error) {
	var texto string
	err := s.db.QueryRow(`SELECT explicacion FROM episodios WHERE clave = ?`, clave).Scan(&texto)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("leyendo la explicacion: %w", err)
	}
	return texto, nil
}
