// Package store persiste los eventos en SQLite.
//
// Se usa modernc.org/sqlite (SQLite reimplementado en Go puro) en vez del
// binding con CGO: asi honey sigue siendo un binario unico que compila y
// se despliega sin necesidad de toolchain de C en la maquina.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "modernc.org/sqlite"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// Store es el acceso a la base de datos.
type Store struct {
	db *sql.DB
}

// El enriquecimiento vive en su propia tabla, no repetido en cada evento:
// una IP que ataca 5.000 veces se consulta y se guarda una sola vez.
const esquema = `
CREATE TABLE IF NOT EXISTS eventos (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    -- identificador estable del evento en el log de origen. UNIQUE hace
    -- la ingesta idempotente: releer un log no duplica nada.
    id_externo    TEXT UNIQUE,
    timestamp     TEXT NOT NULL,
    honeypot      TEXT NOT NULL,
    protocolo     TEXT,
    sesion_id     TEXT,
    ip            TEXT NOT NULL,
    tipo          TEXT NOT NULL,
    detalle       TEXT,
    clasificacion TEXT NOT NULL,
    -- explicacion en lenguaje llano de por que se clasifico asi; los
    -- informes la publican tal cual.
    motivo        TEXT
);
CREATE INDEX IF NOT EXISTS idx_eventos_ts    ON eventos(timestamp);
CREATE INDEX IF NOT EXISTS idx_eventos_ip    ON eventos(ip);
CREATE INDEX IF NOT EXISTS idx_eventos_tipo  ON eventos(tipo);
CREATE INDEX IF NOT EXISTS idx_eventos_clasi ON eventos(clasificacion);

CREATE TABLE IF NOT EXISTS ips (
    ip             TEXT PRIMARY KEY,
    pais           TEXT,
    isp            TEXT,
    tipo_uso       TEXT,
    reputacion     INTEGER NOT NULL DEFAULT 0,
    total_reportes INTEGER NOT NULL DEFAULT 0,
    tor            INTEGER NOT NULL DEFAULT 0,
    ciudad         TEXT NOT NULL DEFAULT '',
    latitud        REAL NOT NULL DEFAULT 0,
    longitud       REAL NOT NULL DEFAULT 0,
    consultado_en  TEXT NOT NULL
);
`

// Abrir abre (y crea si hace falta) la base de datos en la ruta dada.
func Abrir(ruta string) (*Store, error) {
	// Los PRAGMA van en el DSN, no en un Exec posterior: ejecutados con
	// Exec solo afectan a la conexion del pool que atendio esa llamada, y
	// las demas se quedan sin busy_timeout. Eso es justo lo que provoca
	// "database is locked" en cuanto la ingesta y el enriquecimiento
	// escriben a la vez.
	//
	// WAL ademas permite que otro proceso (el resumen, o el futuro
	// dashboard) lea mientras el collector escribe.
	dsn := ruta + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("abriendo %s: %w", ruta, err)
	}

	// SQLite admite un solo escritor: serializar aqui evita ademas que
	// las goroutines de ingesta y enriquecimiento compitan entre si.
	db.SetMaxOpenConns(1)
	if err := migrar(db); err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db}, nil
}

// migrar deja el esquema al dia sin tirar lo ya capturado.
func migrar(db *sql.DB) error {
	if _, err := db.Exec(esquema); err != nil {
		return fmt.Errorf("creando esquema: %w", err)
	}
	if _, err := db.Exec(esquemaAuth); err != nil {
		return fmt.Errorf("creando esquema de auth: %w", err)
	}
	if _, err := db.Exec(esquemaInforme); err != nil {
		return fmt.Errorf("creando esquema de informes: %w", err)
	}
	if _, err := db.Exec(esquemaEpisodio); err != nil {
		return fmt.Errorf("creando esquema de episodios: %w", err)
	}
	if _, err := db.Exec(esquemaExplicaciones); err != nil {
		return fmt.Errorf("creando esquema de explicaciones: %w", err)
	}
	// Bases creadas antes de que los episodios guardaran el motivo del
	// clasificador.
	if err := anadirColumna(db, "episodios", "motivos", "TEXT NOT NULL DEFAULT '[]'"); err != nil {
		return err
	}
	if err := anadirColumna(db, "episodios", "puerto", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := anadirColumna(db, "episodios", "solo_conexiones", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := anadirColumna(db, "episodios", "avisado", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := anadirColumna(db, "usuarios", "ultima_revision", "TEXT"); err != nil {
		return err
	}
	if err := anadirColumna(db, "episodios", "explicacion", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	for _, col := range []struct{ nombre, tipo string }{
		{"ciudad", "TEXT NOT NULL DEFAULT ''"},
		{"latitud", "REAL NOT NULL DEFAULT 0"},
		{"longitud", "REAL NOT NULL DEFAULT 0"},
	} {
		if err := anadirColumna(db, "ips", col.nombre, col.tipo); err != nil {
			return err
		}
	}
	// Columnas que aparecieron despues de la primera version.
	if err := anadirColumna(db, "eventos", "motivo", "TEXT"); err != nil {
		return err
	}

	// Estas columnas vivian en eventos antes de que el enriquecimiento
	// tuviera tabla propia. Si quedan de una version anterior, sobran.
	for _, col := range []string{"pais", "asn", "reputacion"} {
		existe, err := tieneColumna(db, "eventos", col)
		if err != nil {
			return err
		}
		if existe {
			if _, err := db.Exec(`ALTER TABLE eventos DROP COLUMN ` + col); err != nil {
				return fmt.Errorf("retirando columna %s: %w", col, err)
			}
		}
	}
	return nil
}

func tieneColumna(db *sql.DB, tabla, columna string) (bool, error) {
	filas, err := db.Query(`SELECT name FROM pragma_table_info(?)`, tabla)
	if err != nil {
		return false, fmt.Errorf("inspeccionando %s: %w", tabla, err)
	}
	defer filas.Close()
	for filas.Next() {
		var n string
		if err := filas.Scan(&n); err != nil {
			return false, err
		}
		if n == columna {
			return true, nil
		}
	}
	return false, filas.Err()
}

// Cerrar libera la conexion.
func (s *Store) Cerrar() error { return s.db.Close() }

// Guardar inserta un evento. Devuelve false si ya estaba (mismo id
// externo), lo que permite reprocesar logs sin miedo a duplicar.
func (s *Store) Guardar(e *model.Evento) (bool, error) {
	var detalle any
	if len(e.Detalle) > 0 {
		b, err := json.Marshal(e.Detalle)
		if err != nil {
			return false, fmt.Errorf("serializando detalle: %w", err)
		}
		detalle = string(b)
	}

	// Un id externo vacio no puede colisionar por UNIQUE (SQLite permite
	// varios NULL), asi que lo dejamos nulo en vez de cadena vacia.
	var idExterno any
	if e.IDExterno != "" {
		idExterno = e.IDExterno
	}

	res, err := s.db.Exec(
		`INSERT OR IGNORE INTO eventos
		 (id_externo, timestamp, honeypot, protocolo, sesion_id,
		  ip, tipo, detalle, clasificacion, motivo)
		 VALUES (?,?,?,?,?,?,?,?,?,?)`,
		idExterno, e.Timestamp.UTC().Format(time.RFC3339Nano), e.Honeypot,
		e.Protocolo, e.SesionID, e.IP, string(e.Tipo), detalle,
		string(e.Clasificacion), e.Motivo,
	)
	if err != nil {
		return false, fmt.Errorf("insertando evento: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// GuardarOrigen almacena (o refresca) el enriquecimiento de una IP.
func (s *Store) GuardarOrigen(o model.Origen) error {
	cuando := o.ConsultadoEn
	if cuando.IsZero() {
		cuando = time.Now().UTC()
	}
	_, err := s.db.Exec(
		`INSERT INTO ips (ip, pais, isp, tipo_uso, reputacion,
		                  total_reportes, tor, ciudad, latitud, longitud, consultado_en)
		 VALUES (?,?,?,?,?,?,?,?,?,?,?)
		 ON CONFLICT(ip) DO UPDATE SET
		   pais=excluded.pais, isp=excluded.isp, tipo_uso=excluded.tipo_uso,
		   reputacion=excluded.reputacion, total_reportes=excluded.total_reportes,
		   tor=excluded.tor, ciudad=excluded.ciudad,
		   latitud=excluded.latitud, longitud=excluded.longitud,
		   consultado_en=excluded.consultado_en`,
		o.IP, o.Pais, o.ISP, o.TipoUso, o.Reputacion,
		o.TotalReportes, o.Tor, o.Ciudad, o.Latitud, o.Longitud,
		cuando.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("guardando origen de %s: %w", o.IP, err)
	}
	return nil
}

// IPsPendientes devuelve las IPs vistas en eventos que aun no se han
// enriquecido, o cuyo dato ya caduco. Se piden las mas activas primero:
// si la cuota diaria no da para todas, que se gaste en las que importan.
func (s *Store) IPsPendientes(caducidad time.Duration, limite int) ([]string, error) {
	corte := time.Now().UTC().Add(-caducidad).Format(time.RFC3339Nano)
	filas, err := s.db.Query(
		`SELECT e.ip, COUNT(*) n
		   FROM eventos e
		   LEFT JOIN ips i ON i.ip = e.ip
		  WHERE i.ip IS NULL OR i.consultado_en < ?
		  GROUP BY e.ip
		  ORDER BY n DESC
		  LIMIT ?`, corte, limite)
	if err != nil {
		return nil, fmt.Errorf("buscando ips pendientes: %w", err)
	}
	defer filas.Close()

	var ips []string
	for filas.Next() {
		var ip string
		var n int
		if err := filas.Scan(&ip, &n); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, filas.Err()
}

// Recuento es un valor con su numero de apariciones.
type Recuento struct {
	Valor string
	N     int
}

// IPActiva es una IP atacante con su contexto ya resuelto.
type IPActiva struct {
	model.Origen
	Eventos int
}

// Resumen son las cifras que alimentan el informe.
type Resumen struct {
	Total        int
	IPsUnicas    int
	PorTipo      []Recuento
	PorPais      []Recuento
	TopIPs       []IPActiva
	TopUsuarios  []Recuento
	TopPasswords []Recuento
	Primero      time.Time
	Ultimo       time.Time
}

// Resumir calcula el resumen de los eventos desde la fecha indicada.
func (s *Store) Resumir(desde time.Time) (*Resumen, error) {
	corte := desde.UTC().Format(time.RFC3339Nano)
	r := &Resumen{}

	err := s.db.QueryRow(
		`SELECT COUNT(*), COUNT(DISTINCT ip) FROM eventos WHERE timestamp >= ?`,
		corte).Scan(&r.Total, &r.IPsUnicas)
	if err != nil {
		return nil, fmt.Errorf("contando eventos: %w", err)
	}
	if r.Total == 0 {
		return r, nil
	}

	var primero, ultimo string
	if err := s.db.QueryRow(
		`SELECT MIN(timestamp), MAX(timestamp) FROM eventos WHERE timestamp >= ?`,
		corte).Scan(&primero, &ultimo); err != nil {
		return nil, fmt.Errorf("rango temporal: %w", err)
	}
	r.Primero, _ = time.Parse(time.RFC3339Nano, primero)
	r.Ultimo, _ = time.Parse(time.RFC3339Nano, ultimo)

	consultas := []struct {
		destino *[]Recuento
		sql     string
	}{
		{&r.PorTipo, `SELECT tipo, COUNT(*) n FROM eventos
		              WHERE timestamp >= ? GROUP BY tipo ORDER BY n DESC`},
		{&r.PorPais, `SELECT i.pais, COUNT(*) n FROM eventos e
		              JOIN ips i ON i.ip = e.ip
		              WHERE e.timestamp >= ? AND i.pais <> ''
		              GROUP BY i.pais ORDER BY n DESC LIMIT 30`},
		{&r.TopUsuarios, `SELECT json_extract(detalle,'$.usuario') u, COUNT(*) n
		                  FROM eventos WHERE timestamp >= ? AND u IS NOT NULL
		                  GROUP BY u ORDER BY n DESC LIMIT 30`},
		{&r.TopPasswords, `SELECT json_extract(detalle,'$.password') p, COUNT(*) n
		                   FROM eventos WHERE timestamp >= ? AND p IS NOT NULL
		                   GROUP BY p ORDER BY n DESC LIMIT 30`},
	}
	for _, c := range consultas {
		rec, err := s.recuentos(c.sql, corte)
		if err != nil {
			return nil, err
		}
		*c.destino = rec
	}

	r.TopIPs, err = s.topIPs(corte)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) topIPs(corte string) ([]IPActiva, error) {
	filas, err := s.db.Query(
		`SELECT e.ip, COUNT(*) n,
		        COALESCE(i.pais,''), COALESCE(i.isp,''), COALESCE(i.tipo_uso,''),
		        COALESCE(i.reputacion,0), COALESCE(i.total_reportes,0),
		        COALESCE(i.tor,0), i.ip IS NOT NULL
		   FROM eventos e
		   LEFT JOIN ips i ON i.ip = e.ip
		  WHERE e.timestamp >= ?
		  GROUP BY e.ip ORDER BY n DESC LIMIT 30`, corte)
	if err != nil {
		return nil, fmt.Errorf("consultando ips activas: %w", err)
	}
	defer filas.Close()

	var out []IPActiva
	for filas.Next() {
		var a IPActiva
		if err := filas.Scan(&a.IP, &a.Eventos, &a.Pais, &a.ISP, &a.TipoUso,
			&a.Reputacion, &a.TotalReportes, &a.Tor, &a.Enriquecido); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, filas.Err()
}

func (s *Store) recuentos(consulta, corte string) ([]Recuento, error) {
	filas, err := s.db.Query(consulta, corte)
	if err != nil {
		return nil, fmt.Errorf("consultando recuentos: %w", err)
	}
	defer filas.Close()

	var out []Recuento
	for filas.Next() {
		var c Recuento
		if err := filas.Scan(&c.Valor, &c.N); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, filas.Err()
}

// anadirColumna agrega una columna si aun no existe, para que una base de
// datos creada por una version anterior siga sirviendo.
func anadirColumna(db *sql.DB, tabla, columna, tipo string) error {
	existe, err := tieneColumna(db, tabla, columna)
	if err != nil || existe {
		return err
	}
	if _, err := db.Exec(`ALTER TABLE ` + tabla + ` ADD COLUMN ` + columna + ` ` + tipo); err != nil {
		return fmt.Errorf("anadiendo columna %s.%s: %w", tabla, columna, err)
	}
	return nil
}

// OrigenDe devuelve el contexto conocido de una IP. El booleano indica si
// llego a consultarse alguna vez.
func (s *Store) OrigenDe(ip string) (model.Origen, bool, error) {
	var o model.Origen
	var consultado string
	err := s.db.QueryRow(
		`SELECT ip, COALESCE(pais,''), COALESCE(isp,''), COALESCE(tipo_uso,''),
		        reputacion, total_reportes, tor,
		        COALESCE(ciudad,''), COALESCE(latitud,0), COALESCE(longitud,0),
		        consultado_en
		   FROM ips WHERE ip = ?`, ip).
		Scan(&o.IP, &o.Pais, &o.ISP, &o.TipoUso, &o.Reputacion,
			&o.TotalReportes, &o.Tor, &o.Ciudad, &o.Latitud, &o.Longitud, &consultado)
	if errors.Is(err, sql.ErrNoRows) {
		return model.Origen{IP: ip}, false, nil
	}
	if err != nil {
		return o, false, fmt.Errorf("leyendo origen de %s: %w", ip, err)
	}
	o.Enriquecido = true
	o.ConsultadoEn, _ = time.Parse(time.RFC3339Nano, consultado)
	return o, true, nil
}

// EventosDeIP devuelve los eventos de una IP, con lo justo para poder
// reclasificarlos.
func (s *Store) EventosDeIP(ip string) ([]model.Evento, error) {
	filas, err := s.db.Query(
		`SELECT id, tipo, COALESCE(detalle,''), clasificacion
		   FROM eventos WHERE ip = ?`, ip)
	if err != nil {
		return nil, fmt.Errorf("leyendo eventos de %s: %w", ip, err)
	}
	defer filas.Close()

	var out []model.Evento
	for filas.Next() {
		var e model.Evento
		var tipo, detalle, clas string
		if err := filas.Scan(&e.ID, &tipo, &detalle, &clas); err != nil {
			return nil, err
		}
		e.IP = ip
		e.Tipo = model.TipoEvento(tipo)
		e.Clasificacion = model.Clasificacion(clas)
		if detalle != "" {
			if err := json.Unmarshal([]byte(detalle), &e.Detalle); err != nil {
				return nil, fmt.Errorf("detalle ilegible del evento %d: %w", e.ID, err)
			}
		}
		out = append(out, e)
	}
	return out, filas.Err()
}

// Reclasificar actualiza el veredicto de un evento ya guardado. Hace falta
// porque el enriquecimiento llega despues de la ingesta: cuando sabemos
// quien esta detras de una IP, sus eventos pueden merecer otra lectura.
func (s *Store) Reclasificar(id int64, c model.Clasificacion, motivo string) error {
	_, err := s.db.Exec(
		`UPDATE eventos SET clasificacion = ?, motivo = ? WHERE id = ?`,
		string(c), motivo, id)
	if err != nil {
		return fmt.Errorf("reclasificando evento %d: %w", id, err)
	}
	return nil
}

// Destacado es un evento que merece aparecer en un informe.
type Destacado struct {
	Timestamp     time.Time
	IP            string
	Pais          string
	Tipo          model.TipoEvento
	Clasificacion model.Clasificacion
	Motivo        string
	Detalle       map[string]string
}

// Destacados devuelve los eventos que no son ruido de fondo, lo mas
// preocupante primero.
func (s *Store) Destacados(desde time.Time, limite int) ([]Destacado, error) {
	corte := desde.UTC().Format(time.RFC3339Nano)
	filas, err := s.db.Query(
		`SELECT e.timestamp, e.ip, COALESCE(i.pais,''), e.tipo,
		        e.clasificacion, COALESCE(e.motivo,''), COALESCE(e.detalle,'')
		   FROM eventos e
		   LEFT JOIN ips i ON i.ip = e.ip
		  WHERE e.timestamp >= ? AND e.clasificacion <> ?
		  ORDER BY CASE e.clasificacion WHEN ? THEN 0 ELSE 1 END,
		           e.timestamp DESC
		  LIMIT ?`,
		corte, string(model.RuidoFondo), string(model.Notable), limite)
	if err != nil {
		return nil, fmt.Errorf("consultando destacados: %w", err)
	}
	defer filas.Close()

	var out []Destacado
	for filas.Next() {
		var d Destacado
		var ts, tipo, clas, detalle string
		if err := filas.Scan(&ts, &d.IP, &d.Pais, &tipo, &clas, &d.Motivo, &detalle); err != nil {
			return nil, err
		}
		d.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		d.Tipo = model.TipoEvento(tipo)
		d.Clasificacion = model.Clasificacion(clas)
		if detalle != "" {
			json.Unmarshal([]byte(detalle), &d.Detalle)
		}
		out = append(out, d)
	}
	return out, filas.Err()
}

// PorClasificacion cuenta cuantos eventos hay de cada nivel de atencion.
func (s *Store) PorClasificacion(desde time.Time) (map[model.Clasificacion]int, error) {
	corte := desde.UTC().Format(time.RFC3339Nano)
	filas, err := s.db.Query(
		`SELECT clasificacion, COUNT(*) FROM eventos
		  WHERE timestamp >= ? GROUP BY clasificacion`, corte)
	if err != nil {
		return nil, fmt.Errorf("contando por clasificacion: %w", err)
	}
	defer filas.Close()

	out := map[model.Clasificacion]int{}
	for filas.Next() {
		var c string
		var n int
		if err := filas.Scan(&c, &n); err != nil {
			return nil, err
		}
		out[model.Clasificacion(c)] = n
	}
	return out, filas.Err()
}

// PuntoSerie es un intervalo de la grafica temporal, ya desglosado por
// nivel de atencion para poder apilar las barras.
type PuntoSerie struct {
	Momento time.Time `json:"momento"`
	Total   int       `json:"total"`
	Ruido   int       `json:"ruido"`
	Revisar int       `json:"revisar"`
	Notable int       `json:"notable"`
}

// Granularidad de la serie temporal.
type Granularidad string

const (
	PorHora Granularidad = "hora"
	PorDia  Granularidad = "dia"
)

// SerieTemporal agrupa los eventos en intervalos para dibujar la grafica.
//
// El agrupado lo hace SQLite con strftime sobre el timestamp, que se guarda
// en RFC3339 UTC: como el formato es lexicograficamente ordenable, recortar
// la cadena por horas o dias equivale a truncar la fecha.
func (s *Store) SerieTemporal(desde time.Time, g Granularidad) ([]PuntoSerie, error) {
	formato := "%Y-%m-%dT%H:00:00Z"
	if g == PorDia {
		formato = "%Y-%m-%dT00:00:00Z"
	}

	filas, err := s.db.Query(
		`SELECT strftime(?, timestamp) AS cubo,
		        COUNT(*),
		        SUM(clasificacion = ?),
		        SUM(clasificacion = ?),
		        SUM(clasificacion = ?)
		   FROM eventos
		  WHERE timestamp >= ?
		  GROUP BY cubo
		  ORDER BY cubo`,
		formato, string(model.RuidoFondo), string(model.Revisar),
		string(model.Notable), desde.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("consultando la serie temporal: %w", err)
	}
	defer filas.Close()

	var out []PuntoSerie
	for filas.Next() {
		var cubo string
		var p PuntoSerie
		if err := filas.Scan(&cubo, &p.Total, &p.Ruido, &p.Revisar, &p.Notable); err != nil {
			return nil, err
		}
		p.Momento, _ = time.Parse(time.RFC3339, cubo)
		out = append(out, p)
	}
	return out, filas.Err()
}

// Reciente es una linea del feed en vivo.
type Reciente struct {
	Timestamp time.Time `json:"timestamp"`
	IP        string    `json:"ip"`
	Pais      string    `json:"pais"`
	// Ciudad y coordenadas, si la IP esta situada. El mapa dibuja desde
	// aqui cuando las hay, y desde el centroide del pais cuando no.
	Ciudad        string              `json:"ciudad,omitempty"`
	Latitud       float64             `json:"latitud,omitempty"`
	Longitud      float64             `json:"longitud,omitempty"`
	Protocolo     string              `json:"protocolo"`
	Tipo          model.TipoEvento    `json:"tipo"`
	Clasificacion model.Clasificacion `json:"clasificacion"`
	Detalle       map[string]string   `json:"detalle"`
}

// Recientes devuelve los ultimos eventos, del nivel que sean. Es el pulso
// del honeypot: sirve para ver que esta pasando ahora mismo.
func (s *Store) Recientes(limite int) ([]Reciente, error) {
	filas, err := s.db.Query(
		`SELECT e.timestamp, e.ip, COALESCE(i.pais,''), COALESCE(e.protocolo,''),
		        e.tipo, e.clasificacion, COALESCE(e.detalle,''),
		        COALESCE(i.ciudad,''), COALESCE(i.latitud,0), COALESCE(i.longitud,0)
		   FROM eventos e
		   LEFT JOIN ips i ON i.ip = e.ip
		  ORDER BY e.id DESC
		  LIMIT ?`, limite)
	if err != nil {
		return nil, fmt.Errorf("consultando eventos recientes: %w", err)
	}
	defer filas.Close()

	out := []Reciente{}
	for filas.Next() {
		var r Reciente
		var ts, tipo, clas, detalle string
		if err := filas.Scan(&ts, &r.IP, &r.Pais, &r.Protocolo, &tipo, &clas, &detalle,
			&r.Ciudad, &r.Latitud, &r.Longitud); err != nil {
			return nil, err
		}
		r.Timestamp, _ = time.Parse(time.RFC3339Nano, ts)
		r.Tipo = model.TipoEvento(tipo)
		r.Clasificacion = model.Clasificacion(clas)
		if detalle != "" {
			json.Unmarshal([]byte(detalle), &r.Detalle)
		}
		out = append(out, r)
	}
	return out, filas.Err()
}

// IPsSinUbicar devuelve las IPs que tienen ficha pero aun no tienen
// coordenadas. Son las que se pueden situar cuando llega una base GeoIP
// nueva, sin gastar cuota de AbuseIPDB: la geolocalizacion es local.
func (s *Store) IPsSinUbicar(limite int) ([]string, error) {
	filas, err := s.db.Query(
		`SELECT ip FROM ips WHERE latitud = 0 AND longitud = 0 LIMIT ?`, limite)
	if err != nil {
		return nil, fmt.Errorf("buscando IPs sin ubicar: %w", err)
	}
	defer filas.Close()
	var out []string
	for filas.Next() {
		var ip string
		if err := filas.Scan(&ip); err != nil {
			return nil, err
		}
		out = append(out, ip)
	}
	return out, filas.Err()
}

// ActualizarUbicacion pone ciudad y coordenadas de una IP sin tocar nada
// mas. A proposito no cambia consultado_en: situar no es re-enriquecer, y no
// debe adelantar la proxima consulta a AbuseIPDB.
func (s *Store) ActualizarUbicacion(ip, ciudad string, lat, lon float64) error {
	_, err := s.db.Exec(
		`UPDATE ips SET ciudad = ?, latitud = ?, longitud = ? WHERE ip = ?`,
		ciudad, lat, lon, ip)
	if err != nil {
		return fmt.Errorf("actualizando la ubicacion de %s: %w", ip, err)
	}
	return nil
}
