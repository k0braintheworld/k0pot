package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	// Automatismo ("bot" o "manual") lo pone la capa web al leer, no la BD:
	// es un juicio sobre el patron, no un dato capturado.
	Automatismo string `json:"automatismo,omitempty"`
}

// EventosDesde devuelve los eventos a partir de una fecha, en orden
// cronologico, que es como los necesita la reconstruccion de episodios.
// FuenteArtefacto agrupa de donde y quien trajo un fichero capturado.
type FuenteArtefacto struct {
	IPs     []string
	URLs    []string
	Primera time.Time
	Ultima  time.Time
}

// FuentesDeArtefacto busca, por el hash SHA-256 del fichero, los eventos de
// descarga que lo trajeron: que IPs y desde que URLs, y cuando. El hash se
// guarda en el detalle del evento crudo (aunque se pierda al agrupar), asi
// que aqui se recupera la trazabilidad completa de la muestra.
// ShaDeURL devuelve el SHA-256 del fichero que se capturo desde una URL, si
// alguno. Enlaza una campana de descarga con el binario que reparte: de "se
// traen esto de aqui" a "y esto es lo que era".
func (s *Store) ShaDeURL(url string) (string, bool) {
	var sha string
	err := s.db.QueryRow(
		`SELECT json_extract(detalle,'$.sha256') FROM eventos
		  WHERE tipo = ? AND json_extract(detalle,'$.url') = ?
		    AND json_extract(detalle,'$.sha256') IS NOT NULL
		  ORDER BY timestamp DESC LIMIT 1`,
		string(model.DescargaFichero), url).Scan(&sha)
	if err != nil || sha == "" {
		return "", false
	}
	return sha, true
}

// IPsAtacantes devuelve, sin repetir, las direcciones que llegaron al menos a
// la gravedad indicada en el periodo. Es la materia prima de una blocklist:
// lo que de verdad ataco, no el escaneo de fondo.
func (s *Store) IPsAtacantes(desde time.Time, minima string) ([]string, error) {
	q := "SELECT DISTINCT ip FROM episodios WHERE fin >= ?"
	args := []any{desde.UTC().Format(time.RFC3339Nano)}
	if minima != "" {
		q += fmt.Sprintf(" AND %s >= %s",
			fmt.Sprintf(rangoSeveridad, "severidad"),
			fmt.Sprintf(rangoSeveridad, "?"))
		args = append(args, minima)
	}
	q += " ORDER BY ip"
	filas, err := s.db.Query(q, args...)
	if err != nil {
		return nil, fmt.Errorf("ips atacantes: %w", err)
	}
	defer filas.Close()
	var ips []string
	for filas.Next() {
		var ip string
		if err := filas.Scan(&ip); err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, filas.Err()
}

// ArtefactoNuevo es un fichero capturado cuya primera aparicion es reciente.
type ArtefactoNuevo struct {
	SHA256  string    `json:"sha256"`
	Primera time.Time `json:"primera"`
	IPs     int       `json:"ips"`
}

// ArtefactosNuevos devuelve los ficheros cuya PRIMERA aparicion en toda la
// historia cae dentro del periodo: las muestras que no habiamos visto nunca.
// Es lo que de verdad merece una mirada entre tanto Mirai repetido.
func (s *Store) ArtefactosNuevos(desde time.Time) ([]ArtefactoNuevo, error) {
	filas, err := s.db.Query(
		`SELECT sha, primera, ips FROM (
		   SELECT json_extract(detalle,'$.sha256') AS sha,
		          MIN(timestamp) AS primera,
		          COUNT(DISTINCT ip) AS ips
		     FROM eventos
		    WHERE tipo = ? AND json_extract(detalle,'$.sha256') IS NOT NULL
		    GROUP BY sha
		 ) WHERE primera >= ? ORDER BY primera DESC`,
		string(model.DescargaFichero), desde.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return nil, fmt.Errorf("artefactos nuevos: %w", err)
	}
	defer filas.Close()
	var out []ArtefactoNuevo
	for filas.Next() {
		var a ArtefactoNuevo
		var ts string
		if err := filas.Scan(&a.SHA256, &ts, &a.IPs); err != nil {
			return nil, err
		}
		a.Primera, _ = time.Parse(time.RFC3339Nano, ts)
		out = append(out, a)
	}
	return out, filas.Err()
}

func (s *Store) FuentesDeArtefacto(sha256 string) (FuenteArtefacto, error) {
	filas, err := s.db.Query(
		`SELECT ip, COALESCE(json_extract(detalle,'$.url'),''), timestamp
		   FROM eventos
		  WHERE tipo = ? AND json_extract(detalle,'$.sha256') = ?
		  ORDER BY timestamp`,
		string(model.DescargaFichero), sha256)
	if err != nil {
		return FuenteArtefacto{}, fmt.Errorf("fuentes del artefacto: %w", err)
	}
	defer filas.Close()

	var f FuenteArtefacto
	vistaIP, vistaURL := map[string]bool{}, map[string]bool{}
	for filas.Next() {
		var ip, url, ts string
		if err := filas.Scan(&ip, &url, &ts); err != nil {
			return FuenteArtefacto{}, err
		}
		if ip != "" && !vistaIP[ip] {
			vistaIP[ip] = true
			f.IPs = append(f.IPs, ip)
		}
		if url != "" && !vistaURL[url] {
			vistaURL[url] = true
			f.URLs = append(f.URLs, url)
		}
		if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
			if f.Primera.IsZero() || t.Before(f.Primera) {
				f.Primera = t
			}
			if t.After(f.Ultima) {
				f.Ultima = t
			}
		}
	}
	return f, filas.Err()
}

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

// FiltroEpisodios acota que ataques se piden.
//
// Un honeypot expuesto acumula cientos de ataques: sin poder acotar, la
// lista deja de servir para consultar y solo sirve para mirar lo ultimo.
type FiltroEpisodios struct {
	Desde time.Time
	// Minima descarta lo que no llegue a esa gravedad. Vacio = todo.
	Minima string
	// Protocolo acota a un servicio. Vacio = todos.
	Protocolo string
	// IP acota a una direccion exacta. Distinto de Texto, que busca por
	// trozos: para una ficha hace falta esa IP y no las que se le parecen.
	IP string
	// Texto busca en IP, pais, proveedor y resumen a la vez. Quien
	// consulta no sabe -ni tiene por que- en cual de esos campos esta lo
	// que recuerda.
	Texto  string
	Limite int
}

// Episodios devuelve los ataques que casan con el filtro, los mas graves
// primero.
func (s *Store) Episodios(f FiltroEpisodios) ([]EpisodioFila, error) {
	consulta := selectEpisodio + ` WHERE e.fin >= ?`
	args := []any{f.Desde.UTC().Format(time.RFC3339Nano)}

	if f.Minima != "" {
		consulta += fmt.Sprintf(" AND %s >= %s",
			fmt.Sprintf(rangoSeveridad, "e.severidad"), fmt.Sprintf(rangoSeveridad, "?"))
		args = append(args, f.Minima)
	}
	if f.Protocolo != "" {
		consulta += " AND e.protocolo = ?"
		args = append(args, f.Protocolo)
	}
	if f.IP != "" {
		consulta += " AND e.ip = ?"
		args = append(args, f.IP)
	}
	if t := strings.TrimSpace(f.Texto); t != "" {
		// Se busca en varios campos a la vez y por trozos: quien escribe
		// "195.178" o "Censys" no deberia tener que acertar el campo ni la
		// cadena entera.
		//
		// El patron se repite en vez de usar ?1: mezclar parametros
		// numerados con posicionales rompe con este driver, y el fallo sale
		// como un 500 sin pista de donde.
		consulta += ` AND (e.ip LIKE ? OR e.resumen LIKE ? OR e.protocolo LIKE ?
		                   OR COALESCE(i.pais,'') LIKE ? OR COALESCE(i.isp,'') LIKE ?)`
		patron := "%" + t + "%"
		args = append(args, patron, patron, patron, patron, patron)
	}
	consulta += `
		  ORDER BY CASE e.severidad
		             WHEN 'intrusion' THEN 3 WHEN 'acceso' THEN 2
		             WHEN 'tanteo'    THEN 1 ELSE 0 END DESC,
		           e.fin DESC
		  LIMIT ?`
	limite := f.Limite
	if limite <= 0 {
		limite = 200
	}
	args = append(args, limite)

	filas, err := s.db.Query(consulta, args...)
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

// CasosAprende busca, para cada concepto del modo aprende que se puede
// ejemplificar con datos, UNA IP real que lo protagonice en el periodo.
// A diferencia de recorrer la lista de Episodios() -que va acotada y
// ordenada por gravedad, y deja fuera lo de menor severidad-, aqui cada
// consulta barre TODO el periodo, asi que si el caso existe se encuentra.
// Las condiciones son fijas (no entra texto del usuario): sin riesgo de
// inyeccion. Devuelve solo los conceptos con ejemplo; los que faltan es
// que el honeypot aun no ha visto ese ataque.
func (s *Store) CasosAprende(desde time.Time) (map[string]string, error) {
	d := desde.UTC().Format(time.RFC3339Nano)
	casos := []struct{ clave, cond string }{
		{"escaneo", "solo_conexiones = 1"},
		{"fuerzabruta", "logins_fallidos >= 5 AND login_exitoso = 0"},
		{"credenciales", "passwords LIKE '%xc3511%' OR passwords LIKE '%admin%' OR passwords LIKE '%12345%' OR usuarios LIKE '%root%'"},
		{"servicios", "protocolo IN ('redis','mysql','postgres','ftp','docker','smtp','vnc','rdp') AND comandos <> '[]'"},
		{"exploit", "rutas LIKE '%jndi%' OR rutas LIKE '%struts%' OR rutas LIKE '%solr%' OR rutas LIKE '%cgi-bin%' OR rutas LIKE '%actuator%'"},
		{"cripto", "comandos LIKE '%xmrig%' OR comandos LIKE '%minerd%' OR comandos LIKE '%stratum%' OR comandos LIKE '%cpuminer%'"},
		{"proxy", "motivos LIKE '%pasarela%' OR motivos LIKE '%reenviar%'"},
		{"persistencia", "comandos LIKE '%authorized_keys%' OR comandos LIKE '%ssh-rsa%' OR comandos LIKE '%ssh-ed25519%' OR comandos LIKE '%useradd%' OR comandos LIKE '%adduser%'"},
		{"huellas", "comandos LIKE '%history -c%' OR comandos LIKE '%/var/log%' OR comandos LIKE '%shred%' OR comandos LIKE '%histfile%'"},
	}
	out := map[string]string{}
	for _, c := range casos {
		var ip sql.NullString
		err := s.db.QueryRow(
			"SELECT ip FROM episodios WHERE fin >= ? AND ("+c.cond+") ORDER BY fin DESC LIMIT 1",
			d).Scan(&ip)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("casos aprende (%s): %w", c.clave, err)
		}
		if ip.Valid && ip.String != "" {
			out[c.clave] = ip.String
		}
	}
	return out, nil
}
