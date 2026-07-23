package store

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"
)

// Esquema de autenticacion y configuracion.
//
// Las contrasenas se guardan como hash argon2id (ver internal/auth), nunca
// en claro. Las sesiones guardan el HASH del token, no el token: si alguien
// se lleva la base de datos no puede suplantar sesiones vivas con lo que
// hay dentro.
const esquemaAuth = `
CREATE TABLE IF NOT EXISTS usuarios (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    nombre      TEXT NOT NULL UNIQUE,
    hash        TEXT NOT NULL,
    creado_en   TEXT NOT NULL,
    ultimo_acceso TEXT
);

CREATE TABLE IF NOT EXISTS sesiones (
    hash_token  TEXT PRIMARY KEY,
    usuario_id  INTEGER NOT NULL REFERENCES usuarios(id) ON DELETE CASCADE,
    creada_en   TEXT NOT NULL,
    expira_en   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sesiones_expira ON sesiones(expira_en);

-- Una sola fila: la configuracion entera vive como JSON.
CREATE TABLE IF NOT EXISTS config (
    id     INTEGER PRIMARY KEY CHECK (id = 1),
    datos  TEXT NOT NULL
);
`

// ErrNoExiste lo devuelven las lecturas que no encuentran nada.
var ErrNoExiste = errors.New("no existe")

// Usuario es una cuenta del panel.
type Usuario struct {
	ID           int64
	Nombre       string
	Hash         string
	CreadoEn     time.Time
	UltimoAcceso time.Time
}

// CrearUsuario da de alta una cuenta. El hash lo calcula quien llama.
func (s *Store) CrearUsuario(nombre, hash string) (int64, error) {
	res, err := s.db.Exec(
		`INSERT INTO usuarios (nombre, hash, creado_en) VALUES (?,?,?)`,
		nombre, hash, time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, fmt.Errorf("creando usuario %q: %w", nombre, err)
	}
	id, err := res.LastInsertId()
	log.Printf("AUDITORIA: cuenta %q creada (id %d)", nombre, id)
	return id, err
}

// UsuarioPorNombre busca una cuenta. Devuelve ErrNoExiste si no la hay.
func (s *Store) UsuarioPorNombre(nombre string) (*Usuario, error) {
	var u Usuario
	var creado string
	var ultimo sql.NullString

	err := s.db.QueryRow(
		`SELECT id, nombre, hash, creado_en, ultimo_acceso
		   FROM usuarios WHERE nombre = ?`, nombre).
		Scan(&u.ID, &u.Nombre, &u.Hash, &creado, &ultimo)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoExiste
	}
	if err != nil {
		return nil, fmt.Errorf("leyendo usuario: %w", err)
	}
	u.CreadoEn, _ = time.Parse(time.RFC3339, creado)
	if ultimo.Valid {
		u.UltimoAcceso, _ = time.Parse(time.RFC3339, ultimo.String)
	}
	return &u, nil
}

// CambiarHash actualiza la contrasena de una cuenta.
//
// Se deja constancia en el log: en una herramienta de seguridad, un cambio
// de credencial que nadie recuerda haber pedido tiene que ser rastreable.
func (s *Store) CambiarHash(id int64, hash string) error {
	res, err := s.db.Exec(`UPDATE usuarios SET hash = ? WHERE id = ?`, hash, id)
	if err != nil {
		return fmt.Errorf("cambiando contrasena: %w", err)
	}
	n, _ := res.RowsAffected()
	log.Printf("AUDITORIA: contrasena cambiada para el usuario %d (%d fila(s))", id, n)
	return nil
}

// MarcarAcceso deja constancia del ultimo login correcto.
func (s *Store) MarcarAcceso(id int64) error {
	_, err := s.db.Exec(`UPDATE usuarios SET ultimo_acceso = ? WHERE id = ?`,
		time.Now().UTC().Format(time.RFC3339), id)
	return err
}

// HayUsuarios dice si el panel ya esta configurado. Sin ninguna cuenta el
// panel se niega a servir: es preferible eso a una ventana en la que
// cualquiera de la red pueda reclamar la cuenta de administrador.
func (s *Store) HayUsuarios() (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM usuarios`).Scan(&n); err != nil {
		return false, fmt.Errorf("contando usuarios: %w", err)
	}
	return n > 0, nil
}

// CrearSesion guarda el hash de un token de sesion.
func (s *Store) CrearSesion(hashToken string, usuarioID int64, expira time.Time) error {
	ahora := time.Now().UTC()
	_, err := s.db.Exec(
		`INSERT INTO sesiones (hash_token, usuario_id, creada_en, expira_en) VALUES (?,?,?,?)`,
		hashToken, usuarioID, ahora.Format(time.RFC3339), expira.UTC().Format(time.RFC3339))
	if err != nil {
		return fmt.Errorf("creando sesion: %w", err)
	}
	return nil
}

// SesionValida resuelve un hash de token a su usuario, si no ha caducado.
func (s *Store) SesionValida(hashToken string) (*Usuario, error) {
	var u Usuario
	var creado string
	var ultimo sql.NullString

	err := s.db.QueryRow(
		`SELECT u.id, u.nombre, u.hash, u.creado_en, u.ultimo_acceso
		   FROM sesiones s JOIN usuarios u ON u.id = s.usuario_id
		  WHERE s.hash_token = ? AND s.expira_en > ?`,
		hashToken, time.Now().UTC().Format(time.RFC3339)).
		Scan(&u.ID, &u.Nombre, &u.Hash, &creado, &ultimo)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNoExiste
	}
	if err != nil {
		return nil, fmt.Errorf("validando sesion: %w", err)
	}
	u.CreadoEn, _ = time.Parse(time.RFC3339, creado)
	if ultimo.Valid {
		u.UltimoAcceso, _ = time.Parse(time.RFC3339, ultimo.String)
	}
	return &u, nil
}

// BorrarSesion cierra una sesion concreta.
func (s *Store) BorrarSesion(hashToken string) error {
	_, err := s.db.Exec(`DELETE FROM sesiones WHERE hash_token = ?`, hashToken)
	return err
}

// BorrarSesionesDe cierra todas las sesiones de un usuario. Se llama al
// cambiar la contrasena: si alguien te la habia robado, deja de valerle.
func (s *Store) BorrarSesionesDe(usuarioID int64) error {
	_, err := s.db.Exec(`DELETE FROM sesiones WHERE usuario_id = ?`, usuarioID)
	return err
}

// PurgarSesiones borra las caducadas.
func (s *Store) PurgarSesiones() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM sesiones WHERE expira_en <= ?`,
		time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// LeerConfig devuelve el JSON de configuracion. ErrNoExiste si aun no se
// ha guardado ninguna.
func (s *Store) LeerConfig() (string, error) {
	var datos string
	err := s.db.QueryRow(`SELECT datos FROM config WHERE id = 1`).Scan(&datos)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrNoExiste
	}
	if err != nil {
		return "", fmt.Errorf("leyendo configuracion: %w", err)
	}
	return datos, nil
}

// GuardarConfig persiste el JSON de configuracion.
func (s *Store) GuardarConfig(datos string) error {
	_, err := s.db.Exec(
		`INSERT INTO config (id, datos) VALUES (1, ?)
		 ON CONFLICT(id) DO UPDATE SET datos = excluded.datos`, datos)
	if err != nil {
		return fmt.Errorf("guardando configuracion: %w", err)
	}
	return nil
}

// PurgarEventos borra lo capturado antes de una fecha. Devuelve cuantas
// filas se fueron. Sirve a la politica de retencion configurable.
func (s *Store) PurgarEventos(antesDe time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM eventos WHERE timestamp < ?`,
		antesDe.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return 0, fmt.Errorf("purgando eventos: %w", err)
	}
	n, _ := res.RowsAffected()

	// Las IPs que ya no tienen eventos dejan de hacer falta.
	s.db.Exec(`DELETE FROM ips WHERE ip NOT IN (SELECT DISTINCT ip FROM eventos)`)
	return n, nil
}

// ListarUsuarios devuelve las cuentas, sin sus hashes.
func (s *Store) ListarUsuarios() ([]Usuario, error) {
	filas, err := s.db.Query(
		`SELECT id, nombre, creado_en, ultimo_acceso FROM usuarios ORDER BY nombre`)
	if err != nil {
		return nil, fmt.Errorf("listando usuarios: %w", err)
	}
	defer filas.Close()

	var out []Usuario
	for filas.Next() {
		var u Usuario
		var creado string
		var ultimo sql.NullString
		if err := filas.Scan(&u.ID, &u.Nombre, &creado, &ultimo); err != nil {
			return nil, err
		}
		u.CreadoEn, _ = time.Parse(time.RFC3339, creado)
		if ultimo.Valid {
			u.UltimoAcceso, _ = time.Parse(time.RFC3339, ultimo.String)
		}
		out = append(out, u)
	}
	return out, filas.Err()
}
