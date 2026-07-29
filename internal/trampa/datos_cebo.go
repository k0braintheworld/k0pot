package trampa

import (
	"strings"

	cebopkg "github.com/k0braintheworld/k0pot/internal/cebo"
)

// Este fichero define los datos FALSOS que sirven las trampas de base de datos
// (MySQL, PostgreSQL) cuando dejan "entrar" a un atacante. La gracia es doble:
// entretenerlo con botin creible para ver como exfiltra, y colar credenciales
// SENUELO (canarios) entre las filas, de modo que si reutiliza una mas tarde,
// salta la alarma. Nada de esto es real ni abre nada.

// tablaFalsa es un resultado de consulta: sus columnas y sus filas (todo texto).
type tablaFalsa struct {
	Columnas []string
	Filas    [][]string
}

// tablaParaConsulta elige que devolver segun lo que el atacante pregunte. No se
// parsea SQL de verdad: basta con reconocer las consultas de reconocimiento
// tipicas (listar bases, tablas, version, usuarios) y, para el resto, servir la
// tabla jugosa de usuarios con las credenciales senuelo.
func tablaParaConsulta(sql, version string) tablaFalsa {
	q := strings.ToLower(sql)
	switch {
	case strings.Contains(q, "database") || strings.Contains(q, "datname") || strings.Contains(q, "pg_database"):
		return tablaFalsa{[]string{"Database"}, [][]string{
			{"information_schema"}, {"acme_prod"}, {"users"}, {"payments"}, {"mysql"}}}
	case strings.Contains(q, "table_name") || strings.Contains(q, "tablename") ||
		strings.Contains(q, "pg_tables") || strings.Contains(q, "show tables"):
		return tablaFalsa{[]string{"table_name"}, [][]string{
			{"users"}, {"customers"}, {"payments"}, {"sessions"}, {"api_keys"}}}
	case strings.Contains(q, "version"):
		return tablaFalsa{[]string{"version"}, [][]string{{version}}}
	case strings.Contains(q, "user()") || strings.Contains(q, "current_user") ||
		strings.Contains(q, "pg_user") || strings.Contains(q, "mysql.user"):
		return tablaFalsa{[]string{"user", "host"}, [][]string{
			{"root", "localhost"}, {"acme_app", "%"}, {"svc_backup", "10.0.0.9"}}}
	default:
		return datosJugosos()
	}
}

// datosJugosos es la tabla de usuarios con credenciales dentro. La primera fila
// lleva un canario de verdad (el mismo token del catalogo de cebo): si el
// atacante lo exfiltra y lo reutiliza, lo cazamos.
func datosJugosos() tablaFalsa {
	token := canario("token de API", "k0tok_7Fq3Rn9ZbW1sYpX")
	return tablaFalsa{
		Columnas: []string{"id", "email", "role", "password_hash", "api_token"},
		Filas: [][]string{
			{"1", "admin@acme-corp.example", "admin", "$2y$10$Xq9pLk2mWq4rTy7xZc0aJfeUoI5sPdGhKlMnQwq3RnZ", token},
			{"2", "deploy@acme-corp.example", "ops", "$2y$10$Lp7z2Kd9xR3mNp0Ht4bV6cY1aJ8eUoI2sFgQwq3RnZ", "k0tok_pipeline_2Xr9Vb"},
			{"3", "billing@acme-corp.example", "finance", "$2y$10$Q2T3mNpH7bV6cY0AkR9xQuJf2eUoI5sPdGhKlMnZwq", "k0tok_billing_7Yb1Nz"},
		},
	}
}

// canario devuelve el valor de un canario del catalogo por un trozo de su
// etiqueta, con un valor por defecto por si el catalogo cambiara.
func canario(subEtiqueta, porDefecto string) string {
	for _, c := range cebopkg.Canarios() {
		if strings.Contains(c.Etiqueta, subEtiqueta) {
			return c.Valor
		}
	}
	return porDefecto
}
