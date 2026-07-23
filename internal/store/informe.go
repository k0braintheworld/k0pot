package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

const esquemaInforme = `
CREATE TABLE IF NOT EXISTS informe (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    texto     TEXT     NOT NULL,
    generador TEXT     NOT NULL,
    huella    TEXT     NOT NULL,
    dias      INTEGER  NOT NULL,
    momento   DATETIME NOT NULL
);

-- Una fila por dia. Existe para que agotar la cuota diaria de la API sea
-- imposible por construccion y no dependa de que nadie deje el panel
-- abierto: 20 s de refresco son 4.300 llamadas al dia.
CREATE TABLE IF NOT EXISTS cuota_llm (
    dia      TEXT    PRIMARY KEY,
    llamadas INTEGER NOT NULL
);
`

// InformeGuardado es el ultimo informe redactado, con lo necesario para
// decidir si sigue valiendo.
type InformeGuardado struct {
	Texto     string
	Generador string
	// Huella resume los datos con los que se redacto. Si no ha cambiado,
	// el informe seguiria diciendo exactamente lo mismo.
	Huella  string
	Dias    int
	Momento time.Time
}

// GuardarInforme reemplaza el informe almacenado. Solo hay uno.
func (s *Store) GuardarInforme(i InformeGuardado) error {
	_, err := s.db.Exec(
		`INSERT INTO informe (id, texto, generador, huella, dias, momento)
		 VALUES (1, ?, ?, ?, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET
		     texto = excluded.texto, generador = excluded.generador,
		     huella = excluded.huella, dias = excluded.dias,
		     momento = excluded.momento`,
		i.Texto, i.Generador, i.Huella, i.Dias, i.Momento.UTC(),
	)
	if err != nil {
		return fmt.Errorf("guardando el informe: %w", err)
	}
	return nil
}

// UltimoInforme devuelve el informe guardado. El booleano dice si habia
// alguno: la primera vez que arranca k0pot no lo hay, y eso no es un error.
func (s *Store) UltimoInforme() (InformeGuardado, bool, error) {
	var i InformeGuardado
	err := s.db.QueryRow(
		`SELECT texto, generador, huella, dias, momento FROM informe WHERE id = 1`,
	).Scan(&i.Texto, &i.Generador, &i.Huella, &i.Dias, &i.Momento)
	if errors.Is(err, sql.ErrNoRows) {
		return InformeGuardado{}, false, nil
	}
	if err != nil {
		return InformeGuardado{}, false, fmt.Errorf("leyendo el informe: %w", err)
	}
	return i, true, nil
}

// ConsumirCuotaLLM apunta una llamada al LLM del dia indicado si aun queda
// margen, y dice si se pudo. Un tope <= 0 significa sin limite.
//
// El incremento y la comprobacion van en la MISMA sentencia a proposito:
// leer primero y escribir despues deja una ventana por la que dos peticiones
// simultaneas pasan las dos, que es justo como se rebasa un tope.
func (s *Store) ConsumirCuotaLLM(dia string, tope int) (bool, error) {
	if tope <= 0 {
		_, err := s.db.Exec(
			`INSERT INTO cuota_llm (dia, llamadas) VALUES (?, 1)
			 ON CONFLICT(dia) DO UPDATE SET llamadas = llamadas + 1`, dia)
		if err != nil {
			return false, fmt.Errorf("apuntando la llamada: %w", err)
		}
		return true, nil
	}
	res, err := s.db.Exec(
		`INSERT INTO cuota_llm (dia, llamadas) VALUES (?, 1)
		 ON CONFLICT(dia) DO UPDATE SET llamadas = llamadas + 1
		 WHERE cuota_llm.llamadas < ?`, dia, tope)
	if err != nil {
		return false, fmt.Errorf("apuntando la llamada: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("comprobando la cuota: %w", err)
	}
	return n > 0, nil
}

// CuotaLLMUsada son las llamadas ya hechas ese dia.
func (s *Store) CuotaLLMUsada(dia string) (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT llamadas FROM cuota_llm WHERE dia = ?`, dia).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("leyendo la cuota: %w", err)
	}
	return n, nil
}

// DevolverCuotaLLM deshace una llamada apuntada que no llego a hacerse.
//
// La cuota se apunta ANTES de llamar, para que dos peticiones simultaneas
// no rebasen el tope. Pero si el proveedor rechaza la peticion no se ha
// consumido nada suyo, y descontarla igual gastaria el presupuesto del
// usuario en las averias del proveedor.
func (s *Store) DevolverCuotaLLM(dia string) error {
	_, err := s.db.Exec(
		`UPDATE cuota_llm SET llamadas = MAX(0, llamadas - 1) WHERE dia = ?`, dia)
	if err != nil {
		return fmt.Errorf("devolviendo la llamada: %w", err)
	}
	return nil
}
