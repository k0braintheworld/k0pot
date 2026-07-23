package collector

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"time"
)

// Seguidor sigue un fichero de log linea a linea, al estilo "tail -f".
//
// Tolera las dos cosas que le pasan a un log en produccion: que lo roten
// (Cowrie crea un fichero nuevo cada dia) y que lo trunquen. En ambos
// casos reabre y sigue, sin perder el hilo.
//
// Empieza siempre por el principio del fichero: la idempotencia la
// garantiza la restriccion UNIQUE sobre el id externo del evento, asi que
// releer es inofensivo y evita perder eventos entre reinicios.
type Seguidor struct {
	Ruta      string
	Intervalo time.Duration // espera entre sondeos cuando no hay datos nuevos
}

// NuevoSeguidor crea un seguidor con un intervalo de sondeo razonable.
func NuevoSeguidor(ruta string) *Seguidor {
	return &Seguidor{Ruta: ruta, Intervalo: time.Second}
}

// motivo explica por que el fichero que seguiamos dejo de ser valido.
// La distincion importa: al rotar hay que rescatar lo que quede sin leer
// del fichero viejo, mientras que al truncar lo que queda tras nuestro
// offset son bytes del contenido nuevo, no eventos pendientes.
type motivo int

const (
	sigueIgual motivo = iota
	rotado            // la ruta apunta ya a otro fichero
	truncado          // mismo fichero, pero reescrito desde cero
)

// Seguir llama a alLeer por cada linea completa, hasta que se cancele el
// contexto. Una linea a medio escribir se guarda y se completa en la
// siguiente pasada: nunca se entrega JSON truncado.
func (s *Seguidor) Seguir(ctx context.Context, alLeer func([]byte) error) error {
	f, err := os.Open(s.Ruta)
	if err != nil {
		return err
	}
	defer func() { f.Close() }()

	lector := bufio.NewReader(f)
	var pendiente []byte
	var leidos int64
	huella, err := huellaDe(f)
	if err != nil {
		return err
	}

	for {
		linea, err := lector.ReadBytes('\n')
		leidos += int64(len(linea))
		if len(linea) > 0 {
			pendiente = append(pendiente, linea...)
		}

		// Linea completa: la entregamos.
		if err == nil {
			completa := bytes.TrimSpace(pendiente)
			pendiente = nil
			if len(completa) > 0 {
				if err := alLeer(completa); err != nil {
					return err
				}
			}
			continue
		}
		if !errors.Is(err, io.EOF) {
			return err
		}

		// EOF: esperamos a que haya mas datos, comprobando entretanto si
		// el fichero fue rotado o truncado bajo nuestros pies.
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(s.Intervalo):
		}

		porQue, err := s.revisar(f, leidos, &huella)
		if err != nil {
			return err
		}
		if porQue == sigueIgual {
			continue
		}

		// Solo en una rotacion queda algo util por leer: entre nuestro
		// EOF y el renombrado el honeypot pudo escribir mas lineas, y
		// perderlas seria perder ataques sin enterarnos. Si en cambio
		// truncaron, lo que hay tras nuestro offset son bytes sueltos
		// del contenido nuevo: entregarlos seria corromper el log.
		if porQue == rotado {
			if err := drenar(lector, pendiente, alLeer); err != nil {
				return err
			}
		}
		pendiente = nil

		nuevo, err := os.Open(s.Ruta)
		if err != nil {
			// Rotacion a medias: el fichero nuevo aun no existe.
			// Reintentamos en la siguiente vuelta.
			continue
		}
		f.Close()
		f = nuevo
		lector.Reset(f)
		leidos = 0
		if huella, err = huellaDe(f); err != nil {
			return err
		}
	}
}

// drenar entrega las lineas completas que queden por leer antes de
// abandonar un fichero rotado.
func drenar(lector *bufio.Reader, pendiente []byte, alLeer func([]byte) error) error {
	for {
		linea, err := lector.ReadBytes('\n')
		if len(linea) > 0 {
			pendiente = append(pendiente, linea...)
		}
		if err == nil {
			if completa := bytes.TrimSpace(pendiente); len(completa) > 0 {
				if err := alLeer(completa); err != nil {
					return err
				}
			}
			pendiente = nil
			continue
		}
		if errors.Is(err, io.EOF) {
			// Lo que quede sin salto de linea final esta incompleto:
			// no es JSON valido todavia, se descarta.
			return nil
		}
		return err
	}
}

// tamHuella son los bytes de cabecera que usamos como firma del fichero.
const tamHuella = 64

// huellaDe lee el principio del fichero. Sirve de firma para detectar que
// lo han truncado y reescrito: en ese caso la cabecera cambia aunque el
// inodo siga siendo el mismo y el tamano ni siquiera haya bajado.
func huellaDe(f *os.File) ([]byte, error) {
	buf := make([]byte, tamHuella)
	n, err := f.ReadAt(buf, 0)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:n], nil
}

// revisar averigua si el log que seguimos sigue siendo el mismo.
//
// Actualiza la huella cuando el fichero solo ha crecido, para poder
// firmarlo tambien cuando lo empezamos a seguir estando vacio.
func (s *Seguidor) revisar(actual *os.File, leidos int64, huella *[]byte) (motivo, error) {
	enRuta, err := os.Stat(s.Ruta)
	if err != nil {
		if os.IsNotExist(err) {
			return sigueIgual, nil // rotacion a medias; esperamos
		}
		return sigueIgual, err
	}

	abierto, err := actual.Stat()
	if err != nil {
		return sigueIgual, err
	}

	if !os.SameFile(enRuta, abierto) {
		return rotado, nil
	}
	if enRuta.Size() < leidos {
		return truncado, nil
	}

	ahora, err := huellaDe(actual)
	if err != nil {
		return sigueIgual, err
	}
	if n := len(*huella); n > 0 {
		// Anadir al final no toca la cabecera ya firmada; si esta cambia
		// o desaparece, el fichero fue reescrito bajo nuestros pies.
		if len(ahora) < n || !bytes.Equal(ahora[:n], (*huella)[:n]) {
			return truncado, nil
		}
	}
	*huella = ahora
	return sigueIgual, nil
}
