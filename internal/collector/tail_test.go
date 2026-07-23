package collector

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// recolector acumula las lineas que le entrega el seguidor.
type recolector struct {
	mu     sync.Mutex
	lineas []string
}

func (r *recolector) anadir(b []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lineas = append(r.lineas, string(b))
	return nil
}

func (r *recolector) copia() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lineas...)
}

// esperarLineas espera hasta que se hayan recogido n lineas o se agote el
// plazo, para no depender de sleeps fijos.
func esperarLineas(t *testing.T, r *recolector, n int, plazo time.Duration) []string {
	t.Helper()
	limite := time.Now().Add(plazo)
	for time.Now().Before(limite) {
		if l := r.copia(); len(l) >= n {
			return l
		}
		time.Sleep(10 * time.Millisecond)
	}
	l := r.copia()
	t.Fatalf("esperaba %d lineas, recogi %d: %v", n, len(l), l)
	return nil
}

func arrancarSeguidor(t *testing.T, ruta string, r *recolector) context.CancelFunc {
	t.Helper()
	s := &Seguidor{Ruta: ruta, Intervalo: 20 * time.Millisecond}
	ctx, cancelar := context.WithCancel(context.Background())
	go func() { _ = s.Seguir(ctx, r.anadir) }()
	return cancelar
}

func TestSeguirLeeLoQueYaHabiaYLoNuevo(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "cowrie.json")
	if err := os.WriteFile(ruta, []byte("uno\ndos\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var r recolector
	defer arrancarSeguidor(t, ruta, &r)()

	esperarLineas(t, &r, 2, 2*time.Second)

	f, err := os.OpenFile(ruta, os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("tres\n")
	f.Close()

	l := esperarLineas(t, &r, 3, 2*time.Second)
	if l[2] != "tres" {
		t.Errorf("tercera linea = %q, esperaba \"tres\"", l[2])
	}
}

// Una linea a medio escribir no debe entregarse partida: el parser
// recibiria JSON truncado.
func TestSeguirNoEntregaLineasIncompletas(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "cowrie.json")
	if err := os.WriteFile(ruta, []byte(""), 0o644); err != nil {
		t.Fatal(err)
	}

	var r recolector
	defer arrancarSeguidor(t, ruta, &r)()

	f, _ := os.OpenFile(ruta, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(`{"parcial":`)
	f.Sync()
	time.Sleep(150 * time.Millisecond)

	if l := r.copia(); len(l) != 0 {
		t.Fatalf("entrego una linea incompleta: %v", l)
	}

	f.WriteString(`"ya esta"}` + "\n")
	f.Close()

	l := esperarLineas(t, &r, 1, 2*time.Second)
	if l[0] != `{"parcial":"ya esta"}` {
		t.Errorf("linea = %q", l[0])
	}
}

// Cowrie rota el log cada dia. Al rotar no se puede perder lo que quedaba
// por leer en el fichero viejo.
func TestSeguirSobreviveALaRotacion(t *testing.T) {
	dir := t.TempDir()
	ruta := filepath.Join(dir, "cowrie.json")
	if err := os.WriteFile(ruta, []byte("antes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var r recolector
	defer arrancarSeguidor(t, ruta, &r)()
	esperarLineas(t, &r, 1, 2*time.Second)

	// Escribimos una linea mas y rotamos acto seguido, sin dar tiempo a
	// que el seguidor la lea: es la carrera que de verdad pierde eventos.
	f, _ := os.OpenFile(ruta, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString("justo antes de rotar\n")
	f.Close()

	if err := os.Rename(ruta, filepath.Join(dir, "cowrie.json.2026-07-22")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ruta, []byte("despues\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	l := esperarLineas(t, &r, 3, 3*time.Second)
	esperadas := []string{"antes", "justo antes de rotar", "despues"}
	for i, e := range esperadas {
		if l[i] != e {
			t.Errorf("linea %d = %q, esperaba %q", i, l[i], e)
		}
	}
}

func TestSeguirSobreviveAlTruncado(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "cowrie.json")
	if err := os.WriteFile(ruta, []byte("primera\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var r recolector
	defer arrancarSeguidor(t, ruta, &r)()
	esperarLineas(t, &r, 1, 2*time.Second)

	if err := os.WriteFile(ruta, []byte("tras truncar\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	l := esperarLineas(t, &r, 2, 3*time.Second)
	if l[1] != "tras truncar" {
		t.Errorf("segunda linea = %q", l[1])
	}
}

func TestSeguirSeDetieneAlCancelar(t *testing.T) {
	ruta := filepath.Join(t.TempDir(), "cowrie.json")
	if err := os.WriteFile(ruta, []byte("uno\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	s := &Seguidor{Ruta: ruta, Intervalo: 20 * time.Millisecond}
	ctx, cancelar := context.WithCancel(context.Background())
	hecho := make(chan error, 1)
	go func() { hecho <- s.Seguir(ctx, func([]byte) error { return nil }) }()

	time.Sleep(100 * time.Millisecond)
	cancelar()

	select {
	case err := <-hecho:
		if err != context.Canceled {
			t.Errorf("error = %v, esperaba context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("el seguidor no se detuvo al cancelar")
	}
}
