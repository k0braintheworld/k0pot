package trampa

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// arrancar levanta una trampa en un puerto efimero y devuelve su direccion
// y un recolector de los eventos que registra, para poder afirmar sobre
// ellos sin tocar la base de datos.
func arrancar(t *testing.T, tr Trampa) (string, *recolector) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dir := ln.Addr().String()
	ln.Close()

	rec := &recolector{}
	ctx, cancelar := context.WithCancel(context.Background())
	t.Cleanup(cancelar)
	go tr.Servir(ctx, dir, rec.registrar)

	// Esperar a que el puerto acepte.
	for i := 0; i < 50; i++ {
		if c, err := net.Dial("tcp", dir); err == nil {
			c.Close()
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return dir, rec
}

type recolector struct {
	mu       sync.Mutex
	eventos  []model.Evento
}

func (r *recolector) registrar(ev *model.Evento) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.eventos = append(r.eventos, *ev)
}

func (r *recolector) esperar(tipo model.TipoEvento, plazo time.Duration) (model.Evento, bool) {
	fin := time.Now().Add(plazo)
	for time.Now().Before(fin) {
		r.mu.Lock()
		for _, e := range r.eventos {
			if e.Tipo == tipo {
				r.mu.Unlock()
				return e, true
			}
		}
		r.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	return model.Evento{}, false
}

// esperarDetalle es como esperar pero exige que un campo del detalle venga
// relleno. Hace falta porque el arranque abre una conexion-sonda para saber
// que el puerto ya escucha, y esa sonda deja un evento de conexion "pelado".
func (r *recolector) esperarDetalle(tipo model.TipoEvento, clave string, plazo time.Duration) (model.Evento, bool) {
	fin := time.Now().Add(plazo)
	for time.Now().Before(fin) {
		r.mu.Lock()
		for _, e := range r.eventos {
			if e.Tipo == tipo && e.Detalle[clave] != "" {
				r.mu.Unlock()
				return e, true
			}
		}
		r.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	return model.Evento{}, false
}

func TestMySQLCapturaUsuario(t *testing.T) {
	dir, rec := arrancar(t, &MySQL{})
	c, err := net.Dial("tcp", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))

	// Leer el saludo del servidor (cabecera 4 bytes + carga).
	cab := make([]byte, 4)
	if _, err := readFull(c, cab); err != nil {
		t.Fatal(err)
	}
	n := int(cab[0]) | int(cab[1])<<8 | int(cab[2])<<16
	if _, err := readFull(c, make([]byte, n)); err != nil {
		t.Fatal(err)
	}

	// Respuesta de login: flags con CONNECT_WITH_DB|PROTOCOL_41, usuario
	// "root" y base "mysql".
	var carga []byte
	flags := make([]byte, 4)
	binary.LittleEndian.PutUint32(flags, 0x0208)
	carga = append(carga, flags...)
	carga = append(carga, 0, 0, 0, 1) // tamano maximo
	carga = append(carga, 0x21)       // charset
	carga = append(carga, make([]byte, 23)...)
	carga = append(carga, []byte("root")...)
	carga = append(carga, 0)
	carga = append(carga, 0) // longitud de auth = 0
	carga = append(carga, []byte("mysql")...)
	carga = append(carga, 0)
	c.Write(conPaqueteMySQL(carga, 1))

	ev, ok := rec.esperar(model.LoginFallido, time.Second)
	if !ok {
		t.Fatal("no se registro el login")
	}
	if ev.Detalle["usuario"] != "root" {
		t.Fatalf("usuario = %q, esperaba root", ev.Detalle["usuario"])
	}
	if ev.Detalle["base_datos"] != "mysql" {
		t.Fatalf("base_datos = %q, esperaba mysql", ev.Detalle["base_datos"])
	}
}

func TestPostgresCapturaPassword(t *testing.T) {
	dir, rec := arrancar(t, &Postgres{})
	c, err := net.Dial("tcp", dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))

	// StartupMessage: version 3.0 + pares user/database.
	var cuerpo []byte
	cuerpo = append(cuerpo, 0, 3, 0, 0)
	cuerpo = append(cuerpo, []byte("user")...)
	cuerpo = append(cuerpo, 0)
	cuerpo = append(cuerpo, []byte("postgres")...)
	cuerpo = append(cuerpo, 0)
	cuerpo = append(cuerpo, []byte("database")...)
	cuerpo = append(cuerpo, 0)
	cuerpo = append(cuerpo, []byte("clientes")...)
	cuerpo = append(cuerpo, 0)
	cuerpo = append(cuerpo, 0) // fin de pares
	msg := make([]byte, 4)
	binary.BigEndian.PutUint32(msg, uint32(len(cuerpo)+4))
	msg = append(msg, cuerpo...)
	c.Write(msg)

	// Esperar la peticion de contrasena en claro ('R').
	resp := make([]byte, 9)
	if _, err := readFull(c, resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 'R' {
		t.Fatalf("esperaba 'R', llego %q", resp[0])
	}

	// PasswordMessage con la contrasena.
	pass := append([]byte("s3cr3t"), 0)
	pm := []byte{'p'}
	long := make([]byte, 4)
	binary.BigEndian.PutUint32(long, uint32(len(pass)+4))
	pm = append(pm, long...)
	pm = append(pm, pass...)
	c.Write(pm)

	ev, ok := rec.esperar(model.LoginFallido, time.Second)
	if !ok {
		t.Fatal("no se registro el login")
	}
	if ev.Detalle["usuario"] != "postgres" {
		t.Fatalf("usuario = %q", ev.Detalle["usuario"])
	}
	if ev.Detalle["password"] != "s3cr3t" {
		t.Fatalf("password = %q, esperaba s3cr3t", ev.Detalle["password"])
	}
	if ev.Detalle["base_datos"] != "clientes" {
		t.Fatalf("base_datos = %q", ev.Detalle["base_datos"])
	}
}

// readFull lee exactamente len(b) bytes.
func readFull(c net.Conn, b []byte) (int, error) {
	return io.ReadFull(c, b)
}
