package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// unDeb es la cabecera minima de un paquete Debian: archivo "ar" cuyo primer
// miembro es "debian-binary".
var unDeb = append([]byte("!<arch>\ndebian-binary   0           0     0     100644  4         \n"), []byte("2.0\n")...)

func conActualizaciones(t *testing.T) *Servidor {
	t.Helper()
	s := conCuenta(t)
	s.RutaBD = filepath.Join(t.TempDir(), "k0pot.db")
	s.Version = "1.2.3"
	return s
}

func subir(t *testing.T, s *Servidor, cuerpo []byte, origen string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/actualizacion", bytes.NewReader(cuerpo))
	if origen != "" {
		req.Header.Set("Origin", origen)
	}
	w := httptest.NewRecorder()
	s.actualizacion(w, req)
	return w
}

func TestActualizacionAceptaDeb(t *testing.T) {
	s := conActualizaciones(t)
	if w := subir(t, s, unDeb, ""); w.Code != http.StatusOK {
		t.Fatalf("subida de un .deb valido: codigo = %d (%s)", w.Code, w.Body)
	}
	// El fichero queda preparado y el GET lo refleja.
	if _, err := os.Stat(s.rutaActualizacion()); err != nil {
		t.Fatal("el .deb no quedo preparado:", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/api/actualizacion", nil)
	w := httptest.NewRecorder()
	s.actualizacion(w, req)
	var est estadoActualizacion
	json.Unmarshal(w.Body.Bytes(), &est)
	if est.Version != "1.2.3" || est.Pendiente == nil {
		t.Errorf("estado = %+v", est)
	}
}

func TestActualizacionRechazaNoDeb(t *testing.T) {
	s := conActualizaciones(t)
	if w := subir(t, s, []byte("esto no es un paquete"), ""); w.Code != http.StatusBadRequest {
		t.Errorf("acepto algo que no es un .deb: codigo = %d", w.Code)
	}
	if _, err := os.Stat(s.rutaActualizacion()); err == nil {
		t.Error("dejo preparado algo que no era un .deb")
	}
}

func TestActualizacionRechazaOrigenAjeno(t *testing.T) {
	s := conActualizaciones(t)
	// httptest pone Host=example.com; un Origin distinto es CSRF entre sitios.
	if w := subir(t, s, unDeb, "http://evil.example"); w.Code != http.StatusForbidden {
		t.Errorf("acepto un origen ajeno: codigo = %d", w.Code)
	}
}

func TestEsPaqueteDebian(t *testing.T) {
	dir := t.TempDir()
	bueno := filepath.Join(dir, "bueno")
	os.WriteFile(bueno, unDeb, 0o644)
	if !esPaqueteDebian(bueno) {
		t.Error("no reconocio un .deb valido")
	}
	malo := filepath.Join(dir, "malo")
	os.WriteFile(malo, []byte("MZ...un exe de windows"), 0o644)
	if esPaqueteDebian(malo) {
		t.Error("acepto algo que no es un .deb")
	}
}
