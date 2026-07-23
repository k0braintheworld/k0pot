package web

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/k0braintheworld/k0pot/internal/auth"
)

const contrasenaPrueba = "contrasena-de-prueba"

// conCuenta devuelve un servidor con un usuario ya dado de alta.
func conCuenta(t *testing.T) *Servidor {
	t.Helper()
	s := servidorDePrueba(t)
	hash, err := auth.Hash(contrasenaPrueba)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Almacen.CrearUsuario("prueba", hash); err != nil {
		t.Fatal(err)
	}
	return s
}

// entrar hace login y devuelve la cookie de sesion.
func entrarComo(t *testing.T, s *Servidor, usuario, clave string) *http.Cookie {
	t.Helper()
	cuerpo := strings.NewReader(`{"usuario":"` + usuario + `","contrasena":"` + clave + `"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/entrar", cuerpo)
	r.Header.Set("Origin", "http://"+r.Host)
	w := httptest.NewRecorder()
	s.Rutas().ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("login fallido: %d %s", w.Code, w.Body.String())
	}
	for _, c := range w.Result().Cookies() {
		if c.Name == nombreCookie {
			return c
		}
	}
	t.Fatal("el login no devolvio cookie")
	return nil
}

func conSesion(t *testing.T, s *Servidor, metodo, ruta string, cuerpo string, c *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(metodo, ruta, strings.NewReader(cuerpo))
	r.Header.Set("Origin", "http://"+r.Host)
	if c != nil {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	s.Rutas().ServeHTTP(w, r)
	return w
}

// Lo esencial: sin sesion no se ven los datos capturados.
func TestSinSesionNoHayDatos(t *testing.T) {
	s := conCuenta(t)
	for _, ruta := range []string{
		"/api/estado", "/api/destacados", "/api/informe",
		"/api/serie", "/api/recientes", "/api/ajustes",
	} {
		w := pedir(t, s, ruta)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s sin sesion: codigo = %d, esperaba 401", ruta, w.Code)
		}
		if strings.Contains(w.Body.String(), "185.220.101.1") {
			t.Errorf("%s filtro datos capturados sin sesion", ruta)
		}
	}
}

func TestElPanelRedirigeAlLogin(t *testing.T) {
	w := pedir(t, conCuenta(t), "/")
	if w.Code != http.StatusSeeOther {
		t.Errorf("codigo = %d, esperaba una redireccion", w.Code)
	}
	if destino := w.Header().Get("Location"); destino != "/entrar.html" {
		t.Errorf("redirige a %q", destino)
	}
}

func TestLaPantallaDeEntradaEsPublica(t *testing.T) {
	s := conCuenta(t)
	for _, ruta := range []string{"/entrar.html", "/entrar.js", "/estilo.css", "/api/quien"} {
		if w := pedir(t, s, ruta); w.Code != http.StatusOK {
			t.Errorf("%s: codigo = %d, deberia ser publica", ruta, w.Code)
		}
	}
}

func TestCicloDeSesion(t *testing.T) {
	s := conCuenta(t)
	cookie := entrarComo(t, s, "prueba", contrasenaPrueba)

	if !cookie.HttpOnly {
		t.Error("la cookie no es HttpOnly: un script podria leerla")
	}
	if cookie.SameSite != http.SameSiteLaxMode {
		t.Error("la cookie no lleva SameSite: queda expuesta a CSRF")
	}

	if w := conSesion(t, s, http.MethodGet, "/api/estado", "", cookie); w.Code != http.StatusOK {
		t.Fatalf("con sesion: codigo = %d", w.Code)
	}

	if w := conSesion(t, s, http.MethodPost, "/api/salir", "", cookie); w.Code != http.StatusOK {
		t.Fatalf("salir: codigo = %d", w.Code)
	}
	// Tras salir, la misma cookie ya no vale.
	if w := conSesion(t, s, http.MethodGet, "/api/estado", "", cookie); w.Code != http.StatusUnauthorized {
		t.Errorf("la sesion sigue viva tras salir: %d", w.Code)
	}
}

func TestCredencialesIncorrectas(t *testing.T) {
	s := conCuenta(t)
	casos := []struct{ usuario, clave string }{
		{"prueba", "la-que-no-es-1"},
		{"no-existe", contrasenaPrueba},
		{"", ""},
	}
	for _, c := range casos {
		w := conSesion(t, s, http.MethodPost, "/api/entrar",
			`{"usuario":"`+c.usuario+`","contrasena":"`+c.clave+`"}`, nil)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%q/%q: codigo = %d, esperaba 401", c.usuario, c.clave, w.Code)
		}
		// El mensaje no debe distinguir "usuario inexistente" de
		// "contrasena mala": eso regala media credencial.
		var e map[string]string
		json.Unmarshal(w.Body.Bytes(), &e)
		if !strings.Contains(e["error"], "usuario o contrasena") {
			t.Errorf("mensaje demasiado especifico: %q", e["error"])
		}
	}
}

// Sin cuentas el panel no sirve: es preferible a dejar una ventana en la
// que cualquiera de la red reclame la cuenta de administrador.
func TestSinCuentasNoSeEntra(t *testing.T) {
	s := servidorDePrueba(t) // sin usuarios

	w := conSesion(t, s, http.MethodPost, "/api/entrar",
		`{"usuario":"quien","contrasena":"loquesea12"}`, nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("codigo = %d, esperaba 503", w.Code)
	}

	var q map[string]any
	json.Unmarshal(pedir(t, s, "/api/quien").Body.Bytes(), &q)
	if q["sin_cuentas"] != true {
		t.Errorf("/api/quien no avisa de que no hay cuentas: %v", q)
	}
}

// SameSite=Lax es la primera defensa; esta comprobacion es la segunda.
func TestOrigenAjenoRechazado(t *testing.T) {
	s := conCuenta(t)
	cookie := entrarComo(t, s, "prueba", contrasenaPrueba)

	for _, ruta := range []string{"/api/ajustes", "/api/contrasena", "/api/entrar"} {
		r := httptest.NewRequest(http.MethodPost, ruta, strings.NewReader(`{}`))
		r.Header.Set("Origin", "http://sitio-malicioso.example")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		s.Rutas().ServeHTTP(w, r)

		if w.Code != http.StatusForbidden {
			t.Errorf("%s desde otro origen: codigo = %d, esperaba 403", ruta, w.Code)
		}
	}
}

func TestAjustesEnmascaraLasClaves(t *testing.T) {
	s := conCuenta(t)
	cookie := entrarComo(t, s, "prueba", contrasenaPrueba)

	const secreto = "clave-secreta-terminada-en-XYZW"
	c := s.Config.Actual()
	c.ClaveAnthropic = secreto
	if err := s.Config.Guardar(c); err != nil {
		t.Fatal(err)
	}

	w := conSesion(t, s, http.MethodGet, "/api/ajustes", "", cookie)
	if strings.Contains(w.Body.String(), secreto) {
		t.Fatalf("la clave sale en claro por la API:\n%s", w.Body.String())
	}
	// Se deben ver exactamente los cuatro ultimos caracteres, ni uno mas:
	// es lo justo para distinguir una clave de otra.
	if !strings.Contains(w.Body.String(), `"clave_anthropic":"••••XYZW"`) {
		t.Errorf("mascara inesperada:\n%s", w.Body.String())
	}
}

// Reenviar el formulario con el campo de clave vacio no debe borrar la que
// ya estaba guardada.
func TestGuardarSinClaveNoBorraLaExistente(t *testing.T) {
	s := conCuenta(t)
	cookie := entrarComo(t, s, "prueba", contrasenaPrueba)

	c := s.Config.Actual()
	c.ClaveAbuseIPDB = "clave-previa-configurada"
	s.Config.Guardar(c)

	w := conSesion(t, s, http.MethodPost, "/api/ajustes", `{"reputacion_alta":50}`, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("codigo = %d: %s", w.Code, w.Body.String())
	}
	if s.Config.Actual().ClaveAbuseIPDB != "clave-previa-configurada" {
		t.Error("guardar sin tocar la clave la borro")
	}
	if s.Config.Actual().ReputacionAlta != 50 {
		t.Error("no se aplico el cambio de umbral")
	}
}

func TestCambiarContrasena(t *testing.T) {
	s := conCuenta(t)
	cookie := entrarComo(t, s, "prueba", contrasenaPrueba)

	// La actual tiene que ser correcta.
	w := conSesion(t, s, http.MethodPost, "/api/contrasena",
		`{"actual":"la-que-no-es-1","nueva":"nueva-contrasena-larga"}`, cookie)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("acepto una contrasena actual incorrecta: %d", w.Code)
	}

	// La nueva tiene que cumplir el minimo.
	w = conSesion(t, s, http.MethodPost, "/api/contrasena",
		`{"actual":"`+contrasenaPrueba+`","nueva":"corta"}`, cookie)
	if w.Code != http.StatusBadRequest {
		t.Errorf("acepto una contrasena nueva demasiado corta: %d", w.Code)
	}

	w = conSesion(t, s, http.MethodPost, "/api/contrasena",
		`{"actual":"`+contrasenaPrueba+`","nueva":"nueva-contrasena-larga"}`, cookie)
	if w.Code != http.StatusOK {
		t.Fatalf("cambio rechazado: %d %s", w.Code, w.Body.String())
	}
	// Y con la nueva se entra.
	entrarComo(t, s, "prueba", "nueva-contrasena-larga")
}

// Cambiar la contrasena debe cerrar las demas sesiones: si alguien tenia la
// vieja, deja de valerle en ese momento.
func TestCambiarContrasenaCierraLasOtrasSesiones(t *testing.T) {
	s := conCuenta(t)
	otraSesion := entrarComo(t, s, "prueba", contrasenaPrueba)
	laMia := entrarComo(t, s, "prueba", contrasenaPrueba)

	w := conSesion(t, s, http.MethodPost, "/api/contrasena",
		`{"actual":"`+contrasenaPrueba+`","nueva":"otra-contrasena-larga"}`, laMia)
	if w.Code != http.StatusOK {
		t.Fatalf("cambio rechazado: %s", w.Body.String())
	}

	if w := conSesion(t, s, http.MethodGet, "/api/estado", "", otraSesion); w.Code != http.StatusUnauthorized {
		t.Errorf("la otra sesion sigue viva: %d", w.Code)
	}
}
