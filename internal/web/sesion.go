package web

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/auth"
	"github.com/k0braintheworld/k0pot/internal/store"
)

const nombreCookie = "k0pot_sesion"

// Sin cuentas el panel no sirve nada. Es preferible eso a dejar una ventana
// en la que cualquiera de la red pueda reclamar la de administrador.
const avisoSinCuentas = "No hay ninguna cuenta. Crea una en el servidor con: ./honey -crear-usuario <nombre>"

// ponerCookie escribe la cookie de sesion.
//
// Secure se activa solo bajo HTTPS: marcarla siempre romperia el panel en
// HTTP, que es como se sirve en una LAN sin certificado.
func ponerCookie(w http.ResponseWriter, r *http.Request, token string, expira time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     nombreCookie,
		Value:    token,
		Path:     "/",
		Expires:  expira,
		HttpOnly: true, // fuera del alcance de cualquier script
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode, // corta el CSRF entre sitios
	})
}

func borrarCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     nombreCookie,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
	})
}

// usuarioDe resuelve la sesion de una peticion.
func (s *Servidor) usuarioDe(r *http.Request) (*store.Usuario, bool) {
	c, err := r.Cookie(nombreCookie)
	if err != nil || c.Value == "" {
		return nil, false
	}
	u, err := s.Almacen.SesionValida(auth.HashToken(c.Value))
	if err != nil {
		return nil, false
	}
	return u, true
}

// mismoOrigen rechaza peticiones que cambian estado y vienen de otro sitio.
//
// Es defensa en profundidad sobre SameSite=Lax: si un navegador viejo no lo
// respeta, esta comprobacion sigue en pie.
func mismoOrigen(r *http.Request) bool {
	origen := r.Header.Get("Origin")
	if origen == "" {
		// Sin Origin (algunos clientes no lo mandan) se mira el Referer.
		if ref := r.Header.Get("Referer"); ref != "" {
			u, err := url.Parse(ref)
			if err != nil {
				return false
			}
			return u.Host == r.Host
		}
		return true // ni Origin ni Referer: no es una peticion de navegador
	}
	u, err := url.Parse(origen)
	if err != nil {
		return false
	}
	return u.Host == r.Host
}

// protegido exige sesion. Las rutas de API responden 401 en JSON; las de
// pagina redirigen al login, que es lo que espera un navegador.
func (s *Servidor) protegido(siguiente http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.usuarioDe(r); !ok {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				w.Header().Set("Content-Type", "application/json; charset=utf-8")
				w.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(w).Encode(map[string]string{"error": "sesion requerida"})
				return
			}
			http.Redirect(w, r, "/entrar.html", http.StatusSeeOther)
			return
		}
		siguiente(w, r)
	}
}

// escribe estado con un mensaje JSON.
func responderError(w http.ResponseWriter, codigo int, mensaje string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(codigo)
	json.NewEncoder(w).Encode(map[string]string{"error": mensaje})
}

type peticionEntrar struct {
	Usuario    string `json:"usuario"`
	Contrasena string `json:"contrasena"`
}

func (s *Servidor) entrar(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, http.StatusMethodNotAllowed, "usa POST")
		return
	}
	if !mismoOrigen(r) {
		responderError(w, http.StatusForbidden, "origen no permitido")
		return
	}

	hay, err := s.Almacen.HayUsuarios()
	if err != nil {
		responderError(w, http.StatusInternalServerError, "error interno")
		return
	}
	if !hay {
		responderError(w, http.StatusServiceUnavailable, avisoSinCuentas)
		return
	}

	var p peticionEntrar
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&p); err != nil {
		responderError(w, http.StatusBadRequest, "peticion ilegible")
		return
	}

	u, err := s.Almacen.UsuarioPorNombre(p.Usuario)
	if err != nil {
		// Mismo mensaje y mismo coste que una contrasena mala: decir
		// "ese usuario no existe" regala la mitad de la credencial.
		auth.Verificar(p.Contrasena, hashSenuelo)
		log.Printf("intento de acceso fallido para %q desde %s", p.Usuario, r.RemoteAddr)
		responderError(w, http.StatusUnauthorized, auth.ErrCredenciales.Error())
		return
	}
	if err := auth.Verificar(p.Contrasena, u.Hash); err != nil {
		log.Printf("intento de acceso fallido para %q desde %s", p.Usuario, r.RemoteAddr)
		responderError(w, http.StatusUnauthorized, auth.ErrCredenciales.Error())
		return
	}

	token, err := auth.NuevoToken()
	if err != nil {
		responderError(w, http.StatusInternalServerError, "error interno")
		return
	}
	expira := time.Now().Add(auth.DuracionSesion)
	if err := s.Almacen.CrearSesion(auth.HashToken(token), u.ID, expira); err != nil {
		responderError(w, http.StatusInternalServerError, "no se pudo crear la sesion")
		return
	}
	s.Almacen.MarcarAcceso(u.ID)
	s.Almacen.PurgarSesiones()

	ponerCookie(w, r, token, expira)
	responderJSON(w, map[string]any{"usuario": u.Nombre})
}

// hashSenuelo es un hash real de una contrasena que nadie usa. Verificar
// contra el cuando el usuario no existe hace que acertar y fallar el nombre
// cuesten lo mismo, y no se pueda distinguir por el tiempo de respuesta.
var hashSenuelo = func() string {
	h, err := auth.Hash("senuelo-para-igualar-tiempos")
	if err != nil {
		panic(err) // solo puede fallar si el generador aleatorio no va
	}
	return h
}()

func (s *Servidor) salir(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(nombreCookie); err == nil && c.Value != "" {
		s.Almacen.BorrarSesion(auth.HashToken(c.Value))
	}
	borrarCookie(w, r)
	responderJSON(w, map[string]string{"estado": "fuera"})
}

// quien dice al panel si hay sesion, y si el sistema esta sin configurar.
func (s *Servidor) quien(w http.ResponseWriter, r *http.Request) {
	hay, err := s.Almacen.HayUsuarios()
	if err != nil {
		responderError(w, http.StatusInternalServerError, "error interno")
		return
	}
	if !hay {
		responderJSON(w, map[string]any{"sin_cuentas": true, "aviso": avisoSinCuentas})
		return
	}
	u, ok := s.usuarioDe(r)
	if !ok {
		responderJSON(w, map[string]any{"autenticado": false})
		return
	}
	responderJSON(w, map[string]any{"autenticado": true, "usuario": u.Nombre})
}

type peticionContrasena struct {
	Actual string `json:"actual"`
	Nueva  string `json:"nueva"`
}

func (s *Servidor) cambiarContrasena(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, http.StatusMethodNotAllowed, "usa POST")
		return
	}
	if !mismoOrigen(r) {
		responderError(w, http.StatusForbidden, "origen no permitido")
		return
	}
	u, _ := s.usuarioDe(r)

	var p peticionContrasena
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&p); err != nil {
		responderError(w, http.StatusBadRequest, "peticion ilegible")
		return
	}
	if err := auth.Verificar(p.Actual, u.Hash); err != nil {
		responderError(w, http.StatusUnauthorized, "la contrasena actual no es correcta")
		return
	}

	nuevo, err := auth.Hash(p.Nueva)
	if err != nil {
		if errors.Is(err, auth.ErrContrasenaCorta) {
			responderError(w, http.StatusBadRequest, err.Error())
			return
		}
		responderError(w, http.StatusInternalServerError, "error interno")
		return
	}
	if err := s.Almacen.CambiarHash(u.ID, nuevo); err != nil {
		responderError(w, http.StatusInternalServerError, "no se pudo cambiar")
		return
	}
	// Cerrar el resto de sesiones: si alguien tenia la contrasena vieja,
	// deja de valerle ahora mismo.
	s.Almacen.BorrarSesionesDe(u.ID)

	token, err := auth.NuevoToken()
	if err != nil {
		responderError(w, http.StatusInternalServerError, "error interno")
		return
	}
	expira := time.Now().Add(auth.DuracionSesion)
	s.Almacen.CrearSesion(auth.HashToken(token), u.ID, expira)
	ponerCookie(w, r, token, expira)

	responderJSON(w, map[string]string{"estado": "cambiada"})
}
