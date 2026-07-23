package auth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashYVerificar(t *testing.T) {
	h, err := Hash("una-contrasena-larga")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Errorf("formato inesperado: %q", h)
	}
	if strings.Contains(h, "una-contrasena-larga") {
		t.Fatal("la contrasena aparece en claro dentro del hash")
	}
	if err := Verificar("una-contrasena-larga", h); err != nil {
		t.Errorf("no verifica la correcta: %v", err)
	}
	if err := Verificar("otra-cosa-distinta", h); !errors.Is(err, ErrCredenciales) {
		t.Errorf("acepto una contrasena incorrecta: %v", err)
	}
}

// Dos hashes de la misma contrasena deben salir distintos: si no, no hay
// sal y una tabla precalculada valdria para toda la instalacion.
func TestElHashLlevaSal(t *testing.T) {
	a, _ := Hash("misma-contrasena-aqui")
	b, _ := Hash("misma-contrasena-aqui")
	if a == b {
		t.Error("dos hashes identicos: falta la sal")
	}
	if err := Verificar("misma-contrasena-aqui", b); err != nil {
		t.Errorf("el segundo hash no verifica: %v", err)
	}
}

func TestContrasenaCorta(t *testing.T) {
	if _, err := Hash("corta"); !errors.Is(err, ErrContrasenaCorta) {
		t.Errorf("acepto una contrasena corta: %v", err)
	}
	if err := ValidarContrasena(strings.Repeat("a", LongitudMinima)); err != nil {
		t.Errorf("rechazo una del largo minimo: %v", err)
	}
}

func TestHashCorrupto(t *testing.T) {
	for _, malo := range []string{
		"", "no-es-un-hash", "$argon2i$v=19$m=1,t=1,p=1$c2Fs$aGFzaA",
		"$argon2id$v=19$sinparametros$c2Fs$aGFzaA",
	} {
		if err := Verificar("lo-que-sea-aqui", malo); !errors.Is(err, ErrHashInvalido) {
			t.Errorf("%q: err = %v, esperaba ErrHashInvalido", malo, err)
		}
	}
}

func TestTokens(t *testing.T) {
	a, err := NuevoToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NuevoToken()
	if a == b {
		t.Error("dos tokens iguales: el generador no es aleatorio")
	}
	if len(a) < 40 {
		t.Errorf("token de solo %d caracteres", len(a))
	}
	// En la base de datos va el hash, nunca el token: quien se lleve la
	// base de datos no debe poder suplantar una sesion viva.
	h := HashToken(a)
	if h == a || strings.Contains(h, a) {
		t.Error("el hash del token deja ver el token")
	}
	if HashToken(a) != h {
		t.Error("el hash del token no es estable")
	}
}
