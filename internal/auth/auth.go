// Package auth cifra contrasenas y gestiona sesiones del panel.
//
// Contrasenas: argon2id, el algoritmo recomendado hoy para almacenarlas.
// Se guarda un hash con sal aleatoria y los parametros incrustados, de modo
// que subirlos manana no invalida los hashes de ayer.
//
// Sesiones: token aleatorio de 32 bytes que solo ve el navegador; en la base
// de datos se guarda su SHA-256. Quien se lleve la base de datos no puede
// reconstruir un token valido con lo que hay dentro.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

// Parametros de argon2id. Los valores siguen la recomendacion de OWASP
// para argon2id (19 MiB, 2 pasadas, paralelismo 1) y van dentro del hash,
// asi que se pueden subir sin romper lo ya guardado.
const (
	tiempo      uint32 = 2
	memoria     uint32 = 19 * 1024 // KiB
	paralelismo uint8  = 1
	tamSal      uint32 = 16
	tamClave    uint32 = 32
)

// LongitudMinima de contrasena. Corta es peor que compleja: es preferible
// exigir longitud a exigir simbolos raros que la gente apunta en un papel.
const LongitudMinima = 10

var (
	ErrCredenciales    = errors.New("usuario o contrasena incorrectos")
	ErrHashInvalido    = errors.New("hash con formato desconocido")
	ErrContrasenaCorta = fmt.Errorf("la contrasena debe tener al menos %d caracteres", LongitudMinima)
)

// ValidarContrasena comprueba los requisitos minimos.
func ValidarContrasena(c string) error {
	if utf8.RuneCountInString(c) < LongitudMinima {
		return ErrContrasenaCorta
	}
	return nil
}

// Hash cifra una contrasena para guardarla.
func Hash(contrasena string) (string, error) {
	if err := ValidarContrasena(contrasena); err != nil {
		return "", err
	}

	sal := make([]byte, tamSal)
	if _, err := rand.Read(sal); err != nil {
		return "", fmt.Errorf("generando sal: %w", err)
	}

	clave := argon2.IDKey([]byte(contrasena), sal, tiempo, memoria, paralelismo, tamClave)

	// Formato PHC estandar: $argon2id$v=19$m=...,t=...,p=...$sal$hash
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoria, tiempo, paralelismo,
		base64.RawStdEncoding.EncodeToString(sal),
		base64.RawStdEncoding.EncodeToString(clave)), nil
}

// Verificar comprueba una contrasena contra su hash.
//
// La comparacion es en tiempo constante: comparar con == filtra informacion
// por el tiempo de respuesta y permite adivinar el hash byte a byte.
func Verificar(contrasena, hashGuardado string) error {
	partes := strings.Split(hashGuardado, "$")
	if len(partes) != 6 || partes[1] != "argon2id" {
		return ErrHashInvalido
	}

	var version int
	if _, err := fmt.Sscanf(partes[2], "v=%d", &version); err != nil {
		return ErrHashInvalido
	}
	var m, t uint32
	var p uint8
	if _, err := fmt.Sscanf(partes[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return ErrHashInvalido
	}

	sal, err := base64.RawStdEncoding.DecodeString(partes[4])
	if err != nil {
		return ErrHashInvalido
	}
	esperado, err := base64.RawStdEncoding.DecodeString(partes[5])
	if err != nil {
		return ErrHashInvalido
	}

	calculado := argon2.IDKey([]byte(contrasena), sal, t, m, p, uint32(len(esperado)))
	if subtle.ConstantTimeCompare(calculado, esperado) != 1 {
		return ErrCredenciales
	}
	return nil
}

// DuracionSesion es lo que vale una sesion sin volver a entrar.
const DuracionSesion = 12 * time.Hour

// NuevoToken genera el token que viaja en la cookie.
func NuevoToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generando token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashToken es lo unico que se guarda en la base de datos.
//
// SHA-256 a secas basta aqui, sin argon2: el token ya son 32 bytes
// aleatorios, no hay nada que adivinar por fuerza bruta.
func HashToken(token string) string {
	suma := sha256.Sum256([]byte(token))
	return hex.EncodeToString(suma[:])
}
