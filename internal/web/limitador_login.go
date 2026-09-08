package web

import (
	"net"
	"net/http"
	"sync"
	"time"
)

// limitadorLogin frena la fuerza bruta contra el panel. Cada intento FALLIDO
// desde una IP la penaliza con una espera creciente, que se reinicia al
// acertar. No bloquea -un usuario que se equivoca unas veces no se queda
// fuera-, pero vuelve inutil probar miles de contrasenas. En RAM y efimero:
// es una defensa, no un registro. Complementa al Argon2 (ya lento a proposito)
// y al aislamiento de red; defensa en profundidad.
type limitadorLogin struct {
	mu     sync.Mutex
	fallos map[string]*intentos
}

type intentos struct {
	n      int
	ultimo time.Time
}

const (
	loginUmbral = 5 // los primeros fallos no se penalizan (dedos torpes)
	loginPaso   = 500 * time.Millisecond
	loginTope   = 10 * time.Second
	loginOlvido = 15 * time.Minute
	loginMaxIPs = 5000
)

var limitadorDeLogin = nuevoLimitadorLogin()

func nuevoLimitadorLogin() *limitadorLogin {
	return &limitadorLogin{fallos: map[string]*intentos{}}
}

// penalizacion es lo que una IP debe esperar AHORA por sus fallos recientes,
// sin registrar nada. Cero si no tiene fallos o si ya se le olvidaron.
func (l *limitadorLogin) penalizacion(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	it := l.fallos[ip]
	if it == nil || time.Since(it.ultimo) > loginOlvido {
		return 0
	}
	return retrasoLogin(it.n)
}

// fallo anota un intento fallido de una IP.
func (l *limitadorLogin) fallo(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	ahora := time.Now()
	l.podar(ahora)
	it := l.fallos[ip]
	if it == nil {
		it = &intentos{}
		l.fallos[ip] = it
	}
	if ahora.Sub(it.ultimo) > loginOlvido {
		it.n = 0
	}
	it.n++
	it.ultimo = ahora
}

// exito borra el historial de una IP: acerto, no era un atacante.
func (l *limitadorLogin) exito(ip string) {
	l.mu.Lock()
	delete(l.fallos, ip)
	l.mu.Unlock()
}

func (l *limitadorLogin) podar(ahora time.Time) {
	if len(l.fallos) < loginMaxIPs {
		return
	}
	for ip, it := range l.fallos {
		if ahora.Sub(it.ultimo) > loginOlvido {
			delete(l.fallos, ip)
		}
	}
}

// retrasoLogin es la espera por n fallos, aparte para poder probarla: cero
// hasta el umbral, luego medio segundo por fallo, con tope.
func retrasoLogin(n int) time.Duration {
	if n <= loginUmbral {
		return 0
	}
	d := time.Duration(n-loginUmbral) * loginPaso
	if d > loginTope {
		return loginTope
	}
	return d
}

// ipRemota saca la direccion del cliente sin el puerto.
func ipRemota(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
}
