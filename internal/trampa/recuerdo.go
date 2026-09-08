package trampa

import (
	"math/rand"
	"net"
	"sync"
	"time"
)

// recuerdo es la memoria -en RAM y efimera- de que direcciones vienen tocando
// las trampas y con cuanta insistencia. No se persiste ni identifica a nadie:
// solo sirve para hacer perder cada vez MAS tiempo a quien mas insiste.
//
// Es el "engano con estado". Una trampa que contesta siempre igual y al
// instante se delata; una que reconoce al que vuelve y le alarga la espera se
// parece a un servicio real bajo carga y, de paso, le roba tiempo al escaner,
// que es su recurso mas caro. Se comparte entre todas las trampas: quien
// aporrea varios puertos escala mas rapido, porque es el mismo atacante.
//
// Todo son sleeps ACOTADOS: ni ejecuta nada, ni retiene mas alla del plazo de
// lectura, ni crece sin limite (se poda y se olvida a quien deja de venir).
type recuerdo struct {
	mu     sync.Mutex
	vistos map[string]*visita
}

type visita struct {
	veces  int
	ultima time.Time
}

var memoriaTrampas = &recuerdo{vistos: map[string]*visita{}}

const (
	// Espera base: imita la latencia de un servicio real, con variacion para
	// no tener una firma temporal plana.
	tarpitBase   = 20 * time.Millisecond
	tarpitJitter = 130 * time.Millisecond
	// A partir del umbral, cada contacto extra suma castigo hasta un tope. Los
	// primeros contactos NO se penalizan: un escaneo de paso o una sonda de
	// investigacion no merecen tarpit.
	tarpitUmbral = 3
	tarpitPaso   = 300 * time.Millisecond
	tarpitTope   = 4 * time.Second
	// Se olvida a quien lleva rato sin venir, y se poda el mapa cuando crece:
	// esto es un truco de deteccion, no un registro.
	ventanaOlvido = 10 * time.Minute
	maxRecordados = 5000
)

// esperar registra un contacto de una IP y duerme lo que le toque: la latencia
// creible mas el castigo por insistir.
func (r *recuerdo) esperar(ip string) {
	// Loopback no es un atacante remoto: es tooling local (o los tests).
	// Los ataques de verdad llegan por IP publica via el reenvio del router,
	// asi que a loopback ni se le tarpitea ni se le recuerda.
	if p := net.ParseIP(ip); p != nil && p.IsLoopback() {
		return
	}
	r.mu.Lock()
	ahora := time.Now()
	r.podarSiToca(ahora)
	v := r.vistos[ip]
	if v == nil {
		v = &visita{}
		r.vistos[ip] = v
	}
	if ahora.Sub(v.ultima) > ventanaOlvido {
		v.veces = 0 // llevaba rato fuera: empieza de cero
	}
	v.veces++
	v.ultima = ahora
	veces := v.veces
	r.mu.Unlock()

	time.Sleep(tarpitBase + time.Duration(rand.Int63n(int64(tarpitJitter))) + escaladoTarpit(veces))
}

// escaladoTarpit es el castigo por insistir, aparte para poder probarlo: cero
// hasta el umbral, luego un paso por cada contacto, con tope.
func escaladoTarpit(veces int) time.Duration {
	if veces <= tarpitUmbral {
		return 0
	}
	extra := time.Duration(veces-tarpitUmbral) * tarpitPaso
	if extra > tarpitTope {
		return tarpitTope
	}
	return extra
}

// podarSiToca borra a los que llevan rato sin aparecer, pero solo cuando el
// mapa ya es grande: no compensa recorrerlo entero en cada conexion.
func (r *recuerdo) podarSiToca(ahora time.Time) {
	if len(r.vistos) < maxRecordados {
		return
	}
	for ip, v := range r.vistos {
		if ahora.Sub(v.ultima) > ventanaOlvido {
			delete(r.vistos, ip)
		}
	}
}
