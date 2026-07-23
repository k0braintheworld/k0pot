// Package trampa implementa honeypots ligeros nativos en Go.
//
// Por que nativos y no un contenedor por servicio, como T-Pot: este binario
// ya tiene el pipeline entero (clasificacion, enriquecimiento, informes) y
// una trampa nativa entrega el evento directamente, sin pasar por un fichero
// de log que haya que seguir y parsear. Ademas pesan kilobytes en vez de
// cientos de megas, que en una maquina de 1,6 GB importa.
//
// Cowrie sigue aparte, en su contenedor: emular una shell SSH completa es un
// proyecto en si mismo y reimplementarlo seria absurdo.
package trampa

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// Registrar recibe cada evento capturado por una trampa.
type Registrar func(*model.Evento)

// Trampa es un honeypot que escucha en un puerto.
type Trampa interface {
	// ID identifica el servicio en la configuracion.
	ID() string
	// Nombre es como se llama en el panel.
	Nombre() string
	// Descripcion explica que captura, para el panel.
	Descripcion() string
	// PuertoPorDefecto es donde escucha si no se configura otro.
	PuertoPorDefecto() int
	// Servir escucha hasta que se cancele el contexto.
	Servir(ctx context.Context, direccion string, reg Registrar) error
}

// limites protege a la trampa de que un atacante la use para agotar la
// maquina: un honeypot que tumba su propio servidor no sirve de nada.
const (
	plazoLectura   = 30 * time.Second
	maxPorConexion = 64 * 1024
	maxSimultaneas = 200
)

// servirTCP es el bucle de aceptacion comun a todas las trampas TCP.
//
// Limita las conexiones simultaneas y cierra el listener al cancelar el
// contexto, para que parar el servicio no deje puertos colgados.
func servirTCP(ctx context.Context, direccion string, atender func(net.Conn)) error {
	var lc net.ListenConfig
	oyente, err := lc.Listen(ctx, "tcp", direccion)
	if err != nil {
		return fmt.Errorf("escuchando en %s: %w", direccion, err)
	}
	defer oyente.Close()

	go func() {
		<-ctx.Done()
		oyente.Close()
	}()

	hueco := make(chan struct{}, maxSimultaneas)
	for {
		conn, err := oyente.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil // cierre ordenado
			}
			continue // un accept fallido no debe tumbar la trampa
		}

		select {
		case hueco <- struct{}{}:
		default:
			// Saturada: se corta en vez de crecer sin limite.
			conn.Close()
			continue
		}

		go func() {
			defer func() {
				conn.Close()
				<-hueco
				// Una trampa procesa datos de atacantes: un panico aqui
				// no puede llevarse por delante todo el proceso.
				recover()
			}()
			conn.SetDeadline(time.Now().Add(plazoLectura))
			atender(conn)
		}()
	}
}

// ipDe saca la direccion del atacante sin el puerto.
func ipDe(conn net.Conn) string {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return conn.RemoteAddr().String()
	}
	return host
}

// puertoDe extrae el puerto de una direccion de escucha, para poder decir
// a que servicio llamaron. "Conecta" a secas no distingue un sondeo del
// 6379 de uno del 21, y esa es justo la informacion que tiene un honeypot.
func puertoDe(direccion string) string {
	if _, puerto, err := net.SplitHostPort(direccion); err == nil {
		return puerto
	}
	return ""
}

// evento arma un evento ya normalizado.
func evento(honeypot, protocolo, ip string, tipo model.TipoEvento, detalle map[string]string) *model.Evento {
	return &model.Evento{
		Timestamp: time.Now().UTC(),
		Honeypot:  honeypot,
		Protocolo: protocolo,
		IP:        ip,
		Tipo:      tipo,
		Detalle:   detalle,
		// La clasificacion la pone el pipeline, no la trampa.
		Clasificacion: model.RuidoFondo,
	}
}

// Disponibles son todas las trampas que trae k0pot.
func Disponibles() []Trampa {
	return []Trampa{
		&HTTP{},
		&Redis{},
		&FTP{},
	}
}
