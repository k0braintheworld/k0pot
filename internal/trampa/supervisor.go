package trampa

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"
)

// Estado de una trampa para el panel.
type Estado struct {
	ID          string `json:"id"`
	Nombre      string `json:"nombre"`
	Descripcion string `json:"descripcion"`
	Puerto      int    `json:"puerto"`
	Activo      bool   `json:"activo"`
	Corriendo   bool   `json:"corriendo"`
	Error       string `json:"error,omitempty"`
}

// Deseado es lo que la configuracion pide para una trampa.
type Deseado struct {
	Activo bool
	Puerto int
}

// Supervisor arranca y para trampas segun cambia la configuracion, sin
// reiniciar el proceso: activar un servicio desde el panel tiene que
// funcionar en el acto.
type Supervisor struct {
	registrar Registrar

	mu        sync.Mutex
	corriendo map[string]*enMarcha
	ultimoErr map[string]string
}

type enMarcha struct {
	cancelar  context.CancelFunc
	direccion string
	puerto    int
	hecho     chan struct{}
}

func NuevoSupervisor(reg Registrar) *Supervisor {
	return &Supervisor{
		registrar: reg,
		corriendo: map[string]*enMarcha{},
		ultimoErr: map[string]string{},
	}
}

// Aplicar deja corriendo exactamente lo que pide la configuracion: arranca
// lo que falte, para lo que sobre y reinicia lo que cambio de puerto.
func (s *Supervisor) Aplicar(ctx context.Context, direccion string, deseado map[string]Deseado) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range Disponibles() {
		id := t.ID()
		quiero, hay := deseado[id]
		if !hay {
			quiero = Deseado{Activo: false, Puerto: t.PuertoPorDefecto()}
		}
		actual, enPie := s.corriendo[id]

		switch {
		case enPie && (!quiero.Activo || actual.puerto != quiero.Puerto ||
			actual.direccion != direccion):
			// Sobra, o cambio de puerto o de interfaz: se para (y se
			// volvera a arrancar abajo si toca). Comparar solo el puerto
			// dejaba la trampa atada a la interfaz vieja.
			actual.cancelar()
			<-actual.hecho
			delete(s.corriendo, id)
			log.Printf("trampa %s detenida", id)
			if !quiero.Activo {
				continue
			}
			fallthrough
		case !enPie && quiero.Activo:
			s.arrancar(ctx, t, direccion, quiero.Puerto)
		}
	}
}

// arrancar lanza una trampa. Se llama con el mutex tomado.
func (s *Supervisor) arrancar(ctx context.Context, t Trampa, direccion string, puerto int) {
	id := t.ID()
	hijo, cancelar := context.WithCancel(ctx)
	hecho := make(chan struct{})
	addr := net.JoinHostPort(direccion, fmt.Sprint(puerto))

	go func() {
		defer close(hecho)
		if err := t.Servir(hijo, addr, s.registrar); err != nil {
			s.mu.Lock()
			s.ultimoErr[id] = err.Error()
			delete(s.corriendo, id)
			s.mu.Unlock()
			log.Printf("trampa %s: %v", id, err)
			return
		}
	}()

	s.corriendo[id] = &enMarcha{cancelar: cancelar, direccion: direccion, puerto: puerto, hecho: hecho}
	delete(s.ultimoErr, id)
	log.Printf("trampa %s escuchando en %s", id, addr)
}

// Parar detiene todas las trampas.
func (s *Supervisor) Parar() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, m := range s.corriendo {
		m.cancelar()
		<-m.hecho
		delete(s.corriendo, id)
	}
}

// Estados describe todas las trampas para el panel.
func (s *Supervisor) Estados(deseado map[string]Deseado) []Estado {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []Estado
	for _, t := range Disponibles() {
		id := t.ID()
		q, hay := deseado[id]
		if !hay {
			q = Deseado{Puerto: t.PuertoPorDefecto()}
		}
		_, enPie := s.corriendo[id]
		out = append(out, Estado{
			ID:          id,
			Nombre:      t.Nombre(),
			Descripcion: t.Descripcion(),
			Puerto:      q.Puerto,
			Activo:      q.Activo,
			Corriendo:   enPie,
			Error:       s.ultimoErr[id],
		})
	}
	return out
}
