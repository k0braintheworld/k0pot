package web

import (
	"sync"
	"time"

	"github.com/k0braintheworld/k0pot/internal/report"
)

// El resumen del panel (/api/estado) es, con diferencia, lo mas caro que se
// sirve: media docena de agregaciones sobre la tabla de eventos que, con
// cientos de miles de filas, tardan varios segundos. El panel lo pide al
// cargar y en cada refresco (cada 20 s), y como la base va por una sola
// conexion, mientras ese resumen se calcula TODO lo demas que pide el panel
// espera detras. El resultado es un panel que "no termina de cargar".
//
// La salida cambia despacio -importa el patron de horas y dias, no el segundo
// exacto-, asi que se cachea: el primer visitante de un rango paga el calculo
// una vez, y desde ahi se sirve de memoria al instante mientras un refresco en
// segundo plano lo mantiene al dia.

const (
	frescuraEstado = 90 * time.Second
)

type entradaEstado struct {
	datos       Estado
	calculado   time.Time
	refrescando bool
}

type cacheEstado struct {
	mu       sync.Mutex
	porRango map[int]*entradaEstado
}

// IniciarCacheEstado precalienta el rango por defecto y deja un refresco de
// fondo que mantiene frescos los rangos que se hayan llegado a pedir.
func (s *Servidor) IniciarCacheEstado() {
	s.estadoCache.porRango = map[int]*entradaEstado{}
	// El calentado va en segundo plano: abrir el puerto NUNCA debe esperar a
	// una consulta pesada. Hasta que termine, el handler calcula el rango en
	// frio la primera vez que se pide.
	go func() {
		if d, err := s.calcularEstado(1); err == nil {
			s.estadoCache.mu.Lock()
			s.estadoCache.porRango[1] = &entradaEstado{datos: d, calculado: time.Now()}
			s.estadoCache.mu.Unlock()
		}
	}()
}

// refrescarEnFondo recalcula un rango sin bloquear la peticion, con un cerrojo
// por rango para que no se solapen varios refrescos del mismo.
func (s *Servidor) refrescarEnFondo(d int) {
	s.estadoCache.mu.Lock()
	e := s.estadoCache.porRango[d]
	if e == nil || e.refrescando {
		s.estadoCache.mu.Unlock()
		return
	}
	e.refrescando = true
	s.estadoCache.mu.Unlock()

	go func() {
		datos, err := s.calcularEstado(d)
		s.estadoCache.mu.Lock()
		defer s.estadoCache.mu.Unlock()
		if err != nil {
			// Se conserva lo viejo y se suelta el cerrojo: se reintenta al
			// proximo refresco.
			if actual := s.estadoCache.porRango[d]; actual != nil {
				actual.refrescando = false
			}
			return
		}
		s.estadoCache.porRango[d] = &entradaEstado{datos: datos, calculado: time.Now()}
	}()
}

// calcularEstado arma el resumen del panel para un rango de dias. Es lo que
// antes hacia el handler en linea; ahora vive aqui para poder cachearlo.
func (s *Servidor) calcularEstado(d int) (Estado, error) {
	desde := time.Now().AddDate(0, 0, -d)

	resumen, err := s.Almacen.Resumir(desde)
	if err != nil {
		return Estado{}, err
	}
	niveles, err := s.Almacen.PorClasificacion(desde)
	if err != nil {
		return Estado{}, err
	}
	// Reparto de los ATAQUES por gravedad, para la grafica.
	severidades, err := s.Almacen.EpisodiosDesde(desde)
	if err != nil {
		return Estado{}, err
	}
	// Reparto de ataques por servicio, para el semaforo.
	porServicio, err := s.Almacen.AtaquesPorServicio(desde)
	if err != nil {
		return Estado{}, err
	}

	return Estado{
		Severidades:  severidades,
		PorServicio:  porServicio,
		Nivel:        report.NivelDeAtaques(severidades),
		PaisPropio:   s.Config.Actual().PaisPropio,
		Latitud:      s.Config.Actual().LatitudPropia,
		Longitud:     s.Config.Actual().LongitudPropia,
		Frase:        report.FraseSemaforoAtaques(severidades),
		Dias:         d,
		Total:        resumen.Total,
		IPsUnicas:    resumen.IPsUnicas,
		Niveles:      niveles,
		PorTipo:      resumen.PorTipo,
		PorPais:      resumen.PorPais,
		TopIPs:       resumen.TopIPs,
		TopUsuarios:  resumen.TopUsuarios,
		TopPasswords: resumen.TopPasswords,
		Primero:      resumen.Primero,
		Ultimo:       resumen.Ultimo,
	}, nil
}
