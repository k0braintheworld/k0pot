// Package geoip situa una IP en el mapa con precision de ciudad.
//
// AbuseIPDB solo da el pais, asi que las lineas de ataque salian del centro
// del pais: cientos de kilometros de imprecision, y todas las IP de un mismo
// pais amontonadas en el mismo punto. Con una base GeoLite2-City de MaxMind
// -un fichero local, sin llamadas a terceros ni limites- cada IP se situa en
// su ciudad.
//
// Es opcional a proposito: si no hay fichero, no pasa nada y se cae al pais,
// que es lo que habia. Nadie tiene que descargar nada para que k0Pot
// funcione; quien quiera el detalle de ciudad, deja el .mmdb en su sitio.
package geoip

import (
	"fmt"
	"net"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// Lugar es donde esta una IP, hasta donde se sabe.
type Lugar struct {
	Pais     string // codigo ISO, "NL"
	Ciudad   string // "Amsterdam", si consta
	Latitud  float64
	Longitud float64
}

// TieneCoordenadas dice si la ubicacion es utilizable para el mapa. El (0,0)
// es la isla Null en el golfo de Guinea, no una ciudad: se trata como
// "desconocido".
func (l Lugar) TieneCoordenadas() bool {
	return l.Latitud != 0 || l.Longitud != 0
}

// Localizador resuelve IPs contra una base GeoLite2. Es seguro de usar desde
// varias goroutines.
type Localizador struct {
	mu sync.RWMutex
	bd *maxminddb.Reader
}

// registro es lo que se lee del .mmdb. Solo se piden los campos que se usan,
// para no decodificar el resto.
type registro struct {
	Ciudad struct {
		Nombres map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Pais struct {
		ISO string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	Ubicacion struct {
		Latitud  float64 `maxminddb:"latitude"`
		Longitud float64 `maxminddb:"longitude"`
	} `maxminddb:"location"`
}

// Abrir carga la base del fichero indicado. Ruta vacia devuelve un
// Localizador inactivo: no es un error, es no tener geolocalizacion de
// ciudad, y k0Pot funciona igual.
func Abrir(ruta string) (*Localizador, error) {
	if ruta == "" {
		return &Localizador{}, nil
	}
	bd, err := maxminddb.Open(ruta)
	if err != nil {
		return nil, fmt.Errorf("abriendo la base GeoIP %s: %w", ruta, err)
	}
	return &Localizador{bd: bd}, nil
}

// Activo dice si hay una base cargada.
func (l *Localizador) Activo() bool {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.bd != nil
}

// Recargar cambia la base en caliente, para poder actualizar el fichero sin
// reiniciar. Ruta vacia la desactiva.
func (l *Localizador) Recargar(ruta string) error {
	nueva, err := Abrir(ruta)
	if err != nil {
		return err
	}
	l.mu.Lock()
	anterior := l.bd
	l.bd = nueva.bd
	l.mu.Unlock()
	if anterior != nil {
		anterior.Close()
	}
	return nil
}

// Situar busca una IP. Devuelve el lugar y si se encontro algo.
func (l *Localizador) Situar(ip string) (Lugar, bool) {
	l.mu.RLock()
	bd := l.bd
	l.mu.RUnlock()
	if bd == nil {
		return Lugar{}, false
	}

	dir := net.ParseIP(ip)
	if dir == nil {
		return Lugar{}, false
	}

	var r registro
	if err := bd.Lookup(dir, &r); err != nil {
		return Lugar{}, false
	}

	lugar := Lugar{
		Pais:     r.Pais.ISO,
		Latitud:  r.Ubicacion.Latitud,
		Longitud: r.Ubicacion.Longitud,
	}
	// El nombre de la ciudad en espanol si esta, si no en ingles: es lo que
	// trae siempre GeoLite2.
	if n := r.Ciudad.Nombres["es"]; n != "" {
		lugar.Ciudad = n
	} else {
		lugar.Ciudad = r.Ciudad.Nombres["en"]
	}
	return lugar, lugar.Pais != "" || lugar.TieneCoordenadas()
}

// Cerrar libera la base.
func (l *Localizador) Cerrar() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.bd != nil {
		err := l.bd.Close()
		l.bd = nil
		return err
	}
	return nil
}
