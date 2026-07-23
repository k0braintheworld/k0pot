// Package enrich averigua quien hay detras de una IP: pais, proveedor y
// reputacion. Es lo que convierte "10.2.3.4 intento entrar" en "un bot
// alojado en un centro de datos de Vietnam, ya denunciado 300 veces".
package enrich

import (
	"context"
	"net"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// Enriquecedor resuelve los datos de una IP.
type Enriquecedor interface {
	Enriquecer(ctx context.Context, ip string) (model.Origen, error)
}

// Nulo no consulta nada. Permite que honey funcione sin conexion ni clave
// de API: se sigue capturando y clasificando, solo falta el contexto.
type Nulo struct{}

func (Nulo) Enriquecer(_ context.Context, ip string) (model.Origen, error) {
	return model.Origen{IP: ip}, nil
}

// EsConsultable dice si tiene sentido gastar cuota de API en una IP.
//
// Las privadas, de loopback, link-local y demas rangos reservados no
// existen en internet: preguntarlas es tirar peticiones de un presupuesto
// diario que es corto. En desarrollo casi todo el trafico es de estas.
func EsConsultable(ip string) bool {
	dir := net.ParseIP(ip)
	if dir == nil {
		return false
	}
	if dir.IsLoopback() || dir.IsPrivate() ||
		dir.IsLinkLocalUnicast() || dir.IsLinkLocalMulticast() ||
		dir.IsUnspecified() || dir.IsMulticast() {
		return false
	}
	// Rango de tests de la RFC 5737 y CGNAT de la RFC 6598: tampoco son
	// direcciones de internet publico.
	for _, cidr := range reservados {
		if cidr.Contains(dir) {
			return false
		}
	}
	return true
}

var reservados = func() []*net.IPNet {
	rangos := []string{
		"192.0.2.0/24",    // TEST-NET-1
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"100.64.0.0/10",   // CGNAT
		"198.18.0.0/15",   // pruebas de rendimiento
	}
	var out []*net.IPNet
	for _, r := range rangos {
		if _, red, err := net.ParseCIDR(r); err == nil {
			out = append(out, red)
		}
	}
	return out
}()
