package store

import (
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
)

func almacenTemporal(t *testing.T) *Store {
	t.Helper()
	s, err := Abrir(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("abriendo almacen: %v", err)
	}
	t.Cleanup(func() { s.Cerrar() })
	return s
}

func evento(id, ip, usuario string) *model.Evento {
	return &model.Evento{
		IDExterno:     id,
		Timestamp:     time.Now().UTC(),
		Honeypot:      "cowrie",
		Protocolo:     "ssh",
		IP:            ip,
		Tipo:          model.LoginFallido,
		Detalle:       map[string]string{"usuario": usuario, "password": "123456"},
		Clasificacion: model.RuidoFondo,
	}
}

func TestGuardarYResumir(t *testing.T) {
	s := almacenTemporal(t)

	for _, e := range []*model.Evento{
		evento("a", "10.0.0.1", "root"),
		evento("b", "10.0.0.1", "root"),
		evento("c", "10.0.0.2", "admin"),
	} {
		nuevo, err := s.Guardar(e)
		if err != nil {
			t.Fatalf("guardando: %v", err)
		}
		if !nuevo {
			t.Errorf("evento %s deberia ser nuevo", e.IDExterno)
		}
	}

	r, err := s.Resumir(time.Now().AddDate(0, 0, -1))
	if err != nil {
		t.Fatalf("resumiendo: %v", err)
	}
	if r.Total != 3 {
		t.Errorf("total = %d, esperaba 3", r.Total)
	}
	if r.IPsUnicas != 2 {
		t.Errorf("ips unicas = %d, esperaba 2", r.IPsUnicas)
	}
	if len(r.TopIPs) == 0 || r.TopIPs[0].IP != "10.0.0.1" || r.TopIPs[0].Eventos != 2 {
		t.Errorf("top ips = %+v", r.TopIPs)
	}
	if len(r.TopUsuarios) == 0 || r.TopUsuarios[0].Valor != "root" {
		t.Errorf("top usuarios = %v", r.TopUsuarios)
	}
}

// La ingesta relee el log desde el principio en cada arranque, asi que
// reinsertar un evento ya visto tiene que ser inofensivo.
func TestGuardarEsIdempotente(t *testing.T) {
	s := almacenTemporal(t)

	if nuevo, err := s.Guardar(evento("mismo-id", "10.0.0.1", "root")); err != nil || !nuevo {
		t.Fatalf("primera insercion: nuevo=%v err=%v", nuevo, err)
	}
	nuevo, err := s.Guardar(evento("mismo-id", "10.0.0.1", "root"))
	if err != nil {
		t.Fatalf("segunda insercion: %v", err)
	}
	if nuevo {
		t.Error("el duplicado se inserto: la ingesta no es idempotente")
	}

	r, _ := s.Resumir(time.Now().AddDate(0, 0, -1))
	if r.Total != 1 {
		t.Errorf("total = %d, esperaba 1", r.Total)
	}
}

// Los eventos sin id externo no deben bloquearse entre si por la
// restriccion UNIQUE (en SQLite varios NULL conviven).
func TestEventosSinIDExternoConviven(t *testing.T) {
	s := almacenTemporal(t)

	for i := 0; i < 3; i++ {
		nuevo, err := s.Guardar(evento("", "10.0.0.1", "root"))
		if err != nil {
			t.Fatalf("guardando sin id: %v", err)
		}
		if !nuevo {
			t.Fatalf("insercion %d rechazada: los NULL estan colisionando", i)
		}
	}
	r, _ := s.Resumir(time.Now().AddDate(0, 0, -1))
	if r.Total != 3 {
		t.Errorf("total = %d, esperaba 3", r.Total)
	}
}

func TestResumirSinDatos(t *testing.T) {
	s := almacenTemporal(t)
	r, err := s.Resumir(time.Now().AddDate(0, 0, -1))
	if err != nil {
		t.Fatalf("resumiendo vacio: %v", err)
	}
	if r.Total != 0 {
		t.Errorf("total = %d, esperaba 0", r.Total)
	}
}

// Un evento antiguo no debe aparecer en el resumen de hoy.
func TestResumirFiltraPorFecha(t *testing.T) {
	s := almacenTemporal(t)

	viejo := evento("viejo", "10.0.0.1", "root")
	viejo.Timestamp = time.Now().UTC().AddDate(0, 0, -10)
	if _, err := s.Guardar(viejo); err != nil {
		t.Fatalf("guardando: %v", err)
	}
	if _, err := s.Guardar(evento("nuevo", "10.0.0.2", "admin")); err != nil {
		t.Fatalf("guardando: %v", err)
	}

	r, err := s.Resumir(time.Now().AddDate(0, 0, -1))
	if err != nil {
		t.Fatalf("resumiendo: %v", err)
	}
	if r.Total != 1 {
		t.Errorf("total = %d, esperaba 1 (el de hace 10 dias sobra)", r.Total)
	}
}

func origen(ip, pais string, reputacion int) model.Origen {
	return model.Origen{
		IP: ip, Pais: pais, ISP: "Ejemplo SA",
		TipoUso: "Data Center/Web Hosting", Reputacion: reputacion,
		TotalReportes: reputacion * 3, Enriquecido: true,
		ConsultadoEn: time.Now().UTC(),
	}
}

func TestOrigenSeUneAlResumen(t *testing.T) {
	s := almacenTemporal(t)

	if _, err := s.Guardar(evento("a", "185.220.101.1", "root")); err != nil {
		t.Fatal(err)
	}
	if err := s.GuardarOrigen(origen("185.220.101.1", "DE", 100)); err != nil {
		t.Fatalf("guardando origen: %v", err)
	}

	r, err := s.Resumir(time.Now().AddDate(0, 0, -1))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.TopIPs) != 1 {
		t.Fatalf("top ips = %+v", r.TopIPs)
	}
	ip := r.TopIPs[0]
	if ip.Pais != "DE" || ip.Reputacion != 100 || !ip.Enriquecido {
		t.Errorf("la IP no llego enriquecida: %+v", ip)
	}
	if len(r.PorPais) != 1 || r.PorPais[0].Valor != "DE" {
		t.Errorf("por pais = %v", r.PorPais)
	}
}

// Una IP vista pero aun no consultada tiene que aparecer en el resumen
// igualmente, solo que sin contexto.
func TestIPSinEnriquecerSigueApareciendo(t *testing.T) {
	s := almacenTemporal(t)
	if _, err := s.Guardar(evento("a", "1.2.3.4", "root")); err != nil {
		t.Fatal(err)
	}

	r, err := s.Resumir(time.Now().AddDate(0, 0, -1))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.TopIPs) != 1 {
		t.Fatalf("top ips = %+v", r.TopIPs)
	}
	if r.TopIPs[0].Enriquecido {
		t.Error("la IP no se ha consultado, no deberia figurar como enriquecida")
	}
}

func TestGuardarOrigenRefrescaElDatoAnterior(t *testing.T) {
	s := almacenTemporal(t)
	if err := s.GuardarOrigen(origen("1.2.3.4", "US", 10)); err != nil {
		t.Fatal(err)
	}
	if err := s.GuardarOrigen(origen("1.2.3.4", "CN", 90)); err != nil {
		t.Fatalf("refrescando: %v", err)
	}

	if _, err := s.Guardar(evento("a", "1.2.3.4", "root")); err != nil {
		t.Fatal(err)
	}
	r, _ := s.Resumir(time.Now().AddDate(0, 0, -1))
	if r.TopIPs[0].Pais != "CN" || r.TopIPs[0].Reputacion != 90 {
		t.Errorf("no se refresco: %+v", r.TopIPs[0])
	}
}

func TestIPsPendientes(t *testing.T) {
	s := almacenTemporal(t)

	// 1.1.1.1 con 3 eventos, 2.2.2.2 con 1: la mas activa va primero,
	// porque si la cuota diaria no da para todas debe gastarse ahi.
	for i, ip := range []string{"1.1.1.1", "1.1.1.1", "1.1.1.1", "2.2.2.2"} {
		if _, err := s.Guardar(evento(string(rune('a'+i)), ip, "root")); err != nil {
			t.Fatal(err)
		}
	}

	ips, err := s.IPsPendientes(7*24*time.Hour, 10)
	if err != nil {
		t.Fatalf("ips pendientes: %v", err)
	}
	if len(ips) != 2 || ips[0] != "1.1.1.1" {
		t.Fatalf("pendientes = %v, esperaba la mas activa primero", ips)
	}

	// Una vez consultada, deja de estar pendiente.
	if err := s.GuardarOrigen(origen("1.1.1.1", "AU", 0)); err != nil {
		t.Fatal(err)
	}
	ips, err = s.IPsPendientes(7*24*time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 || ips[0] != "2.2.2.2" {
		t.Errorf("pendientes = %v, esperaba solo 2.2.2.2", ips)
	}
}

// Un dato de reputacion viejo hay que volver a preguntarlo: una IP limpia
// hoy puede estar comprometida la semana que viene.
func TestIPsPendientesReconsultaLoCaducado(t *testing.T) {
	s := almacenTemporal(t)
	if _, err := s.Guardar(evento("a", "1.1.1.1", "root")); err != nil {
		t.Fatal(err)
	}

	viejo := origen("1.1.1.1", "AU", 0)
	viejo.ConsultadoEn = time.Now().UTC().AddDate(0, 0, -30)
	if err := s.GuardarOrigen(viejo); err != nil {
		t.Fatal(err)
	}

	ips, err := s.IPsPendientes(7*24*time.Hour, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 1 {
		t.Errorf("pendientes = %v, esperaba que el dato de hace 30 dias caducara", ips)
	}
}

// La ingesta y el enriquecimiento escriben a la vez desde goroutines
// distintas. Si los PRAGMA se aplican solo a una conexion del pool, el
// resto se queda sin busy_timeout y esto revienta con SQLITE_BUSY.
func TestEscriturasConcurrentes(t *testing.T) {
	s := almacenTemporal(t)

	var grupo sync.WaitGroup
	fallos := make(chan error, 2)

	grupo.Add(2)
	go func() {
		defer grupo.Done()
		for i := 0; i < 200; i++ {
			e := evento(fmt.Sprintf("ev-%d", i), "1.2.3.4", "root")
			if _, err := s.Guardar(e); err != nil {
				fallos <- fmt.Errorf("ingesta: %w", err)
				return
			}
		}
	}()
	go func() {
		defer grupo.Done()
		for i := 0; i < 200; i++ {
			o := origen(fmt.Sprintf("5.6.7.%d", i%256), "ES", i%101)
			if err := s.GuardarOrigen(o); err != nil {
				fallos <- fmt.Errorf("enriquecimiento: %w", err)
				return
			}
		}
	}()

	grupo.Wait()
	close(fallos)
	for err := range fallos {
		t.Error(err)
	}
}
