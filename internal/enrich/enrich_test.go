package enrich

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// Gastar cuota en direcciones que no existen en internet publico es tirar
// consultas de un presupuesto diario muy corto. En desarrollo, ademas,
// casi todo el trafico viene de la LAN.
func TestEsConsultable(t *testing.T) {
	casos := []struct {
		ip       string
		esperado bool
		porQue   string
	}{
		{"8.8.8.8", true, "publica"},
		{"1.1.1.1", true, "publica"},
		{"2606:4700::1111", true, "publica IPv6"},
		{"192.168.1.50", false, "LAN"},
		{"10.0.0.1", false, "privada"},
		{"172.16.0.1", false, "privada"},
		{"127.0.0.1", false, "loopback"},
		{"::1", false, "loopback IPv6"},
		{"169.254.1.1", false, "link-local"},
		{"100.64.0.1", false, "CGNAT"},
		{"192.0.2.5", false, "rango de documentacion"},
		{"no-es-una-ip", false, "invalida"},
		{"", false, "vacia"},
	}
	for _, c := range casos {
		if got := EsConsultable(c.ip); got != c.esperado {
			t.Errorf("EsConsultable(%q) = %v, esperaba %v (%s)",
				c.ip, got, c.esperado, c.porQue)
		}
	}
}

func TestNuloNoFalla(t *testing.T) {
	o, err := Nulo{}.Enriquecer(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("no esperaba error: %v", err)
	}
	if o.IP != "8.8.8.8" || o.Enriquecido {
		t.Errorf("origen = %+v", o)
	}
}

func servidorFalso(t *testing.T, manejador http.HandlerFunc) func() {
	t.Helper()
	srv := httptest.NewServer(manejador)
	anterior := URLAbuseIPDB
	URLAbuseIPDB = srv.URL
	return func() {
		URLAbuseIPDB = anterior
		srv.Close()
	}
}

func TestAbuseIPDBTraduceLaRespuesta(t *testing.T) {
	defer servidorFalso(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("ipAddress") != "185.220.101.1" {
			t.Errorf("ip consultada = %q", r.URL.Query().Get("ipAddress"))
		}
		if r.Header.Get("Key") != "clave-de-prueba" {
			t.Errorf("no se envio la clave de API")
		}
		w.Header().Set("X-RateLimit-Remaining", "742")
		w.Write([]byte(`{"data":{"ipAddress":"185.220.101.1",
		 "abuseConfidenceScore":100,"countryCode":"DE","isp":"Zwiebelfreunde",
		 "usageType":"Data Center/Web Hosting","isTor":true,"totalReports":1543}}`))
	})()

	a := NuevoAbuseIPDB("clave-de-prueba")
	o, err := a.Enriquecer(context.Background(), "185.220.101.1")
	if err != nil {
		t.Fatalf("no esperaba error: %v", err)
	}
	if o.Pais != "DE" || o.ISP != "Zwiebelfreunde" {
		t.Errorf("pais/isp = %q/%q", o.Pais, o.ISP)
	}
	if o.Reputacion != 100 || o.TotalReportes != 1543 || !o.Tor {
		t.Errorf("reputacion=%d reportes=%d tor=%v",
			o.Reputacion, o.TotalReportes, o.Tor)
	}
	if !o.Enriquecido || o.ConsultadoEn.IsZero() {
		t.Error("el origen deberia quedar marcado como enriquecido y fechado")
	}
	if a.Restantes() != 742 {
		t.Errorf("cuota leida = %d, esperaba 742", a.Restantes())
	}
}

// Al quedar poca cuota hay que dejar de preguntar por iniciativa propia,
// no esperar a que la API nos corte.
func TestAbuseIPDBSeAutolimitaAntesDeAgotarLaCuota(t *testing.T) {
	var llamadas int
	defer servidorFalso(t, func(w http.ResponseWriter, r *http.Request) {
		llamadas++
		w.Header().Set("X-RateLimit-Remaining", "3")
		w.Write([]byte(`{"data":{"countryCode":"US"}}`))
	})()

	a := NuevoAbuseIPDB("clave")
	a.Reserva = 10

	if _, err := a.Enriquecer(context.Background(), "8.8.8.8"); err != nil {
		t.Fatalf("la primera consulta deberia pasar: %v", err)
	}
	// Tras leer que solo quedan 3 (por debajo de la reserva de 10), no
	// deberia salir ni una peticion mas.
	for i := 0; i < 3; i++ {
		if _, err := a.Enriquecer(context.Background(), "1.1.1.1"); err != ErrSinCuota {
			t.Fatalf("consulta %d: err = %v, esperaba ErrSinCuota", i, err)
		}
	}
	if llamadas != 1 {
		t.Errorf("se hicieron %d llamadas, esperaba 1", llamadas)
	}
}

func TestAbuseIPDBRespeta429(t *testing.T) {
	var llamadas int
	defer servidorFalso(t, func(w http.ResponseWriter, r *http.Request) {
		llamadas++
		w.WriteHeader(http.StatusTooManyRequests)
	})()

	a := NuevoAbuseIPDB("clave")
	if _, err := a.Enriquecer(context.Background(), "8.8.8.8"); err != ErrSinCuota {
		t.Fatalf("err = %v, esperaba ErrSinCuota", err)
	}
	// Tras un 429 hay que parar, no insistir.
	if _, err := a.Enriquecer(context.Background(), "1.1.1.1"); err != ErrSinCuota {
		t.Fatalf("err = %v, esperaba ErrSinCuota", err)
	}
	if llamadas != 1 {
		t.Errorf("se hicieron %d llamadas tras el 429, esperaba 1", llamadas)
	}
}

func TestAbuseIPDBPropagaErroresDeLaAPI(t *testing.T) {
	defer servidorFalso(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"errors":[{"detail":"clave de API invalida"}]}`))
	})()

	a := NuevoAbuseIPDB("mala")
	if _, err := a.Enriquecer(context.Background(), "8.8.8.8"); err == nil {
		t.Fatal("esperaba error cuando la API informa de uno")
	}
}
