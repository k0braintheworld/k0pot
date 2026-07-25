package enrich

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// URLAbuseIPDB es el endpoint de consulta. Variable para poder apuntarlo
// a un servidor de pruebas en los tests.
var URLAbuseIPDB = "https://api.abuseipdb.com/api/v2/check"

// ErrSinCuota indica que se agoto el presupuesto diario de consultas.
// No es un fallo: el enriquecimiento se reanuda cuando la cuota se
// renueva, y mientras tanto se sigue capturando con normalidad.
var ErrSinCuota = errors.New("cuota de AbuseIPDB agotada")

// AbuseIPDB consulta la reputacion de una IP.
//
// El plan gratuito da 1000 consultas al dia, y un honeypot expuesto ve
// muchas mas IPs distintas que eso. Por, eso el cliente se autolimita:
// lee la cuota restante que la propia API informa en cada respuesta y
// deja de preguntar antes de agotarla, guardando un margen de reserva.
type AbuseIPDB struct {
	Clave   string
	Cliente *http.Client
	// Reserva son las consultas que nunca se gastan, para dejar margen a
	// una comprobacion manual o a una alerta urgente.
	Reserva int

	mu         sync.Mutex
	restantes  int // -1 mientras no lo sepamos
	pausaHasta time.Time
}

// NuevoAbuseIPDB crea el cliente con valores por defecto sensatos.
func NuevoAbuseIPDB(clave string) *AbuseIPDB {
	return &AbuseIPDB{
		Clave:     clave,
		Cliente:   &http.Client{Timeout: 10 * time.Second},
		Reserva:   25,
		restantes: -1,
	}
}

type respuestaAbuseIPDB struct {
	Data struct {
		IPAddress            string `json:"ipAddress"`
		AbuseConfidenceScore int    `json:"abuseConfidenceScore"`
		CountryCode          string `json:"countryCode"`
		UsageType            string `json:"usageType"`
		ISP                  string `json:"isp"`
		IsTor                bool   `json:"isTor"`
		TotalReports         int    `json:"totalReports"`
	} `json:"data"`
	Errors []struct {
		Detail string `json:"detail"`
	} `json:"errors"`
}

// Enriquecer consulta una IP. Devuelve ErrSinCuota si no queda margen.
func (a *AbuseIPDB) Enriquecer(ctx context.Context, ip string) (model.Origen, error) {
	if err := a.permitido(); err != nil {
		return model.Origen{IP: ip}, err
	}

	destino, _ := url.Parse(URLAbuseIPDB)
	q := destino.Query()
	q.Set("ipAddress", ip)
	q.Set("maxAgeInDays", "90")
	destino.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, destino.String(), nil)
	if err != nil {
		return model.Origen{IP: ip}, err
	}
	req.Header.Set("Key", a.Clave)
	req.Header.Set("Accept", "application/json")

	resp, err := a.Cliente.Do(req)
	if err != nil {
		return model.Origen{IP: ip}, fmt.Errorf("consultando %s: %w", ip, err)
	}
	defer resp.Body.Close()

	a.anotarCuota(resp)

	if resp.StatusCode == http.StatusTooManyRequests {
		// La API nos corta: paramos hasta mañana en vez de insistir.
		a.pausar(24 * time.Hour)
		return model.Origen{IP: ip}, ErrSinCuota
	}
	if resp.StatusCode != http.StatusOK {
		return model.Origen{IP: ip}, fmt.Errorf("AbuseIPDB devolvio %s para %s",
			resp.Status, ip)
	}

	var r respuestaAbuseIPDB
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return model.Origen{IP: ip}, fmt.Errorf("respuesta ilegible: %w", err)
	}
	if len(r.Errors) > 0 {
		return model.Origen{IP: ip}, fmt.Errorf("AbuseIPDB: %s", r.Errors[0].Detail)
	}

	return model.Origen{
		IP:            ip,
		Pais:          r.Data.CountryCode,
		ISP:           r.Data.ISP,
		TipoUso:       r.Data.UsageType,
		Reputacion:    r.Data.AbuseConfidenceScore,
		TotalReportes: r.Data.TotalReports,
		Tor:           r.Data.IsTor,
		Enriquecido:   true,
		ConsultadoEn:  time.Now().UTC(),
	}, nil
}

// permitido comprueba que quede cuota y que no estemos en pausa.
func (a *AbuseIPDB) permitido() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if time.Now().Before(a.pausaHasta) {
		return ErrSinCuota
	}
	if a.restantes >= 0 && a.restantes <= a.Reserva {
		return ErrSinCuota
	}
	return nil
}

// anotarCuota guarda lo que la API dice que nos queda.
func (a *AbuseIPDB) anotarCuota(resp *http.Response) {
	v := resp.Header.Get("X-RateLimit-Remaining")
	if v == "" {
		return
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return
	}
	a.mu.Lock()
	a.restantes = n
	a.mu.Unlock()
}

func (a *AbuseIPDB) pausar(d time.Duration) {
	a.mu.Lock()
	a.pausaHasta = time.Now().Add(d)
	a.mu.Unlock()
}

// Restantes informa de la cuota conocida (-1 si aun no se ha consultado).
func (a *AbuseIPDB) Restantes() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.restantes
}


// URLReporteAbuseIPDB es el endpoint de denuncia. Variable para los tests.
var URLReporteAbuseIPDB = "https://api.abuseipdb.com/api/v2/report"

// ReportarAbuseIPDB denuncia una IP atacante para contribuir al feed
// comunitario. categorias son los codigos de AbuseIPDB (18=fuerza bruta,
// 15=hacking, 20=host comprometido). Es una PUBLICACION: la lanza el usuario a
// mano, nunca sola.
func ReportarAbuseIPDB(ctx context.Context, cliente *http.Client, clave, ip, categorias, comentario string) error {
	if clave == "" {
		return fmt.Errorf("sin clave de AbuseIPDB")
	}
	if cliente == nil {
		cliente = &http.Client{Timeout: 10 * time.Second}
	}
	datos := url.Values{}
	datos.Set("ip", ip)
	datos.Set("categories", categorias)
	if comentario != "" {
		datos.Set("comment", comentario)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, URLReporteAbuseIPDB,
		strings.NewReader(datos.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Key", clave)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := cliente.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusTooManyRequests {
		return fmt.Errorf("limite de reportes de AbuseIPDB alcanzado")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("AbuseIPDB respondio %d", resp.StatusCode)
	}
	return nil
}
