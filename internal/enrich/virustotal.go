package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

// URLVirusTotal es el endpoint de consulta por hash. Variable para los tests.
var URLVirusTotal = "https://www.virustotal.com/api/v3/files/"

// VeredictoVT resume lo que VirusTotal sabe de un fichero, consultado por su
// hash: NUNCA se sube la muestra, solo se pregunta si ya la conocen.
type VeredictoVT struct {
	Conocido   bool   `json:"conocido"`
	Maliciosos int    `json:"maliciosos"`
	Total      int    `json:"total"`
	Etiqueta   string `json:"etiqueta,omitempty"`
}

type vtEntrada struct {
	v      VeredictoVT
	err    error
	cuando time.Time
}

var (
	vtMu    sync.Mutex
	vtCache = map[string]vtEntrada{}
)

const vtTTL = 12 * time.Hour

// VirusTotal pregunta por el hash y cachea el resultado unas horas: el
// veredicto de una muestra no cambia de un rato para otro y la cuota gratuita
// es limitada (4 consultas/min, 500/dia).
func VirusTotal(ctx context.Context, cliente *http.Client, clave, sha256 string) (VeredictoVT, error) {
	if clave == "" {
		return VeredictoVT{}, fmt.Errorf("sin clave de VirusTotal")
	}
	vtMu.Lock()
	if e, ok := vtCache[sha256]; ok && time.Since(e.cuando) < vtTTL {
		vtMu.Unlock()
		return e.v, e.err
	}
	vtMu.Unlock()

	v, err := consultarVT(ctx, cliente, clave, sha256)
	// Los errores de red no se cachean: pueden ser transitorios.
	if err == nil {
		vtMu.Lock()
		vtCache[sha256] = vtEntrada{v: v, cuando: time.Now()}
		vtMu.Unlock()
	}
	return v, err
}

func consultarVT(ctx context.Context, cliente *http.Client, clave, sha256 string) (VeredictoVT, error) {
	if cliente == nil {
		cliente = &http.Client{Timeout: 9 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, URLVirusTotal+sha256, nil)
	if err != nil {
		return VeredictoVT{}, err
	}
	req.Header.Set("x-apikey", clave)
	resp, err := cliente.Do(req)
	if err != nil {
		return VeredictoVT{}, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusNotFound:
		return VeredictoVT{Conocido: false}, nil // no lo tienen: no es un fallo
	case http.StatusUnauthorized:
		return VeredictoVT{}, fmt.Errorf("la clave de VirusTotal no es valida")
	case http.StatusTooManyRequests:
		return VeredictoVT{}, fmt.Errorf("cuota de VirusTotal agotada por ahora")
	case http.StatusOK:
		// seguimos
	default:
		return VeredictoVT{}, fmt.Errorf("VirusTotal respondio %d", resp.StatusCode)
	}

	var cuerpo struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
					Timeout    int `json:"timeout"`
				} `json:"last_analysis_stats"`
				PopularThreatClassification struct {
					SuggestedThreatLabel string `json:"suggested_threat_label"`
				} `json:"popular_threat_classification"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cuerpo); err != nil {
		return VeredictoVT{}, err
	}
	st := cuerpo.Data.Attributes.LastAnalysisStats
	total := st.Malicious + st.Suspicious + st.Harmless + st.Undetected + st.Timeout
	return VeredictoVT{
		Conocido:   true,
		Maliciosos: st.Malicious + st.Suspicious,
		Total:      total,
		Etiqueta:   cuerpo.Data.Attributes.PopularThreatClassification.SuggestedThreatLabel,
	}, nil
}
