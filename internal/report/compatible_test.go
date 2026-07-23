package report

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func compatibleCon(t *testing.T, h http.HandlerFunc) *ConCompatible {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return &ConCompatible{
		Cliente:  srv.Client(),
		URLBase:  srv.URL,
		Clave:    "clave-de-prueba",
		Modelo:   "modelo-de-prueba",
		Respaldo: PorReglas{},
		Plazo:    5 * time.Second,
	}
}

func respuesta(texto string) string {
	b, _ := json.Marshal(map[string]any{
		"choices": []map[string]any{{"message": map[string]string{
			"role": "assistant", "content": texto,
		}}},
	})
	return string(b)
}

func TestCompatibleDevuelveElTexto(t *testing.T) {
	g := compatibleCon(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("ruta = %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer clave-de-prueba" {
			t.Error("no se envio la clave como Bearer")
		}
		var p peticionChat
		json.NewDecoder(r.Body).Decode(&p)
		if p.Modelo != "modelo-de-prueba" || len(p.Mensajes) != 2 {
			t.Errorf("peticion = %+v", p)
		}
		if p.Mensajes[0].Rol != "system" || p.Mensajes[1].Rol != "user" {
			t.Errorf("roles = %q/%q", p.Mensajes[0].Rol, p.Mensajes[1].Rol)
		}
		io.WriteString(w, respuesta("Esta semana no ha pasado nada preocupante."))
	})

	res, err := g.Generar(context.Background(), datosDePrueba())
	if err != nil {
		t.Fatal(err)
	}
	if res.Texto != "Esta semana no ha pasado nada preocupante." {
		t.Errorf("texto = %q", res.Texto)
	}
	if !strings.Contains(res.Redactado, "modelo-de-prueba") {
		t.Errorf("firma = %q, esperaba que citara el modelo", res.Redactado)
	}
}

// Los modelos de razonamiento (qwen3, deepseek-r1) vuelcan su deliberacion
// entre <think>...</think> en el mismo campo que la respuesta. Sin quitarla,
// el informe sale con parrafos en ingles explicando como se va a redactar.
func TestCompatibleQuitaLaCadenaDeRazonamiento(t *testing.T) {
	casos := []struct{ nombre, bruto, espera string }{
		{"bloque cerrado",
			"<think>Let me plan the report...</think>\nHay algo que mirar.",
			"Hay algo que mirar."},
		{"con mayusculas",
			"<THINK>reasoning</THINK>Informe limpio.",
			"Informe limpio."},
		{"varios bloques",
			"<think>a</think>Primero.<think>b</think> Segundo.",
			"Primero. Segundo."},
		{"sin cerrar (respuesta truncada)",
			"Texto util.<think>y aqui se corto por max_tokens",
			"Texto util."},
		{"sin razonamiento",
			"Informe normal y corriente.",
			"Informe normal y corriente."},
	}
	for _, c := range casos {
		if got := limpiarRazonamiento(c.bruto); got != c.espera {
			t.Errorf("%s: %q -> %q, esperaba %q", c.nombre, c.bruto, got, c.espera)
		}
	}
}

// Si tras quitar el razonamiento no queda nada, mejor un informe por reglas
// que uno vacio.
func TestCompatibleSoloRazonamientoCaeEnReglas(t *testing.T) {
	g := compatibleCon(t, func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, respuesta("<think>me quede pensando y no dije nada"))
	})

	res, err := g.Generar(context.Background(), datosDePrueba())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Texto, "ROJO") {
		t.Errorf("no se genero el informe de respaldo:\n%s", res.Texto)
	}
	if !strings.HasPrefix(res.Redactado, "reglas") {
		t.Errorf("firma = %q, esperaba que dijera que fueron las reglas", res.Redactado)
	}
}

// Ante cualquier fallo del proveedor, el informe se entrega igual.
func TestCompatibleCaeEnReglasSiFallaElProveedor(t *testing.T) {
	casos := map[string]http.HandlerFunc{
		"401": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(401)
			io.WriteString(w, `{"error":{"message":"Invalid API Key"}}`)
		},
		"429": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(429)
			io.WriteString(w, `{"error":{"message":"Rate limit reached"}}`)
		},
		"500": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		"json roto": func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, "esto no es json")
		},
		"sin opciones": func(w http.ResponseWriter, r *http.Request) {
			io.WriteString(w, `{"choices":[]}`)
		},
	}
	for nombre, h := range casos {
		g := compatibleCon(t, h)
		res, err := g.Generar(context.Background(), datosDePrueba())
		if err != nil {
			t.Errorf("%s: no deberia propagar el error: %v", nombre, err)
			continue
		}
		if !strings.Contains(res.Texto, "ROJO") {
			t.Errorf("%s: no se genero el informe de respaldo", nombre)
		}
		if !strings.HasPrefix(res.Redactado, "reglas") {
			t.Errorf("%s: firma = %q", nombre, res.Redactado)
		}
	}
}

func TestCompatibleNoLlamaSinActividad(t *testing.T) {
	var llamadas int
	g := compatibleCon(t, func(w http.ResponseWriter, r *http.Request) {
		llamadas++
		io.WriteString(w, respuesta("no deberia llegar aqui"))
	})

	if _, err := g.Generar(context.Background(), datosVacios()); err != nil {
		t.Fatal(err)
	}
	if llamadas != 0 {
		t.Errorf("se hicieron %d llamadas sin datos que resumir", llamadas)
	}
}

// La firma dice de que servidor salio el informe, sin soltar la URL entera.
func TestNombreCitaModeloYServidor(t *testing.T) {
	g := NuevoCompatible("https://api.groq.com/openai/v1", "clave", "llama-3.3-70b")
	n := g.Nombre()
	if !strings.Contains(n, "llama-3.3-70b") || !strings.Contains(n, "api.groq.com") {
		t.Errorf("nombre = %q", n)
	}
	if strings.Contains(n, "clave") || strings.Contains(n, "/openai/v1") {
		t.Errorf("el nombre filtra detalles: %q", n)
	}
}

func TestURLBaseVaciaUsaGroq(t *testing.T) {
	if g := NuevoCompatible("", "clave", "m"); g.URLBase != URLBaseGroq {
		t.Errorf("URLBase = %q", g.URLBase)
	}
	// La barra final sobra: se concatena la ruta despues.
	if g := NuevoCompatible("https://x.example/v1/", "clave", "m"); g.URLBase != "https://x.example/v1" {
		t.Errorf("URLBase = %q", g.URLBase)
	}
}
