package report

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// ConCompatible redacta el informe contra cualquier API que hable el
// formato de OpenAI: Groq, OpenRouter, Mistral, Together, Ollama...
//
// Es una sola implementacion para muchos proveedores porque todos exponen
// el mismo POST /chat/completions. Cambiar de uno a otro es cambiar la URL
// base, el modelo y la clave, sin tocar codigo.
//
// Igual que ConLLM, ante cualquier fallo se repliega en PorReglas: un
// informe mas seco siempre es mejor que ningun informe.
type ConCompatible struct {
	Cliente  *http.Client
	URLBase  string
	Clave    string
	Modelo   string
	Respaldo Generador
	Plazo    time.Duration
}

// URLBaseGroq es el proveedor gratuito de referencia.
const URLBaseGroq = "https://api.groq.com/openai/v1"

// NuevoCompatible crea el generador con valores sensatos.
func NuevoCompatible(urlBase, clave, modelo string) *ConCompatible {
	if urlBase == "" {
		urlBase = URLBaseGroq
	}
	return &ConCompatible{
		Cliente:  &http.Client{Timeout: 90 * time.Second},
		URLBase:  strings.TrimRight(urlBase, "/"),
		Clave:    clave,
		Modelo:   modelo,
		Respaldo: PorReglas{},
		Plazo:    2 * time.Minute,
	}
}

func (c *ConCompatible) Nombre() string {
	return fmt.Sprintf("%s (%s)", c.Modelo, servidorDe(c.URLBase))
}

// servidorDe saca el host para que la firma del informe diga de donde
// salio sin soltar la URL entera.
func servidorDe(urlBase string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(urlBase, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i > 0 {
		s = s[:i]
	}
	return s
}

type mensajeChat struct {
	Rol       string `json:"role"`
	Contenido string `json:"content"`
}

type peticionChat struct {
	Modelo    string        `json:"model"`
	Mensajes  []mensajeChat `json:"messages"`
	MaxTokens int           `json:"max_tokens"`
	// Algo de temperatura ayuda a que la prosa no salga acartonada, pero
	// sin pasarse: esto es un informe, no un cuento.
	Temperatura float64 `json:"temperature"`
}

type respuestaChat struct {
	Opciones []struct {
		Mensaje mensajeChat `json:"message"`
	} `json:"choices"`
	Error *struct {
		Mensaje string `json:"message"`
		Tipo    string `json:"type"`
	} `json:"error"`
}

func (c *ConCompatible) Generar(ctx context.Context, d Datos) (Resultado, error) {
	if d.SinActividad() {
		return c.Respaldo.Generar(ctx, d)
	}

	ctx, cancelar := context.WithTimeout(ctx, c.Plazo)
	defer cancelar()

	cuerpo, err := json.Marshal(peticionChat{
		Modelo: c.Modelo,
		Mensajes: []mensajeChat{
			{Rol: "system", Contenido: sistema},
			{Rol: "user", Contenido: datosComoTexto(d)},
		},
		MaxTokens:   1200,
		Temperatura: 0.4,
	})
	if err != nil {
		return c.replegarse(ctx, d, "no se pudo preparar la peticion")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.URLBase+"/chat/completions", bytes.NewReader(cuerpo))
	if err != nil {
		return c.replegarse(ctx, d, err.Error())
	}
	req.Header.Set("Authorization", "Bearer "+c.Clave)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.Cliente.Do(req)
	if err != nil {
		return c.replegarse(ctx, d, err.Error())
	}
	defer resp.Body.Close()

	var r respuestaChat
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return c.replegarse(ctx, d,
			fmt.Sprintf("HTTP %d con respuesta ilegible", resp.StatusCode))
	}
	if r.Error != nil {
		return c.replegarse(ctx, d, fmt.Sprintf("HTTP %d: %s", resp.StatusCode, r.Error.Mensaje))
	}
	if resp.StatusCode != http.StatusOK {
		return c.replegarse(ctx, d, fmt.Sprintf("el proveedor respondio %d", resp.StatusCode))
	}
	if len(r.Opciones) == 0 {
		return c.replegarse(ctx, d, "el proveedor no devolvio ninguna respuesta")
	}

	texto := limpiarRazonamiento(r.Opciones[0].Mensaje.Contenido)
	if texto == "" {
		return c.replegarse(ctx, d, "el modelo devolvio un informe vacio")
	}
	return Resultado{Texto: texto, Redactado: c.Nombre()}, nil
}

// limpiarRazonamiento quita la cadena de pensamiento que algunos modelos
// vuelcan dentro de la propia respuesta.
//
// Los modelos de razonamiento (qwen3, deepseek-r1 y companyia) devuelven su
// deliberacion entre <think>...</think> en el mismo campo que el texto
// final. Sin quitarla, el informe sale con parrafos en ingles explicando
// como se va a redactar el informe. Se corta tambien un <think> sin cerrar,
// que es lo que queda cuando la respuesta se trunca por max_tokens.
func limpiarRazonamiento(bruto string) string {
	texto := bruto
	for {
		ini := strings.Index(strings.ToLower(texto), "<think>")
		if ini < 0 {
			break
		}
		fin := strings.Index(strings.ToLower(texto[ini:]), "</think>")
		if fin < 0 {
			// Sin cierre: se descarta desde ahi hasta el final.
			texto = texto[:ini]
			break
		}
		texto = texto[:ini] + texto[ini+fin+len("</think>"):]
	}
	return strings.TrimSpace(texto)
}

func (c *ConCompatible) replegarse(ctx context.Context, d Datos, motivo string) (Resultado, error) {
	log.Printf("informe por LLM no disponible (%s); se usa el generador por reglas", motivo)
	res, err := c.Respaldo.Generar(ctx, d)
	if err != nil {
		return res, err
	}
	res.Redactado = fmt.Sprintf("reglas (el LLM no estaba disponible: %s)", motivo)
	return res, nil
}
