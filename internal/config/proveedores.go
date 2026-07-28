package config

import "strings"

// Proveedor describe un servicio de IA conocido. Existe para que configurarlo
// sea solo elegirlo y pegar la clave: la URL y un modelo por defecto ya vienen.
type Proveedor struct {
	ID      string `json:"id"`
	Nombre  string `json:"nombre"`
	Tipo    string `json:"tipo"` // "compatible" | "anthropic"
	URLBase string `json:"url_base"`
	Modelo  string `json:"modelo"`
}

// Proveedores es el catalogo integrado. El orden es el de la lista desplegable.
var Proveedores = []Proveedor{
	{"groq", "Groq", ProveedorCompatible, "https://api.groq.com/openai/v1", "openai/gpt-oss-120b"},
	{"gemini", "Google Gemini", ProveedorCompatible, "https://generativelanguage.googleapis.com/v1beta/openai", "gemini-2.5-flash"},
	{"openai", "OpenAI", ProveedorCompatible, "https://api.openai.com/v1", "gpt-4o-mini"},
	{"anthropic", "Anthropic", ProveedorAnthropic, "", "claude-3-5-haiku-latest"},
	{"openrouter", "OpenRouter", ProveedorCompatible, "https://openrouter.ai/api/v1", "meta-llama/llama-3.3-70b-instruct"},
	{"mistral", "Mistral", ProveedorCompatible, "https://api.mistral.ai/v1", "mistral-small-latest"},
	{"deepseek", "DeepSeek", ProveedorCompatible, "https://api.deepseek.com", "deepseek-chat"},
}

// ProveedorPorID busca uno del catalogo.
func ProveedorPorID(id string) (Proveedor, bool) {
	for _, p := range Proveedores {
		if p.ID == id {
			return p, true
		}
	}
	return Proveedor{}, false
}

// presetPorURL adivina a que proveedor del catalogo corresponde una URL, para
// migrar la configuracion antigua de un solo proveedor a la nueva lista.
func presetPorURL(url string) string {
	u := strings.ToLower(url)
	switch {
	case strings.Contains(u, "groq"):
		return "groq"
	case strings.Contains(u, "generativelanguage.googleapis"):
		return "gemini"
	case strings.Contains(u, "openrouter"):
		return "openrouter"
	case strings.Contains(u, "mistral"):
		return "mistral"
	case strings.Contains(u, "deepseek"):
		return "deepseek"
	case strings.Contains(u, "api.openai.com"):
		return "openai"
	}
	return ""
}
