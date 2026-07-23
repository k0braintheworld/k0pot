// Package aviso saca de la pantalla lo que no puede esperar a que alguien
// mire.
//
// Un panel solo funciona para quien lo tiene abierto. La primera intrusion
// real de este honeypot ocurrio a las 11:40 y se descubrio horas despues,
// porque a alguien le dio por abrir el navegador. Para un sistema cuya
// pregunta es "¿tengo que preocuparme?", esa es la diferencia entre
// enterarse en minutos o en dias.
//
// Se avisa por episodio y solo de lo grave. Un honeypot expuesto genera
// cientos de eventos al dia: mandarlos todos es garantizar que se dejen de
// leer, que es peor que no mandar ninguno.
package aviso

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Canales admitidos. Los tres se resuelven con un POST y sin cuenta de
// correo: montar SMTP para avisar de un honeypot es mas fontaneria que
// producto.
const (
	CanalNtfy     = "ntfy"
	CanalTelegram = "telegram"
	CanalWebhook  = "webhook"
)

// Mensaje es un aviso listo para enviar.
type Mensaje struct {
	Titulo string
	Cuerpo string
	// Urgente distingue "alguien entro" de "alguien entro Y ademas actuo".
	// Los canales lo traducen a su propia idea de prioridad.
	Urgente bool
	// Enlace al panel, para poder ir directo desde la notificacion.
	Enlace string
}

// Canal es un sitio al que mandar avisos.
type Canal interface {
	Enviar(ctx context.Context, m Mensaje) error
	Nombre() string
}

// Config es lo que hace falta para armar un canal.
type Config struct {
	// Canal: ntfy, telegram o webhook. Vacio desactiva los avisos.
	Canal string
	// Destino: el tema de ntfy, el chat de Telegram o la URL del webhook.
	Destino string
	// Clave: el token del bot de Telegram. Los otros canales no la usan.
	Clave string
	// Servidor solo para ntfy, por si se autoaloja.
	Servidor string
	// Enlace al panel que se incluye en el aviso.
	Enlace string
}

// De construye el canal configurado. Devuelve nil si no hay ninguno, que
// no es un error: no avisar es una opcion legitima.
func De(c Config, cliente *http.Client) (Canal, error) {
	if cliente == nil {
		cliente = &http.Client{Timeout: 15 * time.Second}
	}
	switch strings.ToLower(strings.TrimSpace(c.Canal)) {
	case "":
		return nil, nil
	case CanalNtfy:
		if c.Destino == "" {
			return nil, fmt.Errorf("falta el tema de ntfy")
		}
		servidor := c.Servidor
		if servidor == "" {
			servidor = "https://ntfy.sh"
		}
		return &ntfy{servidor: strings.TrimRight(servidor, "/"), tema: c.Destino, cli: cliente}, nil
	case CanalTelegram:
		if c.Clave == "" || c.Destino == "" {
			return nil, fmt.Errorf("Telegram necesita el token del bot y el chat")
		}
		return &telegram{token: c.Clave, chat: c.Destino, cli: cliente}, nil
	case CanalWebhook:
		if _, err := url.ParseRequestURI(c.Destino); err != nil {
			return nil, fmt.Errorf("la URL del webhook no es valida: %w", err)
		}
		return &webhook{url: c.Destino, cli: cliente}, nil
	default:
		return nil, fmt.Errorf("canal desconocido: %q", c.Canal)
	}
}

// ── ntfy ────────────────────────────────────────────────────────────────

type ntfy struct {
	servidor, tema string
	cli            *http.Client
}

func (n *ntfy) Nombre() string { return "ntfy (" + n.tema + ")" }

func (n *ntfy) Enviar(ctx context.Context, m Mensaje) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		n.servidor+"/"+n.tema, strings.NewReader(m.Cuerpo))
	if err != nil {
		return err
	}
	// Los titulos van en cabecera y ntfy las quiere en ASCII.
	req.Header.Set("Title", soloASCII(m.Titulo))
	req.Header.Set("Tags", "warning")
	if m.Urgente {
		req.Header.Set("Priority", "high")
	}
	if m.Enlace != "" {
		req.Header.Set("Click", m.Enlace)
	}
	return n.soltar(req)
}

func (n *ntfy) soltar(req *http.Request) error { return enviar(n.cli, req) }

// ── Telegram ────────────────────────────────────────────────────────────

type telegram struct {
	token, chat string
	cli         *http.Client
}

func (t *telegram) Nombre() string { return "Telegram" }

func (t *telegram) Enviar(ctx context.Context, m Mensaje) error {
	texto := m.Titulo + "\n\n" + m.Cuerpo
	if m.Enlace != "" {
		texto += "\n\n" + m.Enlace
	}
	cuerpo, err := json.Marshal(map[string]any{
		"chat_id": t.chat, "text": texto, "disable_web_page_preview": true,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.telegram.org/bot"+t.token+"/sendMessage", bytes.NewReader(cuerpo))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return enviar(t.cli, req)
}

// ── Webhook generico ────────────────────────────────────────────────────

type webhook struct {
	url string
	cli *http.Client
}

func (w *webhook) Nombre() string { return "webhook" }

func (w *webhook) Enviar(ctx context.Context, m Mensaje) error {
	cuerpo, err := json.Marshal(map[string]any{
		"titulo": m.Titulo, "cuerpo": m.Cuerpo,
		"urgente": m.Urgente, "enlace": m.Enlace,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(cuerpo))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	return enviar(w.cli, req)
}

// ── Comun ───────────────────────────────────────────────────────────────

func enviar(cli *http.Client, req *http.Request) error {
	resp, err := cli.Do(req)
	if err != nil {
		return fmt.Errorf("no se pudo enviar: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		// El cuerpo suele explicar el motivo mucho mejor que el codigo:
		// "chat not found" dice donde mirar, un 400 a secas no.
		detalle, _ := io.ReadAll(io.LimitReader(resp.Body, 300))
		texto := strings.TrimSpace(string(detalle))
		if texto == "" {
			return fmt.Errorf("el servicio respondio %d", resp.StatusCode)
		}
		return fmt.Errorf("el servicio respondio %d: %s", resp.StatusCode, texto)
	}
	return nil
}

// soloASCII limpia lo que no viaja bien en una cabecera HTTP.
func soloASCII(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r < 128:
			b.WriteRune(r)
		case r == 'á' || r == 'à':
			b.WriteRune('a')
		case r == 'é':
			b.WriteRune('e')
		case r == 'í':
			b.WriteRune('i')
		case r == 'ó':
			b.WriteRune('o')
		case r == 'ú':
			b.WriteRune('u')
		case r == 'ñ':
			b.WriteRune('n')
		}
	}
	return b.String()
}
