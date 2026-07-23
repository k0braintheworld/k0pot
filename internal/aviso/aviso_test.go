package aviso

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/k0braintheworld/k0pot/internal/episodio"
	"github.com/k0braintheworld/k0pot/internal/store"
)

func ep(ip string, sev episodio.Severidad, resumen string) store.EpisodioFila {
	return store.EpisodioFila{
		Episodio: episodio.Episodio{
			Clave: ip, IP: ip, Protocolo: "ssh", Severidad: sev, Resumen: resumen,
			Inicio: time.Now(), Fin: time.Now(),
		},
		Pais: "NL", ISP: "TECHOFF SRV LIMITED",
	}
}

func TestSinAtaquesNoHayAviso(t *testing.T) {
	if _, hay := Redactar(nil, ""); hay {
		t.Error("no deberia haber mensaje")
	}
}

// La primera linea tiene que bastar para decidir si hay que levantarse.
func TestElTituloDiceLoImportante(t *testing.T) {
	m, _ := Redactar([]store.EpisodioFila{
		ep("1.2.3.4", episodio.Intrusion, "Entro como root; intento usar el servidor de pasarela"),
	}, "http://panel")

	if !strings.Contains(m.Titulo, "Intrusion") || !strings.Contains(m.Titulo, "1.2.3.4") {
		t.Errorf("titulo poco informativo: %q", m.Titulo)
	}
	if !m.Urgente {
		t.Error("una intrusion deberia marcarse urgente")
	}
	if !strings.Contains(m.Cuerpo, "pasarela") {
		t.Errorf("el cuerpo deberia contar que hicieron: %q", m.Cuerpo)
	}
}

// Un acceso preocupa, pero menos que una intrusion: el canal lo traduce a
// su prioridad y no conviene gastar la urgencia en todo.
func TestUnAccesoNoEsUrgente(t *testing.T) {
	m, _ := Redactar([]store.EpisodioFila{ep("1.2.3.4", episodio.Acceso, "Entro como root")}, "")
	if m.Urgente {
		t.Error("un acceso sin actividad no deberia ir como urgente")
	}
}

// Lo mas grave, primero: en una notificacion solo se leen dos lineas.
func TestLoMasGraveVaPrimero(t *testing.T) {
	m, _ := Redactar([]store.EpisodioFila{
		ep("1.1.1.1", episodio.Acceso, "Entro"),
		ep("2.2.2.2", episodio.Intrusion, "Entro y ejecuto comandos"),
	}, "")
	if !strings.HasPrefix(m.Cuerpo, "INTRUSION") {
		t.Errorf("el cuerpo empieza por %q", m.Cuerpo[:20])
	}
}

// Treinta notificaciones son ruido y una lista de treinta no se lee en un
// movil: se detallan las primeras y se cuenta el resto.
func TestUnaAvalanchaSeResumeEnUnSoloAviso(t *testing.T) {
	var muchos []store.EpisodioFila
	for i := 0; i < 30; i++ {
		muchos = append(muchos, ep("1.1.1.1", episodio.Acceso, "Entro"))
	}
	m, _ := Redactar(muchos, "")
	if strings.Count(m.Cuerpo, "ACCESO") > topeEnMensaje {
		t.Errorf("se detallaron demasiados: %d", strings.Count(m.Cuerpo, "ACCESO"))
	}
	if !strings.Contains(m.Cuerpo, "y 25 mas") {
		t.Errorf("hay que decir cuantos quedan fuera: %q", m.Cuerpo)
	}
}

func TestSinCanalNoSeAvisa(t *testing.T) {
	c, err := De(Config{}, nil)
	if err != nil || c != nil {
		t.Errorf("sin canal deberia devolver nil sin error: %v %v", c, err)
	}
}

func TestConfiguracionIncompletaSeExplica(t *testing.T) {
	casos := []struct {
		nombre string
		c      Config
	}{
		{"ntfy sin tema", Config{Canal: CanalNtfy}},
		{"telegram sin token", Config{Canal: CanalTelegram, Destino: "123"}},
		{"webhook con URL invalida", Config{Canal: CanalWebhook, Destino: "esto no es una url"}},
		{"canal inventado", Config{Canal: "paloma-mensajera"}},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			if _, err := De(c.c, nil); err == nil {
				t.Error("deberia explicar que falta")
			}
		})
	}
}

func TestNtfyMandaTituloYPrioridad(t *testing.T) {
	var recibido *http.Request
	var cuerpo string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		recibido = r
		b, _ := io.ReadAll(r.Body)
		cuerpo = string(b)
	}))
	defer srv.Close()

	c, err := De(Config{Canal: CanalNtfy, Destino: "mi-tema", Servidor: srv.URL}, srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Enviar(context.Background(), Mensaje{
		Titulo: "Intrusion", Cuerpo: "detalle", Urgente: true, Enlace: "http://panel"}); err != nil {
		t.Fatal(err)
	}
	if recibido.URL.Path != "/mi-tema" {
		t.Errorf("ruta = %s", recibido.URL.Path)
	}
	if recibido.Header.Get("Priority") != "high" {
		t.Error("una intrusion deberia ir con prioridad alta")
	}
	if recibido.Header.Get("Click") != "http://panel" {
		t.Error("falta el enlace al panel")
	}
	if cuerpo != "detalle" {
		t.Errorf("cuerpo = %q", cuerpo)
	}
}

func TestTelegramMandaElChatYElTexto(t *testing.T) {
	var payload map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&payload)
	}))
	defer srv.Close()
	// Se apunta al servidor de prueba reescribiendo el transporte.
	cli := srv.Client()
	cli.Transport = redirigir{srv.URL}

	c, _ := De(Config{Canal: CanalTelegram, Destino: "12345", Clave: "token"}, cli)
	if err := c.Enviar(context.Background(), Mensaje{Titulo: "T", Cuerpo: "C"}); err != nil {
		t.Fatal(err)
	}
	if payload["chat_id"] != "12345" {
		t.Errorf("chat = %v", payload["chat_id"])
	}
	if !strings.Contains(payload["text"].(string), "T") {
		t.Errorf("texto = %v", payload["text"])
	}
}

// Un error del servicio tiene que llegar explicado: "chat not found" dice
// donde mirar, un 400 a secas no.
func TestElErrorDelServicioSePropaga(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"description":"chat not found"}`))
	}))
	defer srv.Close()

	c, _ := De(Config{Canal: CanalWebhook, Destino: srv.URL}, srv.Client())
	err := c.Enviar(context.Background(), Mensaje{Titulo: "T"})
	if err == nil || !strings.Contains(err.Error(), "chat not found") {
		t.Errorf("el error deberia citar al servicio: %v", err)
	}
}

func TestElAvisoDePruebaExplicaQueEsperar(t *testing.T) {
	m := DePrueba("http://panel")
	if !strings.Contains(m.Cuerpo, "ruido de fondo") && !strings.Contains(m.Cuerpo, "ruido") {
		t.Errorf("deberia aclarar que NO se avisa de todo: %q", m.Cuerpo)
	}
}

// El titulo viaja en una cabecera HTTP, que no admite acentos.
func TestElTituloViajaSinAcentos(t *testing.T) {
	if s := soloASCII("Intrusión en el señuelo"); s != "Intrusion en el senuelo" {
		t.Errorf("resultado = %q", s)
	}
}

type redirigir struct{ base string }

func (r redirigir) RoundTrip(req *http.Request) (*http.Response, error) {
	u, _ := req.URL.Parse(r.base + req.URL.Path)
	req.URL = u
	return http.DefaultTransport.RoundTrip(req)
}
