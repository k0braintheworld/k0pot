// Package web sirve el panel de k0Pot.
//
// Todo va embebido en el binario con go:embed: no hay ficheros sueltos que
// desplegar ni rutas que configurar.
//
// Aviso de seguridad que condiciona todo este paquete: un honeypot guarda
// texto escrito por atacantes (usuarios, contrasenas, comandos). Ese
// contenido NUNCA se interpola en HTML aqui. El servidor solo emite JSON y
// el navegador lo pinta con textContent, de modo que un usuario llamado
// "<script>..." se ve como texto y no se ejecuta. La cabecera CSP remata la
// defensa prohibiendo scripts en linea.
package web

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"time"

	"github.com/k0braintheworld/k0pot/internal/config"
	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/report"
	"github.com/k0braintheworld/k0pot/internal/store"
	"github.com/k0braintheworld/k0pot/internal/trampa"
)

//go:embed static
var estaticos embed.FS

// Servidor expone el panel sobre el almacen.
type Servidor struct {
	Almacen   *store.Store
	Generador report.Generador
	Config    *config.Gestor
	// Trampas son los honeypots nativos disponibles, para poder describir
	// su estado en el panel.
	Trampas []trampa.Trampa
	// DirDescargas es donde Cowrie guarda lo que consigue capturar. Se
	// inyecta en vez de deducirse para poder probarlo con un directorio
	// temporal.
	DirDescargas string
	// RutaBD y DirCowrie sirven para medir cuanto ocupa cada cosa.
	RutaBD    string
	DirCowrie string
	// AlCambiarConfig avisa a quien haya que reconfigurar (el generador de
	// informes, el enriquecedor) cuando se guardan ajustes nuevos.
	AlCambiarConfig func(config.Config)
}

// Rutas devuelve el manejador con todo montado.
func (s *Servidor) Rutas() http.Handler {
	mux := http.NewServeMux()

	sub, err := fs.Sub(estaticos, "static")
	if err != nil {
		panic(fmt.Sprintf("empaquetando estaticos: %v", err))
	}
	ficheros := http.FileServer(http.FS(sub))

	// La pagina de login y sus recursos son publicos; el resto del panel
	// no, porque el HTML de por si no filtra nada pero no tiene sentido
	// servir una interfaz que no va a poder cargar ningun dato.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if esPublico(r.URL.Path) {
			ficheros.ServeHTTP(w, r)
			return
		}
		s.protegido(ficheros.ServeHTTP)(w, r)
	})

	// Publicas: son la puerta de entrada.
	mux.HandleFunc("/api/entrar", s.entrar)
	mux.HandleFunc("/api/salir", s.salir)
	mux.HandleFunc("/api/quien", s.quien)

	// Todo lo demas exige sesion.
	mux.HandleFunc("/api/estado", s.protegido(s.estado))
	mux.HandleFunc("/api/serie", s.protegido(s.serie))
	mux.HandleFunc("/api/recientes", s.protegido(s.recientes))
	mux.HandleFunc("/api/destacados", s.protegido(s.destacados))
	mux.HandleFunc("/api/informe", s.protegido(s.informe))
	mux.HandleFunc("/api/episodios", s.protegido(s.episodios))
	mux.HandleFunc("/api/episodio", s.protegido(s.episodio))
	mux.HandleFunc("/api/episodio/explicar", s.protegido(s.explicarEpisodio))
	mux.HandleFunc("/api/ip", s.protegido(s.perfilIP))
	mux.HandleFunc("/api/uso", s.protegido(s.uso))
	mux.HandleFunc("/api/geoip", s.protegido(s.subirGeoIP))
	mux.HandleFunc("/api/campanas", s.protegido(s.campanas))
	mux.HandleFunc("/api/artefactos", s.protegido(s.artefactos))
	mux.HandleFunc("/api/aviso/probar", s.protegido(s.probarAviso))
	mux.HandleFunc("/api/novedades", s.protegido(s.novedades))
	mux.HandleFunc("/api/visto", s.protegido(s.visto))
	mux.HandleFunc("/api/ajustes", s.protegido(s.ajustes))
	mux.HandleFunc("/api/ajustes/defecto", s.protegido(s.valoresPorDefecto))
	mux.HandleFunc("/api/servicios", s.protegido(s.servicios))
	mux.HandleFunc("/api/red", s.protegido(s.red))
	mux.HandleFunc("/api/contrasena", s.protegido(s.cambiarContrasena))

	return cabeceras(mux)
}

// esPublico marca lo que se sirve sin sesion: solo la pantalla de entrada
// y lo minimo que necesita para pintarse.
func esPublico(ruta string) bool {
	switch ruta {
	case "/entrar.html", "/estilo.css", "/entrar.js":
		return true
	}
	return false
}

// cabeceras aplica las defensas del navegador a toda respuesta.
func cabeceras(siguiente http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Sin scripts en linea ni recursos externos: aunque se colara
		// contenido de un atacante en el HTML, el navegador no lo ejecuta.
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; script-src 'self'; style-src 'self'; "+
				"img-src 'self' data:; base-uri 'none'; form-action 'none'; "+
				"frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		siguiente.ServeHTTP(w, r)
	})
}

// dias lee el parametro de rango, acotado para que nadie pida un rango
// absurdo que tumbe la consulta.
func dias(r *http.Request) int {
	n, err := strconv.Atoi(r.URL.Query().Get("dias"))
	if err != nil || n < 1 {
		return 1
	}
	if n > 365 {
		return 365
	}
	return n
}

func responderJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		http.Error(w, "no se pudo serializar la respuesta", http.StatusInternalServerError)
	}
}

// Estado es lo que necesita la pantalla principal.
type Estado struct {
	Nivel      report.Nivel `json:"nivel"`
	PaisPropio string       `json:"pais_propio"`
	// Latitud y Longitud situan la marca del honeypot con precision. Cero
	// en ambas significa que no se han definido y manda el pais.
	Latitud      float64                     `json:"latitud_propia"`
	Longitud     float64                     `json:"longitud_propia"`
	Frase        string                      `json:"frase"`
	Dias         int                         `json:"dias"`
	Total        int                         `json:"total"`
	IPsUnicas    int                         `json:"ips_unicas"`
	Niveles      map[model.Clasificacion]int `json:"niveles"`
	PorTipo      []store.Recuento            `json:"por_tipo"`
	PorPais      []store.Recuento            `json:"por_pais"`
	TopIPs       []store.IPActiva            `json:"top_ips"`
	TopUsuarios  []store.Recuento            `json:"top_usuarios"`
	TopPasswords []store.Recuento            `json:"top_passwords"`
	Primero      time.Time                   `json:"primero"`
	Ultimo       time.Time                   `json:"ultimo"`
}

func (s *Servidor) estado(w http.ResponseWriter, r *http.Request) {
	d := dias(r)
	desde := time.Now().AddDate(0, 0, -d)

	resumen, err := s.Almacen.Resumir(desde)
	if err != nil {
		http.Error(w, "no se pudo leer el resumen", http.StatusInternalServerError)
		return
	}
	niveles, err := s.Almacen.PorClasificacion(desde)
	if err != nil {
		http.Error(w, "no se pudo leer la clasificacion", http.StatusInternalServerError)
		return
	}

	responderJSON(w, Estado{
		Nivel:        report.NivelDe(niveles),
		PaisPropio:   s.Config.Actual().PaisPropio,
		Latitud:      s.Config.Actual().LatitudPropia,
		Longitud:     s.Config.Actual().LongitudPropia,
		Frase:        report.FraseSemaforo(niveles),
		Dias:         d,
		Total:        resumen.Total,
		IPsUnicas:    resumen.IPsUnicas,
		Niveles:      niveles,
		PorTipo:      resumen.PorTipo,
		PorPais:      resumen.PorPais,
		TopIPs:       resumen.TopIPs,
		TopUsuarios:  resumen.TopUsuarios,
		TopPasswords: resumen.TopPasswords,
		Primero:      resumen.Primero,
		Ultimo:       resumen.Ultimo,
	})
}

// serie alimenta la grafica temporal. La granularidad se elige sola: por
// horas cuando el rango cabe en un par de dias, por dias cuando no, para
// que la grafica nunca tenga ni cuatro barras ni mil.
func (s *Servidor) serie(w http.ResponseWriter, r *http.Request) {
	d := dias(r)
	g := store.PorHora
	if d > 2 {
		g = store.PorDia
	}

	puntos, err := s.Almacen.SerieTemporal(time.Now().AddDate(0, 0, -d), g)
	if err != nil {
		http.Error(w, "no se pudo leer la serie", http.StatusInternalServerError)
		return
	}
	if puntos == nil {
		puntos = []store.PuntoSerie{}
	}
	responderJSON(w, map[string]any{"granularidad": g, "puntos": puntos})
}

func (s *Servidor) recientes(w http.ResponseWriter, r *http.Request) {
	lista, err := s.Almacen.Recientes(40)
	if err != nil {
		http.Error(w, "no se pudieron leer los eventos recientes", http.StatusInternalServerError)
		return
	}
	responderJSON(w, lista)
}

func (s *Servidor) destacados(w http.ResponseWriter, r *http.Request) {
	desde := time.Now().AddDate(0, 0, -dias(r))
	lista, err := s.Almacen.Destacados(desde, 50)
	if err != nil {
		http.Error(w, "no se pudieron leer los destacados", http.StatusInternalServerError)
		return
	}
	if lista == nil {
		lista = []store.Destacado{}
	}
	responderJSON(w, lista)
}

// Informe es el texto redactado, quien lo redacto y por que no se ha
// vuelto a redactar. Lo ultimo se ensena: un informe fechado hace media
// hora, sin explicacion, parece un panel atascado.
type Informe struct {
	Texto     string    `json:"texto"`
	Generador string    `json:"generador"`
	Momento   time.Time `json:"momento"`
	// ConIA distingue lo redactado por el modelo de lo que salio de reglas.
	ConIA bool `json:"con_ia"`
	// Desactualizado: hay actividad nueva desde que se redacto con IA.
	Desactualizado bool   `json:"desactualizado"`
	Motivo         string `json:"motivo"`
	// Cuota de informes con IA gastada hoy. 0 en tope = sin limite.
	CuotaUsada int `json:"cuota_usada"`
	CuotaTope  int `json:"cuota_tope"`
}

func (s *Servidor) informe(w http.ResponseWriter, r *http.Request) {
	// Redactar con IA cuesta dinero, asi que se pide con POST: un GET debe
	// poder repetirse sin efectos, y el panel lo repite cada pocos segundos.
	conIA := r.Method == http.MethodPost

	d := dias(r)
	desde := time.Now().AddDate(0, 0, -d)

	resumen, err := s.Almacen.Resumir(desde)
	if err != nil {
		http.Error(w, "no se pudo leer el resumen", http.StatusInternalServerError)
		return
	}
	niveles, err := s.Almacen.PorClasificacion(desde)
	if err != nil {
		http.Error(w, "no se pudo leer la clasificacion", http.StatusInternalServerError)
		return
	}
	lista, err := s.Almacen.Destacados(desde, 20)
	if err != nil {
		http.Error(w, "no se pudieron leer los destacados", http.StatusInternalServerError)
		return
	}

	// Los ataques ya agrupados son el material principal del informe: sin
	// ellos el modelo solo puede parafrasear recuentos.
	ataques, err := s.Almacen.Episodios(store.FiltroEpisodios{Desde: desde, Limite: 50})
	if err != nil {
		http.Error(w, "no se pudieron leer los ataques", http.StatusInternalServerError)
		return
	}

	datos := report.Datos{
		Desde: desde, Hasta: time.Now(),
		Resumen: resumen, Niveles: niveles, Destacados: lista,
		Episodios: ataques,
	}

	// El refresco del panel NUNCA gasta cuota: lo automatico lo redactan
	// las reglas. El modelo entra solo cuando alguien lo pide, con POST.
	pol := s.politica()
	var res report.Servido
	if conIA {
		res, err = pol.AMano(r.Context(), datos, d)
	} else {
		res, err = pol.Automatico(r.Context(), datos, d)
	}
	if err != nil {
		http.Error(w, "no se pudo redactar el informe", http.StatusInternalServerError)
		return
	}
	// Se publica quien redacto de verdad, no quien estaba configurado.
	responderJSON(w, Informe{
		Texto: res.Texto, Generador: res.Generador, Momento: res.Momento,
		ConIA: res.ConIA, Desactualizado: res.Desactualizado, Motivo: res.Motivo,
		CuotaUsada: res.CuotaUsada, CuotaTope: res.CuotaTope,
	})
}

// politica arma el reparto con los ajustes vigentes. Se construye en cada
// peticion, y no una vez al arrancar, para que cambiar el tope desde el
// panel tenga efecto sin reiniciar.
func (s *Servidor) politica() *report.Politica {
	return &report.Politica{
		Gen:        s.Generador,
		Reglas:     report.PorReglas{},
		Alm:        s.Almacen,
		TopeDiario: s.Config.Actual().InformeTopeDiario,
	}
}
