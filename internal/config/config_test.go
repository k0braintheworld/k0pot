package config

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/k0braintheworld/k0pot/internal/store"
)

func gestorTemporal(t *testing.T) *Gestor {
	t.Helper()
	s, err := store.Abrir(filepath.Join(t.TempDir(), "cfg.db"))
	if err != nil {
		t.Fatalf("abriendo almacen: %v", err)
	}
	t.Cleanup(func() { s.Cerrar() })

	g, err := Abrir(s)
	if err != nil {
		t.Fatalf("abriendo configuracion: %v", err)
	}
	return g
}

func TestArrancaConValoresPorDefecto(t *testing.T) {
	c := gestorTemporal(t).Actual()
	if c.ReputacionAlta != 75 || c.Modelo == "" || c.RefrescoSegundos != 20 {
		t.Errorf("configuracion inicial = %+v", c)
	}
}

func TestGuardarYRecargar(t *testing.T) {
	g := gestorTemporal(t)

	c := g.Actual()
	c.ReputacionAlta = 40
	c.Modelo = "claude-haiku-4-5"
	if err := g.Guardar(c); err != nil {
		t.Fatal(err)
	}
	if g.Actual().ReputacionAlta != 40 {
		t.Error("el cambio no quedo en memoria")
	}

	// Recargar simula al otro proceso (el collector) releyendo lo que el
	// panel acaba de escribir.
	g.actual = PorDefecto()
	if err := g.Recargar(); err != nil {
		t.Fatal(err)
	}
	if g.Actual().ReputacionAlta != 40 || g.Actual().Modelo != "claude-haiku-4-5" {
		t.Errorf("tras recargar: %+v", g.Actual())
	}
}

func TestValidacionAcotaLosValores(t *testing.T) {
	g := gestorTemporal(t)
	casos := map[string]func(*Config){
		"reputacion fuera de rango": func(c *Config) { c.ReputacionAlta = 500 },
		"refresco demasiado corto":  func(c *Config) { c.RefrescoSegundos = 1 },
		"caducidad cero":            func(c *Config) { c.CaducidadIPDias = 0 },
		"retencion negativa":        func(c *Config) { c.RetencionDias = -5 },
		"modelo vacio":              func(c *Config) { c.Modelo = "" },
	}
	for nombre, romper := range casos {
		c := PorDefecto()
		romper(&c)
		if err := g.Guardar(c); err == nil {
			t.Errorf("%s: se acepto una configuracion invalida", nombre)
		}
	}
}

// Las claves nunca deben salir del servidor en claro.
func TestLasClavesSalenEnmascaradas(t *testing.T) {
	c := PorDefecto()
	c.ClaveAbuseIPDB = "claveFalsaDeAbuseIPDBParaLaPrueba"
	c.ClaveAnthropic = "sk-ant-api03-secretisimo-de-verdad"

	p := c.ParaPanel()
	if strings.Contains(p.ClaveAbuseIPDB, "claveFalsaDeAbuseIPDBParaLaPrueba") || strings.Contains(p.ClaveAnthropic, "sk-ant") {
		t.Fatalf("la clave sale en claro: %+v", p)
	}
	if !strings.HasPrefix(p.ClaveAbuseIPDB, "••••") || !strings.HasSuffix(p.ClaveAbuseIPDB, "ueba") {
		t.Errorf("mascara inesperada: %q", p.ClaveAbuseIPDB)
	}
	if !p.TieneAbuseIPDB || !p.TieneAnthropic {
		t.Error("el panel no puede saber si hay clave configurada")
	}

	vacia := PorDefecto().ParaPanel()
	if vacia.ClaveAbuseIPDB != "" || vacia.TieneAbuseIPDB {
		t.Errorf("sin clave deberia quedar vacio: %+v", vacia)
	}
}

// Un campo anadido en una version posterior debe quedarse con su valor por
// defecto, no con el cero de Go, al leer una configuracion antigua.
func TestConfiguracionAntiguaNoPierdeDefectos(t *testing.T) {
	s, err := store.Abrir(filepath.Join(t.TempDir(), "vieja.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Cerrar()

	if err := s.GuardarConfig(`{"reputacion_alta":30}`); err != nil {
		t.Fatal(err)
	}
	g, err := Abrir(s)
	if err != nil {
		t.Fatal(err)
	}
	c := g.Actual()
	if c.ReputacionAlta != 30 {
		t.Errorf("no se respeto lo guardado: %d", c.ReputacionAlta)
	}
	if c.RefrescoSegundos != 20 || c.Modelo == "" {
		t.Errorf("los campos ausentes perdieron su valor por defecto: %+v", c)
	}
}

// El mapa traza las lineas hacia el pais propio: si no es un ISO valido,
// no hay destino y las lineas no se pueden dibujar.
func TestPaisPropio(t *testing.T) {
	g := gestorTemporal(t)
	if g.Actual().PaisPropio != "ES" {
		t.Errorf("por defecto = %q, esperaba ES", g.Actual().PaisPropio)
	}

	for _, malo := range []string{"", "E", "ESP", "espana"} {
		c := PorDefecto()
		c.PaisPropio = malo
		if err := g.Guardar(c); err == nil {
			t.Errorf("se acepto %q como pais", malo)
		}
	}

	// Se normaliza a mayusculas: el mapa indexa por ISO en mayuscula.
	c := PorDefecto()
	c.PaisPropio = "de"
	if err := g.Guardar(c); err != nil {
		t.Fatal(err)
	}
	if g.Actual().PaisPropio != "DE" {
		t.Errorf("no se normalizo: %q", g.Actual().PaisPropio)
	}
}

// El proyecto se llamaba honey antes de ser k0Pot. Cambiar el nombre no
// puede dejar sin claves a quien ya lo tenia funcionando.
func TestAceptaLosDosPrefijosDeVariables(t *testing.T) {
	casos := []struct {
		nombre, variable string
		leer             func(Config) string
	}{
		{"prefijo nuevo", "K0POT_CLAVE_ABUSEIPDB", func(c Config) string { return c.ClaveAbuseIPDB }},
		{"prefijo antiguo", "HONEY_ABUSEIPDB_KEY", func(c Config) string { return c.ClaveAbuseIPDB }},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			t.Setenv(c.variable, "valorDePrueba")
			g := gestorTemporal(t)
			if leido := c.leer(g.Actual()); leido != "valorDePrueba" {
				t.Errorf("%s no se leyo: %q", c.variable, leido)
			}
		})
	}
}

// El nuevo manda cuando estan los dos: es hacia donde se migra.
func TestElPrefijoNuevoTienePrioridad(t *testing.T) {
	t.Setenv("K0POT_CLAVE_ABUSEIPDB", "nueva")
	t.Setenv("HONEY_ABUSEIPDB_KEY", "antigua")
	if v := gestorTemporal(t).Actual().ClaveAbuseIPDB; v != "nueva" {
		t.Errorf("gano %q, deberia ganar la nueva", v)
	}
}
