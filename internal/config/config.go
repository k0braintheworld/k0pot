// Package config guarda los ajustes que se pueden cambiar desde el panel.
//
// Vive en la base de datos, no en ficheros: asi se edita desde el navegador
// y no hay que reiniciar nada. Las variables de entorno siguen valiendo
// como semilla inicial de las claves, para no obligar a reconfigurar lo que
// ya funcionaba.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/k0braintheworld/k0pot/internal/store"
)

// Config son todos los ajustes editables.
//
// Las claves llevan `json:"-"` en la salida hacia el panel: se sirven
// aparte y siempre enmascaradas. Ver Publica().
type Config struct {
	// Clasificador: criterio de producto, no constantes tecnicas.
	ReputacionAlta int `json:"reputacion_alta"`
	DenunciasAltas int `json:"denuncias_altas"`

	// Enriquecimiento de IPs.
	EnriquecerActivo bool `json:"enriquecer_activo"`
	CaducidadIPDias  int  `json:"caducidad_ip_dias"`
	ReservaCuota     int  `json:"reserva_cuota"`

	// Informes.
	UsarLLM bool `json:"usar_llm"`
	// Proveedor: "anthropic" o "compatible" (cualquier API con el formato
	// de OpenAI: Groq, OpenRouter, Mistral, Ollama...).
	Proveedor string `json:"proveedor"`
	Modelo    string `json:"modelo"`
	// URLBase solo aplica al proveedor compatible.
	URLBase string `json:"url_base"`

	// Frenos del gasto en IA. El panel pide el informe en cada refresco,
	// asi que sin ellos una pestaña abierta agota la cuota diaria sola.
	// InformeIntervaloMin es lo minimo entre dos informes de pago.
	InformeIntervaloMin int `json:"informe_intervalo_min"`
	// InformeTopeDiario es el limite duro; 0 significa sin limite.
	InformeTopeDiario int `json:"informe_tope_diario"`

	// Red. Dos interfaces distintas a proposito: el panel se sirve por la
	// de gestion y los honeypots escuchan en la expuesta.
	//
	// AVISO: esto separa por donde escucha cada cosa, NO aisla las redes.
	// El aislamiento real es cosa del hipervisor y del router; si ambas
	// interfaces cuelgan del mismo segmento, aqui no hay nada que hacer.
	EscuchaPanel     string `json:"escucha_panel"`
	EscuchaHoneypots string `json:"escucha_honeypots"`

	// Servicios de honeypot activos, por su ID (http, redis, ftp...).
	Servicios map[string]Servicio `json:"servicios"`

	// Panel.
	RefrescoSegundos int `json:"refresco_segundos"`
	// PaisPropio es donde esta el honeypot, en codigo ISO de dos letras.
	// El mapa traza hacia ahi las lineas de ataque.
	PaisPropio string `json:"pais_propio"`

	// Retencion: 0 significa conservar para siempre.
	RetencionDias int `json:"retencion_dias"`

	// Claves de API. Nunca salen en claro del servidor.
	ClaveAbuseIPDB  string `json:"clave_abuseipdb"`
	ClaveAnthropic  string `json:"clave_anthropic"`
	ClaveCompatible string `json:"clave_compatible"`
}

// Servicio es el estado de una trampa.
type Servicio struct {
	Activo bool `json:"activo"`
	Puerto int  `json:"puerto"`
}

// Proveedores admitidos para los informes.
const (
	ProveedorAnthropic  = "anthropic"
	ProveedorCompatible = "compatible"
)

// PorDefecto son los valores de partida.
func PorDefecto() Config {
	return Config{
		ReputacionAlta:   75,
		DenunciasAltas:   100,
		EnriquecerActivo: true,
		CaducidadIPDias:  7,
		ReservaCuota:     25,
		UsarLLM:          true,
		Proveedor:        ProveedorCompatible,
		Modelo:           "openai/gpt-oss-120b",
		URLBase:          "https://api.groq.com/openai/v1",
		// 15 min y 40 al dia caben de sobra en los planes gratuitos y
		// dejan el informe fresco para lo que un honeypot necesita: si
		// algo pasa, lo urgente son las alertas, no la prosa.
		InformeIntervaloMin: 15,
		InformeTopeDiario:   40,
		RefrescoSegundos:    20,
		PaisPropio:          "ES",
		// Vacio = todas las interfaces. Se concreta desde el panel en
		// cuanto la red este separada de verdad.
		EscuchaPanel:     "0.0.0.0",
		EscuchaHoneypots: "0.0.0.0",
		Servicios:        map[string]Servicio{},
		RetencionDias:    0,
	}
}

// Validar acota los valores para que un ajuste absurdo no tumbe nada.
func (c *Config) Validar() error {
	var problemas []string

	acotar := func(nombre string, v *int, min, max int) {
		if *v < min || *v > max {
			problemas = append(problemas,
				fmt.Sprintf("%s debe estar entre %d y %d", nombre, min, max))
		}
	}
	acotar("la reputacion alta", &c.ReputacionAlta, 0, 100)
	acotar("las denuncias altas", &c.DenunciasAltas, 0, 1000000)
	acotar("la caducidad de IP", &c.CaducidadIPDias, 1, 365)
	acotar("la reserva de cuota", &c.ReservaCuota, 0, 1000)
	acotar("el refresco del panel", &c.RefrescoSegundos, 5, 3600)
	acotar("la retencion", &c.RetencionDias, 0, 3650)
	acotar("el intervalo entre informes", &c.InformeIntervaloMin, 1, 1440)
	acotar("el tope diario de informes", &c.InformeTopeDiario, 0, 10000)

	if c.Modelo == "" {
		problemas = append(problemas, "hay que indicar un modelo")
	}
	switch c.Proveedor {
	case ProveedorAnthropic, ProveedorCompatible:
	default:
		problemas = append(problemas,
			fmt.Sprintf("proveedor desconocido %q (usa %q o %q)",
				c.Proveedor, ProveedorAnthropic, ProveedorCompatible))
	}
	if c.Proveedor == ProveedorCompatible && c.URLBase == "" {
		problemas = append(problemas, "el proveedor compatible necesita una URL base")
	}
	for id, sv := range c.Servicios {
		if sv.Puerto < 1 || sv.Puerto > 65535 {
			problemas = append(problemas,
				fmt.Sprintf("el puerto de %s debe estar entre 1 y 65535", id))
		}
		// Por debajo de 1024 hace falta root, y este proceso corre como
		// usuario normal: se avisa antes de que el servicio no arranque.
		if sv.Activo && sv.Puerto < 1024 {
			problemas = append(problemas,
				fmt.Sprintf("el puerto %d de %s necesita privilegios de root; "+
					"usa uno alto y redirige el trafico", sv.Puerto, id))
		}
	}
	if puerto, id := puertoRepetido(c.Servicios); puerto != 0 {
		problemas = append(problemas,
			fmt.Sprintf("el puerto %d esta repetido (%s)", puerto, id))
	}
	if len(c.PaisPropio) != 2 {
		problemas = append(problemas, "el pais propio debe ser un codigo ISO de dos letras")
	}
	c.PaisPropio = strings.ToUpper(c.PaisPropio)
	if len(problemas) > 0 {
		return errors.New(strings.Join(problemas, "; "))
	}
	return nil
}

// puertoRepetido detecta dos servicios activos en el mismo puerto: el
// segundo no arrancaria y el fallo seria dificil de ver.
func puertoRepetido(servicios map[string]Servicio) (int, string) {
	vistos := map[int]string{}
	for id, sv := range servicios {
		if !sv.Activo {
			continue
		}
		if otro, ya := vistos[sv.Puerto]; ya {
			return sv.Puerto, otro + " y " + id
		}
		vistos[sv.Puerto] = id
	}
	return 0, ""
}

// Publica es la vista que se manda al navegador: igual que Config pero con
// las claves sustituidas por una pista de cuatro caracteres. El panel puede
// ver SI hay clave y cual es sin poder leerla.
type Publica struct {
	Config
	ClaveAbuseIPDB  string `json:"clave_abuseipdb"`
	ClaveAnthropic  string `json:"clave_anthropic"`
	ClaveCompatible string `json:"clave_compatible"`
	TieneAbuseIPDB  bool   `json:"tiene_abuseipdb"`
	TieneAnthropic  bool   `json:"tiene_anthropic"`
	TieneCompatible bool   `json:"tiene_compatible"`
}

// ParaPanel enmascara las claves antes de salir del servidor.
func (c Config) ParaPanel() Publica {
	return Publica{
		Config:          c,
		ClaveAbuseIPDB:  enmascarar(c.ClaveAbuseIPDB),
		ClaveAnthropic:  enmascarar(c.ClaveAnthropic),
		ClaveCompatible: enmascarar(c.ClaveCompatible),
		TieneAbuseIPDB:  c.ClaveAbuseIPDB != "",
		TieneAnthropic:  c.ClaveAnthropic != "",
		TieneCompatible: c.ClaveCompatible != "",
	}
}

// enmascarar deja ver lo justo para distinguir una clave de otra.
func enmascarar(clave string) string {
	if clave == "" {
		return ""
	}
	if len(clave) <= 4 {
		return "••••"
	}
	return "••••" + clave[len(clave)-4:]
}

// Gestor mantiene la configuracion viva y la persiste.
//
// Se lee muchas veces (cada peticion del panel) y se escribe pocas, asi que
// va con RWMutex y una copia en memoria.
type Gestor struct {
	almacen *store.Store
	mu      sync.RWMutex
	actual  Config
}

// Abrir carga la configuracion, sembrando las claves del entorno la primera
// vez para no romper una instalacion que ya venia funcionando con .env.
func Abrir(almacen *store.Store) (*Gestor, error) {
	g := &Gestor{almacen: almacen, actual: PorDefecto()}

	datos, err := almacen.LeerConfig()
	switch {
	case errors.Is(err, store.ErrNoExiste):
		// Se aceptan los dos prefijos: el proyecto se llamaba honey antes
		// de ser k0Pot, y cambiar el nombre no deberia romper una
		// instalacion que ya venia funcionando.
		g.actual.ClaveAbuseIPDB = primeraNoVacia(
			"K0POT_CLAVE_ABUSEIPDB", "HONEY_ABUSEIPDB_KEY")
		g.actual.ClaveAnthropic = primeraNoVacia(
			"K0POT_CLAVE_ANTHROPIC", "HONEY_ANTHROPIC_KEY", "ANTHROPIC_API_KEY")
		g.actual.ClaveCompatible = primeraNoVacia(
			"K0POT_CLAVE_COMPATIBLE", "HONEY_GROQ_KEY", "HONEY_LLM_KEY")
		if m := primeraNoVacia("K0POT_MODELO", "HONEY_MODELO"); m != "" {
			g.actual.Modelo = m
		}
		if u := primeraNoVacia("K0POT_URL_BASE"); u != "" {
			g.actual.URLBase = u
		}
		if p := primeraNoVacia("K0POT_PROVEEDOR"); p != "" {
			g.actual.Proveedor = p
		}
		if err := g.Guardar(g.actual); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		// Partir de los valores por defecto y aplicar encima lo guardado:
		// un campo nuevo anadido en una version posterior queda con su
		// valor por defecto en vez de con el cero de Go.
		c := PorDefecto()
		if err := json.Unmarshal([]byte(datos), &c); err != nil {
			return nil, fmt.Errorf("configuracion guardada ilegible: %w", err)
		}
		g.actual = c
	}
	return g, nil
}

func primeraNoVacia(claves ...string) string {
	for _, k := range claves {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}

// Actual devuelve una copia de la configuracion viva.
func (g *Gestor) Actual() Config {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.actual
}

// Guardar valida y persiste.
func (g *Gestor) Guardar(c Config) error {
	if err := c.Validar(); err != nil {
		return err
	}
	datos, err := json.Marshal(c)
	if err != nil {
		return fmt.Errorf("serializando configuracion: %w", err)
	}
	if err := g.almacen.GuardarConfig(string(datos)); err != nil {
		return err
	}

	g.mu.Lock()
	g.actual = c
	g.mu.Unlock()
	return nil
}

// Recargar relee la configuracion de la base de datos.
//
// Hace falta porque el collector y el panel son procesos distintos: si se
// cambia un umbral desde el navegador, el collector solo se entera si
// vuelve a mirar. La base de datos es el punto de encuentro.
func (g *Gestor) Recargar() error {
	datos, err := g.almacen.LeerConfig()
	if errors.Is(err, store.ErrNoExiste) {
		return nil
	}
	if err != nil {
		return err
	}

	c := PorDefecto()
	if err := json.Unmarshal([]byte(datos), &c); err != nil {
		return fmt.Errorf("configuracion guardada ilegible: %w", err)
	}

	g.mu.Lock()
	g.actual = c
	g.mu.Unlock()
	return nil
}
