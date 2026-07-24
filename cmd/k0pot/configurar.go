package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/k0braintheworld/k0pot/internal/config"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// configurar es el asistente de primera puesta en marcha.
//
// Existe porque los ajustes que deciden si k0Pot sirve para algo -que
// interfaz escucha que, y quien puede entrar al panel- son justo los que no
// tienen un valor por defecto razonable. Dejarlos para "luego, desde el
// panel" es como se acaba con un honeypot escuchando en la red de casa.
//
// Se puede volver a ejecutar: no pisa nada que ya este bien salvo que se
// diga.
func configurar(almacen *store.Store, ajustes *config.Gestor, rutaEnv string) error {
	fmt.Println()
	fmt.Println("  k0Pot — configuracion inicial")
	fmt.Println("  ─────────────────────────────")

	c := ajustes.Actual()

	if err := preguntarRed(&c); err != nil {
		return err
	}
	if err := preguntarPanel(&c); err != nil {
		return err
	}
	if err := ajustes.Guardar(c); err != nil {
		return fmt.Errorf("guardando la configuracion: %w", err)
	}
	if err := escribirEnv(rutaEnv, c.EscuchaHoneypots); err != nil {
		return err
	}
	if err := generarCortafuegos(&c, rutaEnv); err != nil {
		// No es fatal: el resto de la configuracion vale igual, y siempre
		// queda crear el .local a mano. Pero se avisa, porque sin el la capa
		// de aislamiento no se aplica.
		fmt.Printf("  AVISO: no se pudo dejar el cortafuegos listo (%v).\n", err)
		fmt.Println("  Tendras que crear el aislamiento.local.nft a mano.")
	}
	if err := preguntarCuenta(almacen); err != nil {
		return err
	}

	fmt.Println()
	esquema := "https"
	if !c.PanelHTTPS {
		esquema = "http"
	}
	fmt.Println()
	fmt.Println("  Configurado. Ya puedes entrar al panel:")
	fmt.Println()
	fmt.Printf("      %s://%s:8080\n", esquema, c.EscuchaPanel)
	fmt.Println()
	fmt.Println("  Antes de exponerlo a internet, quedan estos pasos:")
	fmt.Println()
	fmt.Println("    1. Cortafuegos: sudo k0pot-nft aplicar  (ya generado con tus IP;")
	fmt.Println("                    confirma en 2 min desde otra sesion)")
	fmt.Printf("    2. Router:      redirige los puertos a %s, NUNCA a %s\n",
		c.EscuchaHoneypots, c.EscuchaPanel)
	fmt.Println("    3. Avisos:      Ajustes -> Avisos (opcional)")
	fmt.Println()
	return nil
}

func preguntarRed(c *config.Config) error {
	fmt.Println()
	fmt.Println("  Un honeypot necesita DOS interfaces: una para el panel, en tu")
	fmt.Println("  red, y otra expuesta donde escuchan las trampas. Que sea la")
	fmt.Println("  misma es invitar a un atacante a tu red.")
	fmt.Println()

	disponibles := ipsDeLaMaquina()
	reales := soloReales(disponibles)
	if len(reales) < 2 {
		fmt.Println("  AVISO: se ve menos de dos interfaces de red reales. Sin una")
		fmt.Println("  segunda interfaz en otra red, k0Pot no puede aislar nada.")
	}
	fmt.Println("  Interfaces detectadas:")
	for _, d := range reales {
		fmt.Printf("    %-12s %s\n", d.iface, d.ip)
	}
	fmt.Println()
	fmt.Println("  Se proponen las que ya tiene la maquina: pulsa Enter para")
	fmt.Println("  mantenerlas, o escribe otra si prefieres.")
	fmt.Println()

	// Si ya habia una IP configurada valida se respeta; si no, se propone la
	// detectada. En una maquina ya bien direccionada basta con pulsar Enter.
	gestion := pedir("  IP de GESTION (para el panel)",
		porDefectoRed(c.EscuchaPanel, reales, 0))
	expuesta := pedir("  IP EXPUESTA (para los honeypots)",
		porDefectoRed(c.EscuchaHoneypots, reales, 1))

	for nombre, ip := range map[string]string{"de gestion": gestion, "expuesta": expuesta} {
		if ip == "" {
			return fmt.Errorf("falta la IP %s", nombre)
		}
		if net.ParseIP(ip) == nil {
			return fmt.Errorf("la IP %s (%q) no es una direccion valida", nombre, ip)
		}
		if !existeEnLaMaquina(ip, disponibles) {
			return fmt.Errorf("la IP %s (%s) no existe en esta maquina; "+
				"configurala antes", nombre, ip)
		}
	}
	if gestion == expuesta {
		return fmt.Errorf("las dos IP son la misma: asi no hay separacion posible " +
			"y el honeypot quedaria escuchando en tu propia red")
	}
	if mismaRed(gestion, expuesta) {
		fmt.Println()
		fmt.Println("  AVISO: las dos estan en la misma red /24.")
		fmt.Println("  Eso separa por donde escucha cada cosa, pero NO aisla: un")
		fmt.Println("  atacante que entre seguiria dentro de tu red. Lo correcto")
		fmt.Println("  es ponerlas en VLAN distintas.")
		if strings.ToLower(pedir("  Seguir de todos modos (si/no)", "no")) != "si" {
			return fmt.Errorf("configuracion cancelada")
		}
	}

	c.EscuchaPanel = gestion
	c.EscuchaHoneypots = expuesta
	return nil
}

func preguntarPanel(c *config.Config) error {
	fmt.Println()
	fmt.Println("  El panel pide una contrasena y devuelve todo lo capturado.")
	fmt.Println("  Sin cifrar, eso viaja en claro por tu red.")
	por := "si"
	if !c.PanelHTTPS {
		por = "si"
	}
	c.PanelHTTPS = strings.ToLower(pedir("  ¿Servir el panel por HTTPS? (si/no)", por)) != "no"
	if c.PanelHTTPS {
		fmt.Println("  Se generara un certificado autofirmado: el navegador avisara")
		fmt.Println("  la primera vez, pero el trafico ira cifrado.")
	}
	return nil
}

func preguntarCuenta(almacen *store.Store) error {
	hay, err := almacen.HayUsuarios()
	if err != nil {
		return err
	}
	if hay {
		fmt.Println()
		fmt.Println("  Ya hay cuentas creadas; no se toca ninguna.")
		fmt.Println("  Para anadir otra:  k0pot -crear-usuario <nombre>")
		return nil
	}

	fmt.Println()
	fmt.Println("  Cuenta para entrar al panel.")
	nombre := pedir("  Usuario", "")
	if nombre == "" {
		return fmt.Errorf("hace falta un nombre de usuario")
	}
	return altaUsuario(almacen, nombre)
}

// escribirEnv deja la IP expuesta donde la lee docker compose.
//
// Sin ella compose se niega a arrancar, a proposito: sin IP delante Docker
// publicaria los honeypots en TODAS las interfaces, incluida la de tu red.
func escribirEnv(ruta, expuesta string) error {
	if ruta == "" {
		return nil
	}
	var lineas []string
	if datos, err := os.ReadFile(ruta); err == nil {
		for _, l := range strings.Split(string(datos), "\n") {
			if !strings.HasPrefix(l, "K0POT_IP_EXPUESTA=") {
				lineas = append(lineas, l)
			}
		}
	}
	lineas = append(lineas, "K0POT_IP_EXPUESTA="+expuesta)
	texto := strings.TrimRight(strings.Join(lineas, "\n"), "\n") + "\n"
	if err := os.WriteFile(ruta, []byte(texto), 0o640); err != nil {
		return fmt.Errorf("escribiendo %s: %w", ruta, err)
	}
	fmt.Printf("  %s actualizado\n", ruta)
	return nil
}

// generarCortafuegos deja listo el aislamiento.local.nft con las IP e
// interfaces reales, para que "k0pot-nft aplicar" funcione a la primera sin
// editar nada a mano. Parte de la plantilla del sistema y solo cambia las
// lineas de cabecera -IPs, red de gestion e interfaces-; el resto de las
// reglas no se tocan. Se escribe junto al .env (en el paquete, /etc/k0pot),
// que es justo donde el aplicador lo busca primero.
func generarCortafuegos(c *config.Config, rutaEnv string) error {
	plantilla, err := leerPlantillaNft()
	if err != nil {
		return err
	}
	disponibles := ipsDeLaMaquina()
	ifGestion := interfazDe(c.EscuchaPanel, disponibles)
	ifExpuesta := interfazDe(c.EscuchaHoneypots, disponibles)
	if ifGestion == "" || ifExpuesta == "" {
		return fmt.Errorf("no se pudo determinar el nombre de las interfaces")
	}

	generado := sustituirDefines(plantilla, map[string]string{
		"IP_GESTION":  c.EscuchaPanel,
		"IP_EXPUESTA": c.EscuchaHoneypots,
		"RED_GESTION": red24(c.EscuchaPanel),
		// RED_INTERNA se pone con la red real, no la de ejemplo, para que la
		// regla anti-pivote proteja tu gestion y no la 192.168.1.0/24 del
		// fichero de plantilla.
		"RED_INTERNA": fmt.Sprintf("{ %s, 10.0.0.0/8, 172.16.0.0/12 }", red24(c.EscuchaPanel)),
		"IF_GESTION":  strconv.Quote(ifGestion),
		"IF_EXPUESTA": strconv.Quote(ifExpuesta),
	})

	destino := filepath.Join(dirDe(rutaEnv), "aislamiento.local.nft")
	if err := os.WriteFile(destino, []byte(generado), 0o640); err != nil {
		return fmt.Errorf("escribiendo %s: %w", destino, err)
	}
	fmt.Printf("  %s generado (IP e interfaces reales)\n", destino)
	return nil
}

// leerPlantillaNft encuentra la plantilla de reglas, este instalado por
// paquete o en el arbol de desarrollo.
func leerPlantillaNft() (string, error) {
	for _, ruta := range []string{
		"/usr/share/k0pot/deploy/aislamiento.nft",
		"deploy/aislamiento.nft",
	} {
		if datos, err := os.ReadFile(ruta); err == nil {
			return string(datos), nil
		}
	}
	return "", fmt.Errorf("no se encontro la plantilla aislamiento.nft")
}

// interfazDe devuelve el nombre de la interfaz que tiene esa IP.
func interfazDe(ip string, dirs []direccion) string {
	for _, d := range dirs {
		if d.ip == ip {
			return d.iface
		}
	}
	return ""
}

// red24 deriva la red /24 de una IP: 192.168.10.5 -> 192.168.10.0/24. El
// aislamiento asume /24, igual que el aviso de "misma red" del asistente.
func red24(ip string) string {
	p := strings.Split(ip, ".")
	if len(p) != 4 {
		return ip
	}
	return fmt.Sprintf("%s.%s.%s.0/24", p[0], p[1], p[2])
}

// dirDe da el directorio del .env, donde se co-ubica el cortafuegos. Si no
// hay ruta, el directorio actual.
func dirDe(rutaEnv string) string {
	if rutaEnv == "" {
		return "."
	}
	return filepath.Dir(rutaEnv)
}

// sustituirDefines reemplaza el valor de los "define" indicados, dejando el
// resto del fichero intacto.
func sustituirDefines(plantilla string, valores map[string]string) string {
	lineas := strings.Split(plantilla, "\n")
	for i, l := range lineas {
		t := strings.TrimSpace(l)
		if !strings.HasPrefix(t, "define ") {
			continue
		}
		for nombre, valor := range valores {
			resto := strings.TrimPrefix(t, "define "+nombre)
			// El nombre tiene que casar entero: lo siguiente es espacio o '='.
			if resto != t && (strings.HasPrefix(resto, " ") || strings.HasPrefix(resto, "=")) {
				lineas[i] = fmt.Sprintf("define %s = %s", nombre, valor)
				break
			}
		}
	}
	return strings.Join(lineas, "\n")
}

type direccion struct{ iface, ip string }

func ipsDeLaMaquina() []direccion {
	var out []direccion
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, i := range ifaces {
		dirs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, d := range dirs {
			ipnet, ok := d.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() || ipnet.IP.To4() == nil {
				continue
			}
			out = append(out, direccion{i.Name, ipnet.IP.String()})
		}
	}
	return out
}

// soloReales descarta las interfaces virtuales (loopback, Docker, puentes):
// ninguna sirve como gestion ni como exposicion, y solo estorban al elegir.
func soloReales(dirs []direccion) []direccion {
	var out []direccion
	for _, d := range dirs {
		if interfazReal(d.iface) {
			out = append(out, d)
		}
	}
	return out
}

func interfazReal(nombre string) bool {
	for _, prefijo := range []string{"lo", "docker", "br-", "veth", "virbr", "tap", "kube"} {
		if strings.HasPrefix(nombre, prefijo) {
			return false
		}
	}
	return true
}

// porDefectoRed elige el valor propuesto: la IP que ya estaba configurada si
// es de verdad, o la detectada en esa posicion (0 = gestion, 1 = expuesta).
func porDefectoRed(actual string, reales []direccion, indice int) string {
	if actual != "" && actual != "0.0.0.0" {
		return actual
	}
	if indice < len(reales) {
		return reales[indice].ip
	}
	return ""
}

func existeEnLaMaquina(ip string, dirs []direccion) bool {
	for _, d := range dirs {
		if d.ip == ip {
			return true
		}
	}
	return false
}

func mismaRed(a, b string) bool {
	corta := func(s string) string {
		p := strings.Split(s, ".")
		if len(p) < 3 {
			return s
		}
		return strings.Join(p[:3], ".")
	}
	return corta(a) == corta(b)
}

// pedir lee una respuesta con valor por defecto.
func pedir(pregunta, defecto string) string {
	if defecto != "" && defecto != "0.0.0.0" {
		fmt.Printf("%s [%s]: ", pregunta, defecto)
	} else {
		fmt.Printf("%s: ", pregunta)
		defecto = ""
	}
	linea, err := entradaEstandar.ReadString('\n')
	if err != nil && linea == "" {
		return defecto
	}
	if r := strings.TrimSpace(linea); r != "" {
		return r
	}
	return defecto
}
