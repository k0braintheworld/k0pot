package main

import (
	"fmt"
	"net"
	"os"
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
	if err := preguntarCuenta(almacen); err != nil {
		return err
	}

	fmt.Println()
	fmt.Println("  Configurado. Lo que queda:")
	fmt.Println()
	fmt.Printf("    1. Cortafuegos: sudo k0pot-nft aplicar   (y confirmar en 2 min)\n")
	fmt.Printf("    2. Panel:       https://%s:8080\n", c.EscuchaPanel)
	fmt.Printf("    3. Avisos:      Ajustes → Avisos, para enterarte sin mirar\n")
	fmt.Printf("    4. Router:      redirige los puertos a %s, NUNCA a %s\n",
		c.EscuchaHoneypots, c.EscuchaPanel)
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
	if len(disponibles) < 2 {
		fmt.Println("  AVISO: solo se ve una direccion utilizable. Sin una segunda")
		fmt.Println("  interfaz en otra red, k0Pot no puede aislar nada.")
	}
	for _, d := range disponibles {
		fmt.Printf("    %-12s %s\n", d.iface, d.ip)
	}
	fmt.Println()

	gestion := pedir("  IP de GESTION (para el panel)", c.EscuchaPanel)
	expuesta := pedir("  IP EXPUESTA (para los honeypots)", c.EscuchaHoneypots)

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
