// Package red permite ver y cambiar la configuracion de red del servidor.
//
// El proceso corre sin privilegios, asi que todo lo que toca el sistema pasa
// por un unico ayudante (k0pot-red) autorizado en sudoers para nada mas. Si
// ese ayudante no esta instalado, aqui se puede seguir editando y generando
// la configuracion: solo falta aplicarla a mano.
//
// Cambiar la IP de un servidor remoto es la forma clasica de quedarse fuera,
// asi que aplicar SIEMPRE arranca un temporizador de reversion que hay que
// cancelar confirmando desde la nueva direccion.
package red

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// Ayudante es el binario privilegiado. Variable para poder sustituirlo en
// los tests.
var Ayudante = "/usr/local/sbin/k0pot-red"

// Interfaz es una tarjeta de red del sistema.
type Interfaz struct {
	Nombre     string   `json:"nombre"`
	MAC        string   `json:"mac"`
	Activa     bool     `json:"activa"`
	IPs        []string `json:"ips"`
	Gestionada bool     `json:"gestionada"` // la configura k0pot
}

// Config es lo que se quiere para una interfaz.
type Config struct {
	Nombre   string   `json:"nombre"`
	DHCP     bool     `json:"dhcp"`
	IP       string   `json:"ip"`       // con prefijo: 10.0.0.5/24
	Pasarela string   `json:"pasarela"` // opcional
	DNS      []string `json:"dns"`      // opcional
}

// Listar devuelve las interfaces fisicas del sistema.
//
// Se dejan fuera las virtuales de Docker y las de loopback: no son cosas que
// nadie quiera reconfigurar desde aqui, y ensucian la lista.
func Listar(gestionadas map[string]bool) ([]Interfaz, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("listando interfaces: %w", err)
	}

	var out []Interfaz
	for _, ifa := range ifaces {
		if ifa.Flags&net.FlagLoopback != 0 || esVirtual(ifa.Name) {
			continue
		}
		in := Interfaz{
			Nombre:     ifa.Name,
			MAC:        ifa.HardwareAddr.String(),
			Activa:     ifa.Flags&net.FlagUp != 0,
			Gestionada: gestionadas[ifa.Name],
		}
		dirs, _ := ifa.Addrs()
		for _, d := range dirs {
			if ipnet, ok := d.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				in.IPs = append(in.IPs, ipnet.String())
			}
		}
		out = append(out, in)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Nombre < out[j].Nombre })
	return out, nil
}

func esVirtual(nombre string) bool {
	for _, p := range []string{"docker", "br-", "veth", "virbr", "tun", "tap"} {
		if strings.HasPrefix(nombre, p) {
			return true
		}
	}
	return false
}

// Validar comprueba una configuracion antes de acercarla al sistema.
func Validar(cs []Config) error {
	var problemas []string
	vistas := map[string]bool{}

	for _, c := range cs {
		if c.Nombre == "" {
			problemas = append(problemas, "hay una interfaz sin nombre")
			continue
		}
		if vistas[c.Nombre] {
			problemas = append(problemas, fmt.Sprintf("%s aparece dos veces", c.Nombre))
		}
		vistas[c.Nombre] = true

		if c.DHCP {
			continue // con DHCP no hay nada mas que validar
		}

		ip, red, err := net.ParseCIDR(c.IP)
		if err != nil {
			problemas = append(problemas,
				fmt.Sprintf("%s: %q no es una direccion con prefijo (ej. 10.0.0.5/24)", c.Nombre, c.IP))
			continue
		}
		if ip.To4() == nil {
			problemas = append(problemas, fmt.Sprintf("%s: solo se admite IPv4", c.Nombre))
			continue
		}

		if c.Pasarela != "" {
			g := net.ParseIP(c.Pasarela)
			if g == nil || g.To4() == nil {
				problemas = append(problemas,
					fmt.Sprintf("%s: la pasarela %q no es una IPv4", c.Nombre, c.Pasarela))
			} else if !red.Contains(g) {
				// Un fallo facil de cometer y que deja la maquina sin salida.
				problemas = append(problemas,
					fmt.Sprintf("%s: la pasarela %s no esta dentro de %s", c.Nombre, c.Pasarela, red))
			}
		}
		for _, d := range c.DNS {
			if net.ParseIP(d) == nil {
				problemas = append(problemas, fmt.Sprintf("%s: DNS %q invalido", c.Nombre, d))
			}
		}
	}

	if len(problemas) > 0 {
		return fmt.Errorf("%s", strings.Join(problemas, "; "))
	}
	return nil
}

// GenerarYAML produce el fichero de netplan que k0pot gestiona.
//
// Va aparte del que dejo el instalador y con un nombre posterior (90-), que
// es como netplan resuelve la precedencia: asi no hay que leer ni tocar la
// configuracion original, que ademas solo puede leer root.
func GenerarYAML(cs []Config) (string, error) {
	if err := Validar(cs); err != nil {
		return "", err
	}

	var b bytes.Buffer
	b.WriteString("# Generado por k0Pot. No editar a mano: el panel lo sobrescribe.\n")
	b.WriteString("network:\n  version: 2\n  renderer: networkd\n  ethernets:\n")

	for _, c := range cs {
		fmt.Fprintf(&b, "    %s:\n", c.Nombre)
		if c.DHCP {
			b.WriteString("      dhcp4: true\n")
			continue
		}
		b.WriteString("      dhcp4: false\n")
		fmt.Fprintf(&b, "      addresses: [%s]\n", c.IP)
		if c.Pasarela != "" {
			// routes en vez de gateway4, que netplan marco obsoleto.
			b.WriteString("      routes:\n")
			fmt.Fprintf(&b, "        - to: default\n          via: %s\n", c.Pasarela)
		}
		if len(c.DNS) > 0 {
			fmt.Fprintf(&b, "      nameservers:\n        addresses: [%s]\n", strings.Join(c.DNS, ", "))
		}
	}
	return b.String(), nil
}

// Disponible dice si el ayudante privilegiado esta instalado y autorizado.
func Disponible() bool {
	ctx, cancelar := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelar()
	return exec.CommandContext(ctx, "sudo", "-n", Ayudante, "mostrar").Run() == nil
}

// Aplicar manda la configuracion al ayudante. La red se revierte sola si
// nadie confirma a tiempo.
func Aplicar(ctx context.Context, yaml string) (string, error) {
	return ejecutar(ctx, "aplicar", yaml)
}

// Confirmar cancela la reversion pendiente.
func Confirmar(ctx context.Context) (string, error) { return ejecutar(ctx, "confirmar", "") }

// Revertir deshace el ultimo cambio sin esperar.
func Revertir(ctx context.Context) (string, error) { return ejecutar(ctx, "revertir", "") }

// Actual devuelve la configuracion que gestiona k0pot.
func Actual(ctx context.Context) (string, error) { return ejecutar(ctx, "mostrar", "") }

func ejecutar(ctx context.Context, orden, entrada string) (string, error) {
	cmd := exec.CommandContext(ctx, "sudo", "-n", Ayudante, orden)
	if entrada != "" {
		cmd.Stdin = strings.NewReader(entrada)
	}
	salida, err := cmd.CombinedOutput()
	texto := strings.TrimSpace(string(salida))
	if err != nil {
		if texto == "" {
			texto = err.Error()
		}
		return texto, fmt.Errorf("el ayudante de red fallo: %s", texto)
	}
	return texto, nil
}
