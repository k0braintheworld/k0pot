package red

import (
	"strings"
	"testing"
)

// Una configuracion de red mal validada deja el servidor inaccesible, asi
// que cada error tipico tiene su comprobacion.
func TestValidar(t *testing.T) {
	casos := []struct {
		nombre  string
		cfg     Config
		mencion string // "" = valida
	}{
		{"correcta", Config{Nombre: "ens19", IP: "10.99.0.10/24", Pasarela: "10.99.0.1"}, ""},
		{"dhcp sin mas datos", Config{Nombre: "ens19", DHCP: true}, ""},
		{"sin prefijo", Config{Nombre: "ens19", IP: "10.99.0.10"}, "prefijo"},
		{"ip inventada", Config{Nombre: "ens19", IP: "999.1.1.1/24"}, "prefijo"},
		{"sin nombre", Config{IP: "10.99.0.10/24"}, "sin nombre"},
		{"pasarela fuera de la red",
			Config{Nombre: "ens19", IP: "10.99.0.10/24", Pasarela: "192.168.1.1"}, "no esta dentro"},
		{"pasarela invalida",
			Config{Nombre: "ens19", IP: "10.99.0.10/24", Pasarela: "no-es-ip"}, "no es una IPv4"},
		{"dns invalido",
			Config{Nombre: "ens19", IP: "10.99.0.10/24", DNS: []string{"1.1.1.1", "nope"}}, "DNS"},
	}
	for _, c := range casos {
		err := Validar([]Config{c.cfg})
		if c.mencion == "" {
			if err != nil {
				t.Errorf("%s: deberia ser valida: %v", c.nombre, err)
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: se acepto una configuracion invalida", c.nombre)
		} else if !strings.Contains(err.Error(), c.mencion) {
			t.Errorf("%s: error = %q, esperaba que mencionara %q", c.nombre, err, c.mencion)
		}
	}
}

func TestValidarInterfazRepetida(t *testing.T) {
	err := Validar([]Config{
		{Nombre: "ens19", IP: "10.0.0.1/24"},
		{Nombre: "ens19", IP: "10.0.0.2/24"},
	})
	if err == nil || !strings.Contains(err.Error(), "dos veces") {
		t.Errorf("error = %v, esperaba que detectara la repeticion", err)
	}
}

func TestGenerarYAML(t *testing.T) {
	yaml, err := GenerarYAML([]Config{
		{Nombre: "ens18", IP: "192.168.1.10/24", Pasarela: "192.168.1.1",
			DNS: []string{"1.1.1.1", "8.8.8.8"}},
		{Nombre: "ens19", DHCP: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, esperado := range []string{
		"network:", "version: 2", "renderer: networkd",
		"ens18:", "addresses: [192.168.1.10/24]",
		"to: default", "via: 192.168.1.1",
		"addresses: [1.1.1.1, 8.8.8.8]",
		"ens19:", "dhcp4: true",
	} {
		if !strings.Contains(yaml, esperado) {
			t.Errorf("falta %q en:\n%s", esperado, yaml)
		}
	}
	// gateway4 esta obsoleto en netplan y genera avisos.
	if strings.Contains(yaml, "gateway4") {
		t.Error("usa gateway4, que netplan da por obsoleto")
	}
}

// Generar no debe producir nada si la configuracion no vale: es la ultima
// barrera antes de que el YAML llegue al sistema.
func TestGenerarRechazaLoInvalido(t *testing.T) {
	if _, err := GenerarYAML([]Config{{Nombre: "ens19", IP: "chorrada"}}); err == nil {
		t.Error("genero YAML a partir de una configuracion invalida")
	}
}

func TestVirtualesFueraDeLaLista(t *testing.T) {
	for _, n := range []string{"docker0", "br-3161ac00cd68", "veth8b7a6fe", "virbr0"} {
		if !esVirtual(n) {
			t.Errorf("%q deberia considerarse virtual", n)
		}
	}
	for _, n := range []string{"ens18", "eth0", "enp3s0", "wlan0"} {
		if esVirtual(n) {
			t.Errorf("%q no es virtual", n)
		}
	}
}
