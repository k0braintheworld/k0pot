package geoip

import "testing"

const base = "testdata/GeoLite2-City-Test.mmdb"

func TestSituaUnaIPEnSuCiudad(t *testing.T) {
	loc, err := Abrir(base)
	if err != nil {
		t.Fatal(err)
	}
	defer loc.Cerrar()

	casos := []struct {
		ip, pais, ciudad string
	}{
		{"81.2.69.142", "GB", "Londres"},
		{"89.160.20.112", "SE", "Linköping"},
		{"216.160.83.56", "US", "Milton"},
	}
	for _, c := range casos {
		t.Run(c.ip, func(t *testing.T) {
			l, ok := Situar(loc, c.ip)
			if !ok {
				t.Fatalf("no se situo %s", c.ip)
			}
			if l.Pais != c.pais {
				t.Errorf("pais = %q, se esperaba %q", l.Pais, c.pais)
			}
			if l.Ciudad != c.ciudad {
				t.Errorf("ciudad = %q, se esperaba %q", l.Ciudad, c.ciudad)
			}
			if !l.TieneCoordenadas() {
				t.Error("deberia traer coordenadas")
			}
		})
	}
}

// Una IP que no esta en la base no debe romper ni inventar una ubicacion.
func TestUnaIPDesconocidaNoSeInventa(t *testing.T) {
	loc, _ := Abrir(base)
	defer loc.Cerrar()
	if _, ok := Situar(loc, "203.0.113.99"); ok {
		t.Error("una IP fuera de la base no deberia situarse")
	}
}

// Sin fichero, el localizador no falla: simplemente no situa nada, y k0Pot
// se conforma con el pais.
func TestSinFicheroNoSituaPeroNoFalla(t *testing.T) {
	loc, err := Abrir("")
	if err != nil {
		t.Fatal(err)
	}
	if loc.Activo() {
		t.Error("sin ruta no deberia estar activo")
	}
	if _, ok := loc.Situar("81.2.69.142"); ok {
		t.Error("sin base no puede situar nada")
	}
}

func TestUnFicheroInexistenteEsError(t *testing.T) {
	if _, err := Abrir("no/existe.mmdb"); err == nil {
		t.Error("deberia fallar con una ruta que no existe")
	}
}

// La isla Null (0,0) es agua, no una ciudad: no cuenta como coordenadas.
func TestElOrigenNoCuentaComoUbicacion(t *testing.T) {
	if (Lugar{Latitud: 0, Longitud: 0}).TieneCoordenadas() {
		t.Error("(0,0) no es una ubicacion real")
	}
	if !(Lugar{Latitud: 40.4}).TieneCoordenadas() {
		t.Error("una latitud real si cuenta")
	}
}

// Recargar cambia la base en caliente sin reiniciar.
func TestRecargarActivaYDesactiva(t *testing.T) {
	loc, _ := Abrir("")
	if err := loc.Recargar(base); err != nil {
		t.Fatal(err)
	}
	if !loc.Activo() {
		t.Error("tras recargar con base deberia estar activo")
	}
	if err := loc.Recargar(""); err != nil {
		t.Fatal(err)
	}
	if loc.Activo() {
		t.Error("recargar con ruta vacia deberia desactivar")
	}
}

// Situar acepta un *Localizador nil-safe: el bucle de enriquecimiento lo
// llama siempre, tenga base o no.
func Situar(l *Localizador, ip string) (Lugar, bool) { return l.Situar(ip) }
