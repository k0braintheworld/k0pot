package report

import "testing"

func TestEsMalformada(t *testing.T) {
	malo := "dispositivos (139) del (140) hogar (141) conectado. (142) Los (143) " +
		"cibercriminales (144) buscan (145) estos (146) equipos (147) porque (148) suelen (149) estar (150) enc"
	if !EsMalformada(malo) {
		t.Fatal("no detecto el texto con numeracion tras cada palabra")
	}

	// Texto normal, con algun ano suelto entre parentesis: NO es malformado.
	bueno := "Este binario es un bot de la familia Mirai. Apareció por primera vez " +
		"en 2016 (2016) y desde entonces han salido muchas variantes. Busca " +
		"cámaras y routers con contraseñas por defecto para reclutarlos."
	if EsMalformada(bueno) {
		t.Fatal("falso positivo con una explicacion normal")
	}
}
