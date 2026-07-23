package episodio

import (
	"testing"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
)

var base = time.Date(2026, 7, 23, 8, 0, 0, 0, time.UTC)

func ev(min int, ip, proto string, tipo model.TipoEvento, det map[string]string) model.Evento {
	return model.Evento{
		Timestamp: base.Add(time.Duration(min) * time.Minute),
		IP:        ip, Protocolo: proto, Tipo: tipo, Detalle: det,
		Clasificacion: model.RuidoFondo,
	}
}

func TestUnAtaqueEsUnEpisodio(t *testing.T) {
	es := Agrupar([]model.Evento{
		ev(0, "1.2.3.4", "ssh", model.Conexion, nil),
		ev(1, "1.2.3.4", "ssh", model.LoginFallido, map[string]string{"usuario": "root", "password": "123456"}),
		ev(2, "1.2.3.4", "ssh", model.LoginExitoso, map[string]string{"usuario": "root", "password": "admin"}),
		ev(3, "1.2.3.4", "ssh", model.ComandoEjecutado, map[string]string{"comando": "uname -a"}),
	}, HuecoPorDefecto)

	if len(es) != 1 {
		t.Fatalf("se esperaba 1 episodio, hubo %d", len(es))
	}
	e := es[0]
	if e.Severidad != Intrusion {
		t.Errorf("severidad = %s, se esperaba intrusion", e.Severidad)
	}
	if !e.LoginExitoso || e.LoginsFallidos != 1 || len(e.Comandos) != 1 {
		t.Errorf("resumen mal recogido: %+v", e)
	}
	if e.Eventos != 4 {
		t.Errorf("eventos = %d, se esperaban 4", e.Eventos)
	}
}

// El silencio separa ataques: la misma IP mañana no es el mismo episodio.
func TestElSilencioSeparaEpisodios(t *testing.T) {
	es := Agrupar([]model.Evento{
		ev(0, "1.2.3.4", "ssh", model.Conexion, nil),
		ev(5, "1.2.3.4", "ssh", model.Conexion, nil),
		ev(120, "1.2.3.4", "ssh", model.Conexion, nil), // dos horas despues
	}, HuecoPorDefecto)

	if len(es) != 2 {
		t.Fatalf("se esperaban 2 episodios, hubo %d", len(es))
	}
	if es[0].Eventos != 2 || es[1].Eventos != 1 {
		t.Errorf("mal repartidos: %d y %d", es[0].Eventos, es[1].Eventos)
	}
}

func TestSeSeparaPorIPyProtocolo(t *testing.T) {
	es := Agrupar([]model.Evento{
		ev(0, "1.2.3.4", "ssh", model.Conexion, nil),
		ev(1, "1.2.3.4", "http", model.Conexion, nil),
		ev(2, "5.6.7.8", "ssh", model.Conexion, nil),
	}, HuecoPorDefecto)

	if len(es) != 3 {
		t.Fatalf("cada IP y protocolo va por su lado: %d episodios", len(es))
	}
}

// Lo que importa es lo que consiguio, no cuanto insistio.
func TestOrdenaPorLoConseguidoNoPorVolumen(t *testing.T) {
	var ruidoso []model.Evento
	for i := 0; i < 500; i++ {
		ruidoso = append(ruidoso, ev(i%20, "9.9.9.9", "ftp", model.Conexion, nil))
	}
	uno := []model.Evento{
		ev(0, "1.1.1.1", "ssh", model.LoginExitoso, map[string]string{"usuario": "root"}),
		ev(1, "1.1.1.1", "ssh", model.ComandoEjecutado, map[string]string{"comando": "cat /etc/passwd"}),
	}
	es := Agrupar(append(ruidoso, uno...), HuecoPorDefecto)
	PorGravedad(es)

	if es[0].IP != "1.1.1.1" {
		t.Errorf("primero salio %s con %d eventos; debia mandar la intrusion",
			es[0].IP, es[0].Eventos)
	}
}

func TestSeveridadPorLoQueHizo(t *testing.T) {
	casos := []struct {
		nombre string
		evs    []model.Evento
		quiero Severidad
	}{
		{"solo conecta", []model.Evento{ev(0, "1.1.1.1", "ftp", model.Conexion, nil)}, Roce},
		{"prueba credenciales", []model.Evento{
			ev(0, "1.1.1.1", "ssh", model.LoginFallido, map[string]string{"usuario": "root"})}, Tanteo},
		{"tantea rutas", []model.Evento{
			ev(0, "1.1.1.1", "http", model.PeticionHTTP, map[string]string{"ruta": "/.env"})}, Tanteo},
		{"entra", []model.Evento{
			ev(0, "1.1.1.1", "ssh", model.LoginExitoso, map[string]string{"usuario": "root"})}, Acceso},
		{"entra y actua", []model.Evento{
			ev(0, "1.1.1.1", "ssh", model.LoginExitoso, map[string]string{"usuario": "root"}),
			ev(1, "1.1.1.1", "ssh", model.ComandoEjecutado, map[string]string{"comando": "id"})}, Intrusion},
		{"descarga", []model.Evento{
			ev(0, "1.1.1.1", "ssh", model.DescargaFichero, map[string]string{"url": "http://x/bot.sh"})}, Intrusion},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			es := Agrupar(c.evs, HuecoPorDefecto)
			if es[0].Severidad != c.quiero {
				t.Errorf("severidad = %s, se esperaba %s", es[0].Severidad, c.quiero)
			}
		})
	}
}

// Un evento marcado como revisar sube el episodio aunque su tipo sea una
// simple conexion: la clasificacion ya sabe cosas que el tipo no dice.
func TestLaClasificacionSubeLaSeveridad(t *testing.T) {
	e := ev(0, "1.1.1.1", "redis", model.Conexion, nil)
	e.Clasificacion = model.Notable
	es := Agrupar([]model.Evento{e}, HuecoPorDefecto)
	if es[0].Severidad != Tanteo {
		t.Errorf("severidad = %s, se esperaba tanteo", es[0].Severidad)
	}
}

func TestResumenSeLeeSinAbrirElEpisodio(t *testing.T) {
	es := Agrupar([]model.Evento{
		ev(0, "1.2.3.4", "ssh", model.LoginFallido, map[string]string{"usuario": "root", "password": "a"}),
		ev(1, "1.2.3.4", "ssh", model.LoginFallido, map[string]string{"usuario": "root", "password": "b"}),
		ev(2, "1.2.3.4", "ssh", model.LoginExitoso, map[string]string{"usuario": "admin", "password": "c"}),
		ev(3, "1.2.3.4", "ssh", model.ComandoEjecutado, map[string]string{"comando": "id"}),
	}, HuecoPorDefecto)

	r := es[0].Resumen
	for _, quiero := range []string{"admin", "1 comando", "2 credenciales"} {
		if !contiene(r, quiero) {
			t.Errorf("el resumen %q no menciona %q", r, quiero)
		}
	}
}

// "Solo conecto" desaprovecha lo que sabemos: a que puerto llamaron y que
// se fueron sin decir nada. Eso es un sondeo de puertos, y nombrarlo
// ahorra tener que deducirlo.
func TestUnSondeoDePuertosSeLlamaPorSuNombre(t *testing.T) {
	puerto := map[string]string{"puerto": "2121"}
	es := Agrupar([]model.Evento{
		ev(0, "1.2.3.4", "ftp", model.Conexion, puerto),
		ev(1, "1.2.3.4", "ftp", model.Conexion, puerto),
	}, HuecoPorDefecto)

	e := es[0]
	if !e.SoloConexiones {
		t.Error("nadie hablo: deberia constar como sondeo")
	}
	if e.Puerto != "2121" {
		t.Errorf("puerto = %q, se esperaba 2121", e.Puerto)
	}
	for _, quiero := range []string{"2121", "sin enviar nada", "2 veces"} {
		if !contiene(e.Resumen, quiero) {
			t.Errorf("el resumen %q no menciona %q", e.Resumen, quiero)
		}
	}
}

// En cuanto dicen algo deja de ser un sondeo, aunque sea un solo comando.
func TestHablarDejaDeSerUnSondeo(t *testing.T) {
	es := Agrupar([]model.Evento{
		ev(0, "1.2.3.4", "ftp", model.Conexion, map[string]string{"puerto": "2121"}),
		ev(1, "1.2.3.4", "ftp", model.LoginFallido, map[string]string{"usuario": "anonymous"}),
	}, HuecoPorDefecto)
	if es[0].SoloConexiones {
		t.Error("probaron credenciales: ya no es un sondeo de puertos")
	}
}

// Un bot con un diccionario enorme no puede hacer crecer una fila sin fin.
func TestLasListasTienenTope(t *testing.T) {
	var evs []model.Evento
	for i := 0; i < 5000; i++ {
		evs = append(evs, ev(0, "1.1.1.1", "ssh", model.LoginFallido,
			map[string]string{"usuario": "root", "password": string(rune('a' + i%26))}))
	}
	es := Agrupar(evs, HuecoPorDefecto)
	if len(es[0].Passwords) > 20 {
		t.Errorf("la lista de contrasenas crecio a %d", len(es[0].Passwords))
	}
	if es[0].LoginsFallidos != 5000 {
		t.Errorf("el recuento si debe ser exacto: %d", es[0].LoginsFallidos)
	}
}

func TestLaClaveEsEstable(t *testing.T) {
	evs := []model.Evento{ev(0, "1.2.3.4", "ssh", model.Conexion, nil)}
	if Agrupar(evs, HuecoPorDefecto)[0].Clave != Agrupar(evs, HuecoPorDefecto)[0].Clave {
		t.Error("la clave cambia entre reconstrucciones; se duplicarian los episodios")
	}
}

func contiene(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// La etiqueta y el texto no pueden contradecirse: un "tanteo" cuyo resumen
// diga "solo conecto" hace que quien lo lee deje de fiarse del panel.
func TestElResumenNuncaContradiceALaSeveridad(t *testing.T) {
	e := ev(0, "1.1.1.1", "redis", model.Conexion, nil)
	e.Clasificacion = model.Revisar
	e.Motivo = "uso un comando de administracion"

	es := Agrupar([]model.Evento{e, ev(1, "1.1.1.1", "redis", model.Conexion, nil)}, HuecoPorDefecto)
	if es[0].Severidad == Roce {
		t.Fatal("la clasificacion deberia haber elevado la severidad")
	}
	if contiene(es[0].Resumen, "olo conecto") {
		t.Errorf("resumen %q contradice la severidad %s", es[0].Resumen, es[0].Severidad)
	}
	if !contiene(es[0].Resumen, "administracion") {
		t.Errorf("el resumen deberia explicar el motivo: %q", es[0].Resumen)
	}
}

// El caso que lo destapo: Censys sondeando Redis con PING, INFO, un
// comando inexistente y QUIT salia marcado como INTRUSION. En Redis un
// "comando" es un verbo del protocolo, no una linea tecleada en una
// shell; marcarlo asi ahoga las alertas de verdad entre ruido.
func TestSondearRedisNoEsUnaIntrusion(t *testing.T) {
	var evs []model.Evento
	for _, c := range []string{"PING", "INFO", "NONEXISTENT", "QUIT"} {
		evs = append(evs, ev(0, "1.1.1.1", "redis", model.ComandoEjecutado,
			map[string]string{"comando": c}))
	}
	e := Agrupar(evs, HuecoPorDefecto)[0]

	if e.Severidad == Intrusion {
		t.Errorf("un sondeo de Redis no puede ser intrusion: %+v", e)
	}
	if contiene(e.Resumen, "ejecuto") {
		t.Errorf("el resumen %q hace pensar que alguien entro", e.Resumen)
	}
}

// Pero no todos los verbos son inofensivos: CONFIG SET es el primer paso
// de la via clasica de Redis para escribir un fichero ajeno en disco.
func TestConfigSetDeRedisSiEsUnaIntrusion(t *testing.T) {
	e := Agrupar([]model.Evento{
		ev(0, "1.1.1.1", "redis", model.ComandoEjecutado, map[string]string{"comando": "PING"}),
		ev(1, "1.1.1.1", "redis", model.ComandoEjecutado,
			map[string]string{"comando": "CONFIG SET dir /var/spool/cron"}),
	}, HuecoPorDefecto)[0]

	if e.Severidad != Intrusion {
		t.Errorf("CONFIG SET deberia ser intrusion, dio %s", e.Severidad)
	}
}

// En una shell de verdad, cualquier comando si significa que estan dentro.
func TestUnComandoEnShellSigueSiendoIntrusion(t *testing.T) {
	e := Agrupar([]model.Evento{
		ev(0, "1.1.1.1", "ssh", model.ComandoEjecutado, map[string]string{"comando": "ls"}),
	}, HuecoPorDefecto)[0]
	if e.Severidad != Intrusion {
		t.Errorf("un comando por SSH es intrusion, dio %s", e.Severidad)
	}
}

// Ante un protocolo que no conocemos conviene alertar y que alguien lo
// mire. Callarse ante lo desconocido es como se pierden los incidentes.
func TestProtocoloDesconocidoAlerta(t *testing.T) {
	e := Agrupar([]model.Evento{
		ev(0, "1.1.1.1", "protocolo-raro", model.ComandoEjecutado,
			map[string]string{"comando": "algo"}),
	}, HuecoPorDefecto)[0]
	if e.Severidad != Intrusion {
		t.Errorf("lo desconocido deberia alertar, dio %s", e.Severidad)
	}
}

// Servirse de la maquina pesa como una intrusion aunque no se teclee un
// solo comando: no buscan tus datos, buscan tu conexion.
func TestPedirUnTunelEsIntrusion(t *testing.T) {
	e := Agrupar([]model.Evento{
		ev(0, "1.1.1.1", "ssh", model.LoginExitoso, map[string]string{"usuario": "root", "password": "admin"}),
		ev(1, "1.1.1.1", "ssh", model.TunelSolicitado, map[string]string{"destino": "8.8.8.8:443"}),
	}, HuecoPorDefecto)[0]

	if e.Severidad != Intrusion {
		t.Errorf("severidad = %s, se esperaba intrusion", e.Severidad)
	}
	if !contiene(e.Resumen, "pasarela") {
		t.Errorf("el resumen deberia decirlo: %q", e.Resumen)
	}
}
