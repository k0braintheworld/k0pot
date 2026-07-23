package collector

import (
	"bufio"
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/k0braintheworld/k0pot/internal/model"
)

const fixture = "../../testdata/cowrie/sesion-ejemplo.json"

func TestParsearCowrieConexion(t *testing.T) {
	linea := []byte(`{"eventid":"cowrie.session.connect","src_ip":"203.0.113.7",
	 "src_port":58621,"dst_port":2222,"session":"8949f54197f3","protocol":"ssh",
	 "uuid":"26508e4e-6eff-11f1-9488-c6c9e32495b7",
	 "timestamp":"2026-07-22T18:18:18.572993Z"}`)

	ev, err := ParsearCowrie(linea)
	if err != nil {
		t.Fatalf("no esperaba error: %v", err)
	}
	if ev.Tipo != model.Conexion {
		t.Errorf("tipo = %q, esperaba %q", ev.Tipo, model.Conexion)
	}
	if ev.IP != "203.0.113.7" {
		t.Errorf("ip = %q", ev.IP)
	}
	if ev.Honeypot != "cowrie" || ev.Protocolo != "ssh" {
		t.Errorf("honeypot/protocolo = %q/%q", ev.Honeypot, ev.Protocolo)
	}
	if ev.IDExterno == "" {
		t.Error("evento sin id externo")
	}
	if ev.Timestamp.Year() != 2026 || ev.Timestamp.Minute() != 18 {
		t.Errorf("timestamp mal parseado: %v", ev.Timestamp)
	}
}

func TestParsearCowrieLoginRecogeCredenciales(t *testing.T) {
	linea := []byte(`{"eventid":"cowrie.login.failed","username":"root",
	 "password":"123456","src_ip":"10.0.0.9","session":"abc","protocol":"ssh",
	 "uuid":"u-1","timestamp":"2026-07-22T18:18:19.000000Z"}`)

	ev, err := ParsearCowrie(linea)
	if err != nil {
		t.Fatalf("no esperaba error: %v", err)
	}
	if ev.Tipo != model.LoginFallido {
		t.Errorf("tipo = %q", ev.Tipo)
	}
	if ev.Detalle["usuario"] != "root" || ev.Detalle["password"] != "123456" {
		t.Errorf("detalle = %v", ev.Detalle)
	}
}

func TestParsearCowrieIgnoraRuidoCriptografico(t *testing.T) {
	// kex y fingerprint son detalle de la negociacion SSH: validos, pero
	// sin valor para un informe humano.
	for _, id := range []string{"cowrie.client.kex", "cowrie.client.fingerprint"} {
		linea := []byte(`{"eventid":"` + id + `","src_ip":"10.0.0.9",
		 "timestamp":"2026-07-22T18:18:19.000000Z"}`)
		if _, err := ParsearCowrie(linea); !errors.Is(err, ErrIgnorado) {
			t.Errorf("%s: esperaba ErrIgnorado, obtuve %v", id, err)
		}
	}
}

func TestParsearCowrieRechazaBasura(t *testing.T) {
	if _, err := ParsearCowrie([]byte(`{esto no es json`)); err == nil {
		t.Error("esperaba error con JSON invalido")
	}
	// JSON valido pero con timestamp ilegible: tiene que fallar, no colar
	// un evento con fecha cero.
	linea := []byte(`{"eventid":"cowrie.login.failed","timestamp":"ayer"}`)
	if _, err := ParsearCowrie(linea); err == nil {
		t.Error("esperaba error con timestamp invalido")
	}
}

// TestParsearFixtureReal recorre los eventos que capturamos de verdad en el
// servidor: es la garantia de que parseamos lo que Cowrie escribe, no lo
// que creemos que escribe.
func TestParsearFixtureReal(t *testing.T) {
	f, err := os.Open(fixture)
	if err != nil {
		t.Skipf("sin fixture disponible: %v", err)
	}
	defer f.Close()

	porTipo := map[model.TipoEvento]int{}
	var total, ignorados int

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		linea := sc.Bytes()
		if len(linea) == 0 {
			continue
		}
		total++
		ev, err := ParsearCowrie(linea)
		if errors.Is(err, ErrIgnorado) {
			ignorados++
			continue
		}
		if err != nil {
			t.Fatalf("linea %d ilegible: %v", total, err)
		}
		if ev.IP == "" {
			t.Errorf("linea %d: evento sin IP de origen", total)
		}
		if ev.IDExterno == "" {
			t.Errorf("linea %d: evento sin id externo, la ingesta no seria idempotente", total)
		}
		porTipo[ev.Tipo]++
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("leyendo fixture: %v", err)
	}

	if total == 0 {
		t.Fatal("el fixture esta vacio")
	}
	// El fixture son 3 sesiones SSH fallidas.
	for _, tipo := range []model.TipoEvento{
		model.Conexion, model.LoginFallido, model.HuellaCliente,
	} {
		if porTipo[tipo] == 0 {
			t.Errorf("no se reconocio ningun evento de tipo %q", tipo)
		}
	}
	t.Logf("fixture: %d lineas, %d ignoradas, por tipo: %v",
		total, ignorados, porTipo)
}

// El campo uuid de Cowrie identifica al sensor, no al evento: es identico
// en todas las lineas del log. Si lo usaramos como clave de idempotencia,
// la restriccion UNIQUE colapsaria el log entero en una sola fila y
// perderiamos casi todos los ataques sin ningun error visible.
func TestIDExternoDistingueEventosDeLaMismaSesion(t *testing.T) {
	const mismoUUID = "26508e4e-6eff-11f1-9488-c6c9e32495b7"
	lineas := [][]byte{
		[]byte(`{"eventid":"cowrie.session.connect","src_ip":"10.0.0.9",
		 "session":"s1","uuid":"` + mismoUUID + `",
		 "timestamp":"2026-07-22T18:18:18.572993Z"}`),
		[]byte(`{"eventid":"cowrie.login.failed","username":"root","password":"a",
		 "src_ip":"10.0.0.9","session":"s1","uuid":"` + mismoUUID + `",
		 "timestamp":"2026-07-22T18:18:18.689104Z"}`),
		[]byte(`{"eventid":"cowrie.login.failed","username":"root","password":"b",
		 "src_ip":"10.0.0.9","session":"s1","uuid":"` + mismoUUID + `",
		 "timestamp":"2026-07-22T18:18:18.911002Z"}`),
	}

	vistos := map[string]bool{}
	for i, l := range lineas {
		ev, err := ParsearCowrie(l)
		if err != nil {
			t.Fatalf("linea %d: %v", i, err)
		}
		if vistos[ev.IDExterno] {
			t.Fatalf("linea %d reutiliza el id %q: la ingesta perderia eventos",
				i, ev.IDExterno)
		}
		vistos[ev.IDExterno] = true
	}
}

// La misma linea releida tiene que dar la misma clave, o reprocesar un log
// duplicaria todo.
func TestIDExternoEsEstable(t *testing.T) {
	linea := []byte(`{"eventid":"cowrie.login.failed","username":"root",
	 "src_ip":"10.0.0.9","timestamp":"2026-07-22T18:18:19.000000Z"}`)

	primero, err := ParsearCowrie(linea)
	if err != nil {
		t.Fatal(err)
	}
	segundo, err := ParsearCowrie(linea)
	if err != nil {
		t.Fatal(err)
	}
	if primero.IDExterno != segundo.IDExterno {
		t.Errorf("ids distintos para la misma linea: %q vs %q",
			primero.IDExterno, segundo.IDExterno)
	}
}

// Pedir un canal direct-tcpip es intentar usar la maquina de pasarela.
// Se descartaba en silencio por no estar en la tabla de tipos, y es de lo
// mas valioso que registra un honeypot: el primer acceso real que capturo
// k0Pot no tecleo ni un comando, solo pidio un tunel hacia 8.8.8.8:443.
func TestSeCapturaLaPeticionDeTunel(t *testing.T) {
	linea := []byte(`{"eventid":"cowrie.direct-tcpip.request","src_ip":"203.0.113.9",` +
		`"dst_ip":"8.8.8.8","dst_port":443,"session":"abc","protocol":"ssh",` +
		`"timestamp":"2026-07-23T11:40:07.000Z"}`)

	ev, err := ParsearCowrie(linea)
	if err != nil {
		t.Fatalf("deberia capturarse: %v", err)
	}
	if ev.Tipo != model.TunelSolicitado {
		t.Errorf("tipo = %s", ev.Tipo)
	}
	if ev.Detalle["destino"] != "8.8.8.8:443" {
		t.Errorf("destino = %q, se esperaba 8.8.8.8:443", ev.Detalle["destino"])
	}
}

// Tras un apagado abrupto el sistema de ficheros deja un hueco de ceros en
// el log. Como ahi tampoco sobrevive el salto de linea, el relleno y el
// evento siguiente llegan como una sola linea, y descartarla entera tira un
// evento legible por culpa de la basura que lo precede.
//
// Paso de verdad al reiniciar el servidor: 13.353 ceros y, justo detras,
// una conexion real que se perdio.
func TestSeRecuperaElEventoQueSigueAlRellenoDeCeros(t *testing.T) {
	bueno := []byte(`{"eventid":"cowrie.session.connect","src_ip":"114.66.37.86",` +
		`"session":"abc","protocol":"ssh","timestamp":"2026-07-23T13:40:00.000Z"}`)
	linea := append(bytes.Repeat([]byte{0}, 13353), bueno...)

	ev, err := ParsearCowrie(linea)
	if err != nil {
		t.Fatalf("deberia recuperarse: %v", err)
	}
	if ev.IP != "114.66.37.86" {
		t.Errorf("IP = %q", ev.IP)
	}
}

// Una linea de puros ceros no es un evento y debe rechazarse: aqui no se
// adivina nada, solo se descarta el relleno.
func TestUnaLineaDeSoloCerosSigueSiendoIlegible(t *testing.T) {
	if _, err := ParsearCowrie(bytes.Repeat([]byte{0}, 500)); err == nil {
		t.Error("deberia rechazarse")
	}
}

// Y una linea normal no se toca.
func TestUnaLineaSinCerosNoSeAltera(t *testing.T) {
	linea := []byte(`{"eventid":"cowrie.session.connect","src_ip":"1.2.3.4",` +
		`"session":"x","protocol":"ssh","timestamp":"2026-07-23T13:40:00.000Z"}`)
	ev, err := ParsearCowrie(linea)
	if err != nil || ev.IP != "1.2.3.4" {
		t.Errorf("ev=%v err=%v", ev, err)
	}
}
