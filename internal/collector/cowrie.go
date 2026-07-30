// Package collector lee los logs que escriben los honeypots y los traduce
// al esquema comun de model.Evento. Cada honeypot tiene aqui su parser;
// el resto del pipeline ya no sabe de que honeypot vino el dato.
package collector

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// lineaCowrie es el subconjunto de campos de cowrie.json que nos interesa.
// Cowrie emite muchos mas, pero anadirlos aqui es trivial cuando hagan falta.
type lineaCowrie struct {
	EventID   string `json:"eventid"`
	Timestamp string `json:"timestamp"`
	// Ojo: uuid identifica al SENSOR, no al evento. Se repite igual en
	// todas las lineas del log, asi que no sirve como clave unica.
	UUID     string `json:"uuid"`
	Session  string `json:"session"`
	Protocol string `json:"protocol"`
	SrcIP    string `json:"src_ip"`

	Username string  `json:"username"`
	Password string  `json:"password"`
	Input    string  `json:"input"`
	Version  string  `json:"version"`
	URL      string  `json:"url"`
	Shasum   string  `json:"shasum"`
	Destfile string  `json:"destfile"`
	Filename string  `json:"filename"`
	Duration float64 `json:"duration"`
	// Destino del tunel que piden abrir.
	DstIP   string `json:"dst_ip"`
	DstPort int    `json:"dst_port"`
}

// tiposCowrie mapea los eventid de Cowrie a nuestro esquema. Lo que no
// aparece aqui se descarta a proposito: kex y fingerprint son detalle
// criptografico de la negociacion SSH, ruido para un informe humano.
var tiposCowrie = map[string]model.TipoEvento{
	"cowrie.session.connect":       model.Conexion,
	"cowrie.login.failed":          model.LoginFallido,
	"cowrie.login.success":         model.LoginExitoso,
	"cowrie.command.input":         model.ComandoEjecutado,
	"cowrie.session.file_download": model.DescargaFichero,
	"cowrie.session.file_upload":   model.DescargaFichero,
	"cowrie.client.version":        model.HuellaCliente,
	// Pedir un canal direct-tcpip es intentar usar la maquina de pasarela
	// para reenviar trafico ajeno. Es de lo mas valioso que registra un
	// honeypot: no buscan tus datos, buscan tu conexion para esconder la
	// suya. Se descartaba por no estar en esta tabla.
	"cowrie.direct-tcpip.request": model.TunelSolicitado,
	"cowrie.direct-tcpip.data":    model.TunelSolicitado,
}

// sinRelleno recupera el evento que haya detras de un bloque de ceros.
//
// Tras un apagado abrupto, el sistema de ficheros puede haber guardado el
// tamano del log pero no su contenido, y el hueco queda relleno de bytes
// nulos. Como en ese hueco tampoco sobrevive el salto de linea, los ceros y
// el evento siguiente llegan aqui como una sola linea: descartarla entera
// -que es lo que pasaba- tira un evento perfectamente legible por culpa de
// la basura que lo precede.
//
// Ocurrio de verdad al reiniciar el servidor: 13.353 ceros y, justo
// detras, una conexion real que se perdio.
func sinRelleno(linea []byte) []byte {
	i := bytes.LastIndexByte(linea, 0)
	if i < 0 {
		return linea
	}
	// Lo que quede tras el ultimo cero. Si no empieza por "{" no es un
	// evento y lo rechazara el propio json.Unmarshal, que es lo correcto:
	// aqui no se adivina, solo se descarta el relleno.
	return bytes.TrimLeft(linea[i+1:], "\x00")
}

// ErrIgnorado indica que la linea era valida pero de un tipo que no
// registramos. No es un fallo: es el caso normal para buena parte del log.
var ErrIgnorado = fmt.Errorf("evento ignorado")

// ParsearCowrie traduce una linea de cowrie.json a un model.Evento.
// Devuelve ErrIgnorado si el evento no es de los que nos interesan.
func ParsearCowrie(linea []byte) (*model.Evento, error) {
	linea = sinRelleno(linea)

	var lc lineaCowrie
	if err := json.Unmarshal(linea, &lc); err != nil {
		return nil, fmt.Errorf("json invalido: %w", err)
	}

	tipo, nosInteresa := tiposCowrie[lc.EventID]
	if !nosInteresa {
		return nil, ErrIgnorado
	}

	ts, err := time.Parse(time.RFC3339Nano, lc.Timestamp)
	if err != nil {
		return nil, fmt.Errorf("timestamp %q ilegible: %w", lc.Timestamp, err)
	}

	protocolo := lc.Protocol
	if protocolo == "" {
		protocolo = "ssh" // Cowrie solo omite el campo en eventos de sesion SSH
	}

	ev := &model.Evento{
		IDExterno: idDeLinea(linea),
		Timestamp: ts.UTC(),
		Honeypot:  "cowrie",
		Protocolo: protocolo,
		SesionID:  lc.Session,
		IP:        lc.SrcIP,
		Tipo:      tipo,
		Detalle:   detalleDe(lc),
		// El clasificador real llega en la fase 4; hasta entonces todo
		// entra como ruido de fondo, que es lo que estadisticamente es.
		Clasificacion: model.RuidoFondo,
	}
	return ev, nil
}

// detalleDe extrae solo los campos con contenido, para no llenar la base
// de datos de claves vacias.
func detalleDe(lc lineaCowrie) map[string]string {
	d := map[string]string{}
	poner := func(k, v string) {
		if v != "" {
			d[k] = v
		}
	}
	poner("usuario", lc.Username)
	poner("password", lc.Password)
	poner("comando", lc.Input)
	poner("cliente", lc.Version)
	poner("url", lc.URL)
	poner("sha256", lc.Shasum)
	// destfile es donde el atacante lo dejo (/dev/.fxcat, /usr/bin/...);
	// filename, el nombre con que lo subio por SFTP. Dice mucho de la
	// intencion, y muchas descargas por "echo" no traen URL pero si esto.
	if dest := lc.Destfile; dest != "" {
		poner("destino_fichero", dest)
	} else {
		poner("destino_fichero", lc.Filename)
	}
	if lc.DstIP != "" && lc.DstPort > 0 {
		poner("destino", fmt.Sprintf("%s:%d", lc.DstIP, lc.DstPort))
	}

	if len(d) == 0 {
		return nil
	}
	return d
}

// idDeLinea deriva una clave estable a partir del contenido de la linea.
//
// Cowrie no numera sus eventos (su campo uuid es el del sensor y se repite
// en todo el log), asi que la idempotencia de la ingesta la construimos
// nosotros: la misma linea siempre da la misma clave, y lineas distintas
// dan claves distintas porque el timestamp baja a microsegundos.
func idDeLinea(linea []byte) string {
	suma := sha256.Sum256(linea)
	return "cowrie:" + hex.EncodeToString(suma[:12])
}
