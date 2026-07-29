package trampa

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"math"
	"net"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
)

// MongoDB finge un MongoDB abierto sin autenticacion, el otro gran data store
// que rastrean para vaciar. Habla su protocolo binario lo justo para pasar el
// apreton de manos (isMaster/hello), decir su version y, si preguntan que
// bases hay, listar unas cuantas con nombres jugosos. No ejecuta ni devuelve
// datos reales: solo responde lo justo para que el escaner se lo crea y se
// retrate, y anota cada comando que prueba.
type MongoDB struct{}

func (*MongoDB) ID() string            { return "mongodb" }
func (*MongoDB) Nombre() string        { return "MongoDB" }
func (*MongoDB) PuertoPorDefecto() int { return 27017 }
func (*MongoDB) Descripcion() string {
	return "Finge un MongoDB abierto sin autenticacion. Atrae a quien busca bases " +
		"NoSQL expuestas: pasa el apreton de manos, dice su version y lista bases " +
		"con nombres jugosos, anotando cada comando."
}

// Codigos de operacion del protocolo de MongoDB.
const (
	opReply = 1
	opQuery = 2004
	opMsg   = 2013
)

func (t *MongoDB) Servir(ctx context.Context, direccion string, reg Registrar) error {
	return servirTCP(ctx, direccion, func(conn net.Conn) {
		// Un escaner encadena varios comandos en la misma conexion (isMaster,
		// buildInfo, listDatabases...). Se atienden en bucle hasta que cierra
		// o se agota el plazo.
		for {
			cmd, opCode, reqID, ok := leerMensajeMongo(conn)
			if !ok {
				if cmd == "" {
					reg(evento(t.ID(), "mongodb", ipDe(conn), model.Conexion,
						map[string]string{"puerto": puertoDe(direccion)}))
				}
				return
			}
			reg(evento(t.ID(), "mongodb", ipDe(conn), model.ComandoEjecutado,
				map[string]string{"comando": cmd}))

			resp := respuestaMongo(cmd, opCode, reqID)
			if resp == nil {
				return
			}
			if _, err := conn.Write(resp); err != nil {
				return
			}
			conn.SetDeadline(time.Now().Add(plazoLectura))
		}
	})
}

// leerMensajeMongo lee un mensaje del protocolo y devuelve el comando que
// pide, su codigo de operacion y su requestID (para responder al que toca).
// ok=false si la conexion se cerro o el mensaje no era valido.
func leerMensajeMongo(conn net.Conn) (cmd string, opCode int32, reqID uint32, ok bool) {
	cabecera := make([]byte, 16)
	if _, err := io.ReadFull(conn, cabecera); err != nil {
		return "", 0, 0, false
	}
	msgLen := int32(binary.LittleEndian.Uint32(cabecera[0:4]))
	reqID = binary.LittleEndian.Uint32(cabecera[4:8])
	opCode = int32(binary.LittleEndian.Uint32(cabecera[12:16]))
	if msgLen < 16 || msgLen > maxPorConexion {
		return "", opCode, reqID, false
	}
	cuerpo := make([]byte, msgLen-16)
	if _, err := io.ReadFull(conn, cuerpo); err != nil {
		return "", opCode, reqID, false
	}
	return comandoMongo(cuerpo), opCode, reqID, true
}

// comandosMongo son los que manda un escaner, en el orden en que conviene
// reconocerlos (los mas especificos primero).
var comandosMongo = []string{
	"listDatabases", "buildInfo", "buildinfo", "hello", "isMaster", "ismaster",
	"getLog", "connectionStatus", "serverStatus", "saslStart", "saslContinue",
	"whatsmyuri", "getnonce", "ping", "find", "listCollections",
}

// comandoMongo saca de la carga util el nombre del comando pedido. El comando
// es la primera clave del documento BSON; basta con buscar cual de los
// conocidos aparece, sin parsear el BSON entero.
func comandoMongo(cuerpo []byte) string {
	for _, c := range comandosMongo {
		if bytes.Contains(cuerpo, append([]byte(c), 0x00)) {
			return c
		}
	}
	return "comando desconocido"
}

// respuestaMongo arma la respuesta binaria adecuada al comando y al codigo de
// operacion de la peticion.
func respuestaMongo(cmd string, opCode int32, reqID uint32) []byte {
	var doc []byte
	switch cmd {
	case "buildInfo", "buildinfo":
		doc = docBuildInfo()
	case "listDatabases":
		doc = docListDatabases()
	case "hello":
		doc = docIsMaster(true)
	case "isMaster", "ismaster":
		doc = docIsMaster(false)
	default:
		doc = bsonDoc(bsonDouble("ok", 1.0))
	}

	switch opCode {
	case opQuery:
		return envolverOpReply(reqID, doc)
	case opMsg:
		return envolverOpMsg(reqID, doc)
	default:
		// Protocolo comprimido u otro: no sabemos responder, se corta.
		return nil
	}
}

// envolverOpReply mete un documento en un OP_REPLY (respuesta a un OP_QUERY).
func envolverOpReply(reqID uint32, doc []byte) []byte {
	var b bytes.Buffer
	cuerpo := make([]byte, 20)
	// responseFlags(4)=0, cursorID(8)=0, startingFrom(4)=0, numberReturned(4)=1
	binary.LittleEndian.PutUint32(cuerpo[16:20], 1)
	escribirCabeceraMongo(&b, len(cuerpo)+len(doc), reqID, opReply)
	b.Write(cuerpo)
	b.Write(doc)
	return b.Bytes()
}

// envolverOpMsg mete un documento en un OP_MSG (respuesta a un OP_MSG).
func envolverOpMsg(reqID uint32, doc []byte) []byte {
	var b bytes.Buffer
	cuerpo := make([]byte, 5) // flagBits(4)=0 + kind(1)=0 (body)
	escribirCabeceraMongo(&b, len(cuerpo)+len(doc), reqID, opMsg)
	b.Write(cuerpo)
	b.Write(doc)
	return b.Bytes()
}

// escribirCabeceraMongo escribe los 16 bytes de cabecera. responseTo apunta al
// requestID de la peticion, que es como el cliente empareja pregunta y
// respuesta.
func escribirCabeceraMongo(b *bytes.Buffer, longCuerpo int, responseTo uint32, opCode int32) {
	cab := make([]byte, 16)
	binary.LittleEndian.PutUint32(cab[0:4], uint32(16+longCuerpo))
	binary.LittleEndian.PutUint32(cab[4:8], 1) // requestID nuestro, cualquiera
	binary.LittleEndian.PutUint32(cab[8:12], responseTo)
	binary.LittleEndian.PutUint32(cab[12:16], uint32(opCode))
	b.Write(cab)
}

// --- Constructor minimo de BSON --------------------------------------------
//
// Solo los tipos que necesitan estas respuestas. Un elemento es
// tipo(1) + nombre + 0x00 + valor; un documento es longitud(4) + elementos +
// 0x00.

func cadenaC(s string) []byte { return append([]byte(s), 0x00) }

func bsonDoc(elems ...[]byte) []byte {
	var cuerpo []byte
	for _, e := range elems {
		cuerpo = append(cuerpo, e...)
	}
	out := make([]byte, 4, 4+len(cuerpo)+1)
	binary.LittleEndian.PutUint32(out, uint32(4+len(cuerpo)+1))
	out = append(out, cuerpo...)
	return append(out, 0x00)
}

func bsonBool(nombre string, v bool) []byte {
	b := byte(0)
	if v {
		b = 1
	}
	return append(append([]byte{0x08}, cadenaC(nombre)...), b)
}

func bsonInt32(nombre string, v int32) []byte {
	val := make([]byte, 4)
	binary.LittleEndian.PutUint32(val, uint32(v))
	return append(append([]byte{0x10}, cadenaC(nombre)...), val...)
}

func bsonInt64(nombre string, v int64) []byte {
	val := make([]byte, 8)
	binary.LittleEndian.PutUint64(val, uint64(v))
	return append(append([]byte{0x12}, cadenaC(nombre)...), val...)
}

func bsonDouble(nombre string, v float64) []byte {
	val := make([]byte, 8)
	binary.LittleEndian.PutUint64(val, math.Float64bits(v))
	return append(append([]byte{0x01}, cadenaC(nombre)...), val...)
}

func bsonDatetime(nombre string, ms int64) []byte {
	val := make([]byte, 8)
	binary.LittleEndian.PutUint64(val, uint64(ms))
	return append(append([]byte{0x09}, cadenaC(nombre)...), val...)
}

func bsonString(nombre, v string) []byte {
	s := cadenaC(v)
	val := make([]byte, 4, 4+len(s))
	binary.LittleEndian.PutUint32(val, uint32(len(s)))
	val = append(val, s...)
	return append(append([]byte{0x02}, cadenaC(nombre)...), val...)
}

func bsonSubdoc(nombre string, doc []byte) []byte {
	return append(append([]byte{0x03}, cadenaC(nombre)...), doc...)
}

func bsonArray(nombre string, doc []byte) []byte {
	return append(append([]byte{0x04}, cadenaC(nombre)...), doc...)
}

func docIsMaster(hello bool) []byte {
	elems := [][]byte{}
	if hello {
		elems = append(elems, bsonBool("isWritablePrimary", true))
	}
	elems = append(elems,
		bsonBool("ismaster", true),
		bsonInt32("maxBsonObjectSize", 16777216),
		bsonInt32("maxMessageSizeBytes", 48000000),
		bsonInt32("maxWriteBatchSize", 100000),
		bsonDatetime("localTime", time.Now().UnixMilli()),
		bsonInt32("logicalSessionTimeoutMinutes", 30),
		bsonInt32("connectionId", 17),
		bsonInt32("minWireVersion", 0),
		bsonInt32("maxWireVersion", 13),
		bsonBool("readOnly", false),
		bsonDouble("ok", 1.0),
	)
	return bsonDoc(elems...)
}

func docBuildInfo() []byte {
	return bsonDoc(
		bsonString("version", "4.4.6"),
		bsonString("gitVersion", "72e66213c2c3eab37d9358d5e78ad7f5c1d0d0d7"),
		bsonInt32("maxBsonObjectSize", 16777216),
		bsonBool("debug", false),
		bsonDouble("ok", 1.0),
	)
}

func docListDatabases() []byte {
	base := func(nombre string, tam int64) []byte {
		return bsonDoc(
			bsonString("name", nombre),
			bsonInt64("sizeOnDisk", tam),
			bsonBool("empty", false),
		)
	}
	arr := bsonDoc(
		bsonSubdoc("0", base("admin", 40960)),
		bsonSubdoc("1", base("config", 73728)),
		bsonSubdoc("2", base("acme_prod", 2145386496)),
		bsonSubdoc("3", base("users", 512090112)),
		bsonSubdoc("4", base("payments", 268435456)),
	)
	return bsonDoc(
		bsonArray("databases", arr),
		bsonInt64("totalSize", 2925961216),
		bsonDouble("ok", 1.0),
	)
}
