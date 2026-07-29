package trampa

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	cebopkg "github.com/k0braintheworld/k0pot/internal/cebo"
	"github.com/k0braintheworld/k0pot/internal/exploit"
	"github.com/k0braintheworld/k0pot/internal/model"
)

// Elasticsearch finge un Elasticsearch abierto sin autenticacion, uno de los
// blancos favoritos de quien rastrea internet en busca de bases de datos que
// exponer y vaciar. Habla su API REST lo justo para que el escaner se lo crea
// -el banner con su "tagline", indices con nombres jugosos, resultados de
// busqueda con credenciales dentro- y anota cada consulta. Los datos que
// sirve son FALSOS: las credenciales son senuelo (ver internal/cebo), asi que
// si alguien las reutiliza mas tarde, lo sabemos con certeza.
type Elasticsearch struct{}

func (*Elasticsearch) ID() string            { return "elasticsearch" }
func (*Elasticsearch) Nombre() string        { return "Elasticsearch" }
func (*Elasticsearch) PuertoPorDefecto() int { return 9200 }
func (*Elasticsearch) Descripcion() string {
	return "Finge un Elasticsearch abierto sin autenticacion. Atrae a quien busca " +
		"bases de datos expuestas para vaciarlas, sirve datos falsos con " +
		"credenciales senuelo y anota cada consulta."
}

func (t *Elasticsearch) Servir(ctx context.Context, direccion string, reg Registrar) error {
	return servirTCP(ctx, direccion, func(conn net.Conn) {
		lector := bufio.NewReader(&lectorLimitado{r: conn, quedan: maxPorConexion})
		req, err := http.ReadRequest(lector)
		if err != nil {
			// Basura que no es HTTP: se anota como conexion a secas.
			reg(evento(t.ID(), "elasticsearch", ipDe(conn), model.Conexion,
				map[string]string{"puerto": puertoDe(direccion)}))
			return
		}

		detalle := map[string]string{
			"metodo": req.Method,
			"ruta":   recortar(req.URL.RequestURI(), 512),
		}
		if ua := req.UserAgent(); ua != "" {
			detalle["cliente"] = recortar(ua, 256)
		}
		if h := req.Host; h != "" {
			detalle["host"] = recortar(h, 128)
		}
		// Algunos escaneres prueban credenciales por Basic Auth contra el
		// cluster; son credenciales que estan probando, se anotan.
		if usuario, clave, ok := req.BasicAuth(); ok {
			detalle["usuario"] = recortar(usuario, 128)
			detalle["password"] = recortar(clave, 128)
		}

		var cuerpo []byte
		if req.Method == http.MethodPost || req.Method == http.MethodPut {
			cuerpo, _ = io.ReadAll(io.LimitReader(req.Body, 8192))
			if len(cuerpo) > 0 {
				detalle["cuerpo"] = recortar(string(cuerpo), 512)
			}
		}

		// ES corre sobre HTTP y ha sufrido exploits (incluido Log4Shell): se
		// mira toda la peticion por si filtran su infraestructura.
		if h, ok := exploit.Detectar(superficieDe(req, cuerpo)); ok {
			detalle["exploit"] = h.Familia
			if h.Destino != "" {
				detalle["callback"] = recortar(h.Destino, 512)
			}
		}

		cuerpoResp, tipoResp, que := responderES(req.URL.Path)
		if que != "" {
			detalle["cebo"] = que
		}

		reg(evento(t.ID(), "elasticsearch", ipDe(conn), model.PeticionHTTP, detalle))

		fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\n"+
			"content-type: %s\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n\r\n%s", tipoResp, len(cuerpoResp), cuerpoResp)
	})
}

// responderES elige la respuesta segun la ruta pedida, imitando la API REST
// de Elasticsearch. Devuelve el cuerpo, su tipo y una etiqueta de cebo para
// el panel (vacia si no sirve nada especialmente jugoso).
func responderES(ruta string) (cuerpo, tipo, que string) {
	const json = "application/json; charset=UTF-8"
	p := strings.ToLower(ruta)
	switch {
	case strings.Contains(p, "_search"):
		return esBusqueda, json, "documentos con credenciales senuelo dentro"
	case strings.Contains(p, "_cat/indices"):
		return esIndices, "text/plain; charset=UTF-8", "el listado de indices, con nombres jugosos"
	case strings.Contains(p, "_cluster/health"):
		return esSalud, json, ""
	case strings.HasPrefix(p, "/_cat/nodes"), strings.HasPrefix(p, "/_nodes"):
		return esNodos, json, ""
	default:
		// La raiz y todo lo demas: el banner. Es lo que el escaner mira para
		// confirmar que ha encontrado un Elasticsearch de verdad.
		return esBanner, json, ""
	}
}

const esBanner = `{
  "name" : "es-node-01",
  "cluster_name" : "acme-logs",
  "cluster_uuid" : "kR9xQzJ2T3mNpH7bV6cY0A",
  "version" : {
    "number" : "7.10.2",
    "build_flavor" : "default",
    "build_type" : "docker",
    "build_hash" : "747e1cc71def077253878a59143c1f785afa92b9",
    "build_date" : "2021-01-13T00:42:12.435326Z",
    "build_snapshot" : false,
    "lucene_version" : "8.7.0",
    "minimum_wire_compatibility_version" : "6.8.0",
    "minimum_index_compatibility_version" : "6.0.0-beta1"
  },
  "tagline" : "You Know, for Search"
}
`

const esIndices = `green open customers        k9Fq3Rn9ZbW1sYpXa 1 1  48213 0  61.2mb  30.6mb
green open users            7Fq3Rn9ZbW1sYpXk 1 1  12904 0  18.7mb   9.3mb
green open payments         Q2T3mNpH7bV6cY0Ab 1 1   9330 0  22.1mb  11.0mb
green open sessions         mNpH7bV6cY0AkR9xz 1 1  40218 0  14.9mb   7.4mb
green open app-logs-2024.06 pH7bV6cY0AkR9xQ2T 5 1 883104 0 512.7mb 256.3mb
green open .kibana_1        H7bV6cY0AkR9xQ2Tm 1 0      7 0  36.8kb  36.8kb
`

const esSalud = `{
  "cluster_name" : "acme-logs",
  "status" : "green",
  "timed_out" : false,
  "number_of_nodes" : 3,
  "number_of_data_nodes" : 3,
  "active_primary_shards" : 14,
  "active_shards" : 28,
  "relocating_shards" : 0,
  "initializing_shards" : 0,
  "unassigned_shards" : 0,
  "active_shards_percent_as_number" : 100.0
}
`

const esNodos = `{
  "_nodes" : { "total" : 3, "successful" : 3, "failed" : 0 },
  "cluster_name" : "acme-logs",
  "nodes" : {
    "kR9xQzJ2T3mNpH7bV6cY0A" : {
      "name" : "es-node-01",
      "host" : "10.0.0.31",
      "ip" : "10.0.0.31",
      "version" : "7.10.2",
      "roles" : [ "data", "ingest", "master" ]
    }
  }
}
`

// esBusqueda se construye al arrancar con credenciales SENUELO reales (las
// mismas del catalogo de cebo), para que vaciar esta "base de datos" sea a la
// vez el gancho y una trampa: si el atacante reutiliza una, salta la alarma.
var esBusqueda string

func init() {
	token, aws := "k0tok_7Fq3Rn9ZbW1sYpX", "AKIA7ACMEQK2NR0PZ3XV"
	for _, c := range cebopkg.Canarios() {
		switch {
		case strings.Contains(c.Etiqueta, "token de API"):
			token = c.Valor
		case strings.Contains(c.Etiqueta, "clave de acceso AWS"):
			aws = c.Valor
		}
	}
	esBusqueda = fmt.Sprintf(`{
  "took" : 14,
  "timed_out" : false,
  "_shards" : { "total" : 1, "successful" : 1, "skipped" : 0, "failed" : 0 },
  "hits" : {
    "total" : { "value" : 12904, "relation" : "eq" },
    "max_score" : 1.0,
    "hits" : [
      {
        "_index" : "users", "_id" : "1", "_score" : 1.0,
        "_source" : {
          "email" : "admin@acme-corp.example",
          "role" : "admin",
          "api_token" : %q,
          "created" : "2023-02-11T09:14:22Z"
        }
      },
      {
        "_index" : "users", "_id" : "2", "_score" : 1.0,
        "_source" : {
          "email" : "deploy@acme-corp.example",
          "role" : "ops",
          "aws_access_key_id" : %q,
          "created" : "2023-05-03T16:40:08Z"
        }
      }
    ]
  }
}
`, token, aws)
}
