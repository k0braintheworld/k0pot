package web

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/episodio"
	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/report"
	"github.com/k0braintheworld/k0pot/internal/saber"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// episodios lista los ataques que casan con el filtro, los mas graves
// primero.
func (s *Servidor) episodios(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	idioma := idiomaDe(r)
	lista, err := s.Almacen.Episodios(store.FiltroEpisodios{
		Desde:     time.Now().AddDate(0, 0, -dias(r)),
		Minima:    severidadValida(q.Get("severidad")),
		Protocolo: q.Get("protocolo"),
		Texto:     q.Get("q"),
		Limite:    200,
	})
	if err != nil {
		http.Error(w, "no se pudieron leer los ataques", http.StatusInternalServerError)
		return
	}
	for i := range lista {
		lista[i].Resumen = episodio.Redactar(lista[i].Episodio, idioma)
	}
	responderJSON(w, lista)
}

// severidadValida descarta lo que no sea una severidad conocida.
//
// Va contra una lista blanca y no contra la cadena recibida: el valor entra
// en la consulta y, aunque vaya como parametro, aceptar cualquier cosa
// haria que un filtro mal escrito devolviera la lista entera en silencio,
// que es peor que no filtrar.
func severidadValida(s string) string {
	switch s {
	case "tanteo", "acceso", "intrusion":
		return s
	}
	return ""
}

// PasoNarrado es una linea de la narracion de un ataque.
//
// El detalle se aplana a un texto ya legible en el servidor: la plantilla
// de cada tipo de evento es logica, no presentacion, y repartirla por el
// JavaScript la duplicaria en cuanto haya otra vista.
type PasoNarrado struct {
	Momento time.Time `json:"momento"`
	Tipo    string    `json:"tipo"`
	Texto   string    `json:"texto"`
	// Destacado marca los pasos que cambian la historia: entrar, ejecutar
	// algo, descargar. Son los que hay que poder localizar de un vistazo
	// en una sesion de doscientas lineas.
	Destacado bool `json:"destacado"`
	// Nota explica que significa el paso, cuando se sabe. Un registro que
	// dice "GET /SDK/webLanguage" solo lo entiende quien ya sabia la
	// respuesta; es el resto de la gente la que necesita el panel.
	Nota *saber.Nota `json:"nota,omitempty"`
	// Crudo es lo que el atacante envio EXACTAMENTE, con los bytes de
	// control ya escapados para que se puedan leer. La narracion cuenta
	// que fue; esto es la prueba literal, que a veces dice mas: un cliente
	// SSH que en realidad manda un saludo RDP, un comando con rutas
	// concretas, un user-agent con la version del bot.
	Crudo string `json:"crudo,omitempty"`
}

// DetalleEpisodio es un ataque con su narracion completa.
type DetalleEpisodio struct {
	store.EpisodioFila
	// NotaProveedor dice quien opera la IP cuando se sabe. Un escaner de
	// investigacion y una botnet dejan el mismo rastro; solo el operador
	// los distingue.
	NotaProveedor *saber.Nota   `json:"nota_proveedor,omitempty"`
	Pasos         []PasoNarrado `json:"pasos"`
	// Explicacion es lo que redacto el modelo sobre ESTE ataque, si
	// alguien lo pidio. Se guarda con el episodio: reabrir el dialogo no
	// vuelve a gastar cuota.
	Explicacion string `json:"explicacion,omitempty"`
}

func (s *Servidor) episodio(w http.ResponseWriter, r *http.Request) {
	clave := r.URL.Query().Get("clave")
	if clave == "" {
		http.Error(w, "falta la clave del ataque", http.StatusBadRequest)
		return
	}

	ep, hay, err := s.Almacen.EpisodioPorClave(clave)
	if err != nil {
		http.Error(w, "no se pudo leer el ataque", http.StatusInternalServerError)
		return
	}
	if !hay {
		http.Error(w, "ese ataque no existe", http.StatusNotFound)
		return
	}

	eventos, err := s.Almacen.EventosDeEpisodio(ep.IP, ep.Protocolo, ep.Inicio, ep.Fin)
	if err != nil {
		http.Error(w, "no se pudo leer la secuencia", http.StatusInternalServerError)
		return
	}

	idioma := idiomaDe(r)
	tr := func(es, en string) string {
		if idioma == "en" {
			return en
		}
		return es
	}
	pasos := make([]PasoNarrado, 0, len(eventos))
	// Cuando nadie llego a hablar, cada conexion es un sondeo de puertos:
	// merece decirse una vez, no repetir "abre conexion" diez veces sin
	// explicar nunca que significa.
	if ep.SoloConexiones && len(eventos) > 0 {
		notaSondeo := saber.Nota{
			Que: "comprobacion de que el puerto esta abierto",
			Por: "es el primer paso de cualquier inventario automatico; " +
				"no llegaron a probar nada contra el servicio",
		}.En(idioma)
		pasos = append(pasos, PasoNarrado{
			Momento: ep.Inicio, Tipo: "sondeo",
			Texto: tr("sondeo de puertos: abrieron la conexion y la cerraron sin enviar nada",
				"port scan: they opened the connection and closed it without sending anything"),
			Nota: &notaSondeo,
		})
	}
	for _, ev := range eventos {
		texto, destacado := narrar(ev, idioma)
		pasos = append(pasos, PasoNarrado{
			Momento: ev.Timestamp, Tipo: string(ev.Tipo),
			Texto: texto, Destacado: destacado, Nota: notaDe(ev, idioma),
			Crudo: crudoDe(ev),
		})
	}
	ep.Resumen = episodio.Redactar(ep.Episodio, idioma)
	det := DetalleEpisodio{EpisodioFila: ep, Pasos: pasos}
	det.Explicacion, _ = s.Almacen.Explicacion(clave)
	if n, hay := saber.DeProveedor(ep.ISP); hay {
		nn := n.En(idioma)
		det.NotaProveedor = &nn
	}
	responderJSON(w, det)
}

// narrar convierte un evento en la linea que se lee en la narracion, y
// dice si es de los que cambian la historia.
func narrar(ev model.Evento, idioma string) (string, bool) {
	tr := func(es, en string) string {
		if idioma == "en" {
			return en
		}
		return es
	}
	d := ev.Detalle
	switch ev.Tipo {
	case model.Conexion:
		if p := d["puerto"]; p != "" {
			return tr("abre conexion al puerto ", "opens connection to port ") + p, false
		}
		return tr("abre conexion", "opens connection"), false
	case model.HuellaCliente:
		if c := d["cliente"]; c != "" {
			return tr("se identifica como ", "identifies as ") + visible(c), false
		}
		return tr("se identifica", "identifies itself"), false
	case model.LoginFallido:
		return tr("prueba ", "tries ") + credencial(d, idioma) + tr(" — rechazada", " — rejected"), false
	case model.LoginExitoso:
		return tr("ENTRA con ", "ENTERS with ") + credencial(d, idioma), true
	case model.ComandoEjecutado:
		c := d["comando"]
		if c == "" {
			return tr("ejecuta un comando", "runs a command"), true
		}
		if saber.SinShell(ev.Protocolo) {
			// Es un verbo del protocolo, no una shell. Solo se resalta si
			// de verdad intenta algo: resaltar un PING gasta la atencion
			// del lector en lo que no importa.
			v, hay := saber.DeVerbo(ev.Protocolo, c)
			return tr("envia: ", "sends: ") + c, hay && v.Grave
		}
		return tr("ejecuta: ", "runs: ") + c, true
	case model.TunelSolicitado:
		if d := d["destino"]; d != "" {
			return tr("pide reenviar trafico hacia ", "asks to forward traffic to ") + d, true
		}
		return tr("pide reenviar trafico a traves del servidor", "asks to forward traffic through the server"), true

	case model.DescargaFichero:
		if u := d["url"]; u != "" {
			return tr("intenta descargar ", "tries to download ") + u, true
		}
		return tr("intenta descargar un fichero", "tries to download a file"), true
	case model.PeticionHTTP:
		linea := d["metodo"] + " " + d["ruta"]
		if linea == " " {
			linea = tr("peticion HTTP", "HTTP request")
		}
		// Una peticion a /.env o /wp-admin no es una visita: es tanteo, y
		// el clasificador ya lo sabe. Se hereda su veredicto.
		return linea, ev.Clasificacion != model.RuidoFondo
	default:
		return string(ev.Tipo), false
	}
}

// notaDe busca en el catalogo que significa lo observado. Devuelve nil
// cuando no se sabe: no decir nada es mejor que inventar una explicacion,
// porque quien lee el panel no tiene como distinguir una de otra.
func notaDe(ev model.Evento, idioma string) *saber.Nota {
	d := ev.Detalle
	var (
		n   saber.Nota
		hay bool
	)
	switch ev.Tipo {
	case model.PeticionHTTP:
		n, hay = saber.DeRuta(d["ruta"])
	case model.ComandoEjecutado:
		if saber.SinShell(ev.Protocolo) {
			if v, ok := saber.DeVerbo(ev.Protocolo, d["comando"]); ok {
				nota := v.Nota.En(idioma)
				return &nota
			}
			return nil
		}
		n, hay = saber.DeComando(d["comando"])
	case model.HuellaCliente:
		n, hay = saber.DeCliente(d["cliente"])
	case model.TunelSolicitado:
		n, hay = saber.Nota{
			Que: "intento de usar el servidor como pasarela",
			Por: "no buscan tus datos, buscan tu conexion para esconder la suya: " +
				"spam, fuerza bruta contra terceros o trafico que no quieren " +
				"que salga de su IP",
		}, true
	case model.LoginFallido, model.LoginExitoso:
		n, hay = saber.DeCredencial(d["usuario"], d["password"])
	}
	if !hay {
		return nil
	}
	n = n.En(idioma)
	return &n
}

func credencial(d map[string]string, idioma string) string {
	u, p := d["usuario"], d["password"]
	switch {
	case u != "" && p != "":
		return u + ":" + p
	case u != "":
		return u
	case p != "":
		if idioma == "en" {
			return "(no user):" + p
		}
		return "(sin usuario):" + p
	default:
		if idioma == "en" {
			return "some credentials"
		}
		return "unas credenciales"
	}
}

// explicarEpisodio pide al modelo que cuente este ataque concreto.
//
// Va por POST y con su propio boton: es el momento en que alguien quiere
// entender algo, y por eso es donde mejor se gasta una llamada. El informe
// del periodo resume cifras; esto explica una historia que ya esta
// ordenada, que es lo que un modelo hace bien.
func (s *Servidor) explicarEpisodio(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		responderError(w, http.StatusMethodNotAllowed, "usa POST")
		return
	}
	clave := r.URL.Query().Get("clave")
	if clave == "" {
		responderError(w, http.StatusBadRequest, "falta la clave del ataque")
		return
	}

	explicador, ok := s.Generador.(report.Explicador)
	if !ok {
		responderError(w, http.StatusBadRequest,
			"no hay ningun modelo configurado: revisa Ajustes → Informes")
		return
	}

	ep, hay, err := s.Almacen.EpisodioPorClave(clave)
	if err != nil || !hay {
		responderError(w, http.StatusNotFound, "ese ataque no existe")
		return
	}
	eventos, err := s.Almacen.EventosDeEpisodio(ep.IP, ep.Protocolo, ep.Inicio, ep.Fin)
	if err != nil {
		http.Error(w, "no se pudo leer la secuencia", http.StatusInternalServerError)
		return
	}

	idioma := idiomaDe(r)
	pasos := make([]report.PasoDeAtaque, 0, len(eventos))
	for _, ev := range eventos {
		texto, _ := narrar(ev, idioma)
		p := report.PasoDeAtaque{Hora: ev.Timestamp.Local().Format("15:04:05"), Texto: texto}
		if n := notaDe(ev, idioma); n != nil {
			p.Nota = n.Que + ": " + n.Por
		}
		pasos = append(pasos, p)
	}
	var notaProv string
	if n, hay := saber.DeProveedor(ep.ISP); hay {
		n = n.En(idioma)
		notaProv = n.Que + ": " + n.Por
	}

	// Cuenta contra el mismo tope diario que el informe: es la misma cuota.
	dia := time.Now().Format("2006-01-02")
	permitido, err := s.Almacen.ConsumirCuotaLLM(dia, s.Config.Actual().InformeTopeDiario)
	if err != nil {
		http.Error(w, "no se pudo comprobar la cuota", http.StatusInternalServerError)
		return
	}
	if !permitido {
		responderError(w, http.StatusTooManyRequests,
			"alcanzado el tope de peticiones con IA de hoy")
		return
	}

	// El tope es generoso a proposito aunque la respuesta pedida sea corta:
	// los modelos de razonamiento gastan la mayor parte del presupuesto
	// deliberando dentro de la propia respuesta, y limpiarRazonamiento
	// descarta esa parte. Con poco margen se queda todo en nada y el
	// usuario ve "el modelo devolvio un informe vacio".
	texto, err := report.ExplicarAtaque(r.Context(), explicador, ep, pasos, notaProv, idiomaDe(r), 2000)
	if err != nil {
		// No llego a redactarse nada: se devuelve la llamada apuntada.
		s.Almacen.DevolverCuotaLLM(dia)
		responderError(w, http.StatusBadGateway, err.Error())
		return
	}
	if err := s.Almacen.GuardarExplicacion(clave, texto); err != nil {
		http.Error(w, "no se pudo guardar", http.StatusInternalServerError)
		return
	}
	responderJSON(w, map[string]string{"explicacion": texto})
}

// crudoDe devuelve lo que el atacante envio EXACTAMENTE en ese paso, o vacio
// si el evento no tiene un contenido literal que ensenar (una conexion a
// secas no lo tiene).
//
// Es la prueba, frente a la narracion que la interpreta. A veces dice mas:
// el "cliente" que en realidad es un saludo de otro protocolo, el comando
// con sus rutas, el user-agent con la version del bot.
func crudoDe(ev model.Evento) string {
	d := ev.Detalle
	switch ev.Tipo {
	case model.ComandoEjecutado:
		return visible(d["comando"])
	case model.HuellaCliente:
		return visible(d["cliente"])
	case model.PeticionHTTP:
		linea := strings.TrimSpace(d["metodo"] + " " + d["ruta"])
		if ua := d["cliente"]; ua != "" {
			linea += "\n" + ua
		}
		return visible(linea)
	case model.LoginFallido, model.LoginExitoso:
		return visible(d["usuario"] + ":" + d["password"])
	case model.DescargaFichero:
		if u := d["url"]; u != "" {
			return visible(u)
		}
		return visible(d["fichero"])
	case model.TunelSolicitado:
		return visible(d["destino"])
	}
	return ""
}

// visible hace legible un texto que puede traer bytes de control o basura
// binaria: los escaneres no siempre hablan el protocolo del puerto, asi que
// el "cliente SSH" puede ser en realidad un saludo RDP con bytes crudos.
// Volcarlos tal cual rompe el render -salen como cuadraditos y mojibake- y
// puede colar caracteres que confundan a quien lo lee. Se escapan a \xNN,
// que ademas deja ver que habia bytes no imprimibles, que es un dato en si.
func visible(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\t':
			b.WriteString("\\t")
		case r == '\n' || r == '\r':
			b.WriteRune(r) // los saltos de linea reales se respetan
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\x%02x", r)
		case r == 0xfffd:
			b.WriteString("\\x??") // byte que ni siquiera era UTF-8 valido
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
