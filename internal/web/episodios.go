package web

import (
	"net/http"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/report"
	"github.com/k0braintheworld/k0pot/internal/saber"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// episodios lista los ataques del periodo, los mas graves primero.
func (s *Servidor) episodios(w http.ResponseWriter, r *http.Request) {
	desde := time.Now().AddDate(0, 0, -dias(r))
	lista, err := s.Almacen.Episodios(desde, 200)
	if err != nil {
		http.Error(w, "no se pudieron leer los ataques", http.StatusInternalServerError)
		return
	}
	responderJSON(w, lista)
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

	pasos := make([]PasoNarrado, 0, len(eventos))
	// Cuando nadie llego a hablar, cada conexion es un sondeo de puertos:
	// merece decirse una vez, no repetir "abre conexion" diez veces sin
	// explicar nunca que significa.
	if ep.SoloConexiones && len(eventos) > 0 {
		pasos = append(pasos, PasoNarrado{
			Momento: ep.Inicio, Tipo: "sondeo",
			Texto: "sondeo de puertos: abrieron la conexion y la cerraron sin enviar nada",
			Nota: &saber.Nota{
				Que: "comprobacion de que el puerto esta abierto",
				Por: "es el primer paso de cualquier inventario automatico; " +
					"no llegaron a probar nada contra el servicio",
			},
		})
	}
	for _, ev := range eventos {
		texto, destacado := narrar(ev)
		pasos = append(pasos, PasoNarrado{
			Momento: ev.Timestamp, Tipo: string(ev.Tipo),
			Texto: texto, Destacado: destacado, Nota: notaDe(ev),
		})
	}
	det := DetalleEpisodio{EpisodioFila: ep, Pasos: pasos}
	det.Explicacion, _ = s.Almacen.Explicacion(clave)
	if n, hay := saber.DeProveedor(ep.ISP); hay {
		det.NotaProveedor = &n
	}
	responderJSON(w, det)
}

// narrar convierte un evento en la linea que se lee en la narracion, y
// dice si es de los que cambian la historia.
func narrar(ev model.Evento) (string, bool) {
	d := ev.Detalle
	switch ev.Tipo {
	case model.Conexion:
		if p := d["puerto"]; p != "" {
			return "abre conexion al puerto " + p, false
		}
		return "abre conexion", false
	case model.HuellaCliente:
		if c := d["cliente"]; c != "" {
			return "se identifica como " + c, false
		}
		return "se identifica", false
	case model.LoginFallido:
		return "prueba " + credencial(d) + " — rechazada", false
	case model.LoginExitoso:
		return "ENTRA con " + credencial(d), true
	case model.ComandoEjecutado:
		c := d["comando"]
		if c == "" {
			return "ejecuta un comando", true
		}
		if saber.SinShell(ev.Protocolo) {
			// Es un verbo del protocolo, no una shell. Solo se resalta si
			// de verdad intenta algo: resaltar un PING gasta la atencion
			// del lector en lo que no importa.
			v, hay := saber.DeVerbo(ev.Protocolo, c)
			return "envia: " + c, hay && v.Grave
		}
		return "ejecuta: " + c, true
	case model.TunelSolicitado:
		if d := d["destino"]; d != "" {
			return "pide reenviar trafico hacia " + d, true
		}
		return "pide reenviar trafico a traves del servidor", true

	case model.DescargaFichero:
		if u := d["url"]; u != "" {
			return "intenta descargar " + u, true
		}
		return "intenta descargar un fichero", true
	case model.PeticionHTTP:
		linea := d["metodo"] + " " + d["ruta"]
		if linea == " " {
			linea = "peticion HTTP"
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
func notaDe(ev model.Evento) *saber.Nota {
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
				return &v.Nota
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
	return &n
}

func credencial(d map[string]string) string {
	u, p := d["usuario"], d["password"]
	switch {
	case u != "" && p != "":
		return u + ":" + p
	case u != "":
		return u
	case p != "":
		return "(sin usuario):" + p
	default:
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

	pasos := make([]report.PasoDeAtaque, 0, len(eventos))
	for _, ev := range eventos {
		texto, _ := narrar(ev)
		p := report.PasoDeAtaque{Hora: ev.Timestamp.Local().Format("15:04:05"), Texto: texto}
		if n := notaDe(ev); n != nil {
			p.Nota = n.Que + ": " + n.Por
		}
		pasos = append(pasos, p)
	}
	var notaProv string
	if n, hay := saber.DeProveedor(ep.ISP); hay {
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
	texto, err := report.ExplicarAtaque(r.Context(), explicador, ep, pasos, notaProv, 2000)
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
