package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/k0braintheworld/k0pot/internal/store"
)

// ModeloPorDefecto es el modelo que se usa si no se configura otro.
//
// Se puede cambiar con HONEY_MODELO. Para bajar coste a cambio de textos
// algo menos matizados, claude-haiku-4-5 es la alternativa obvia: el
// informe semanal se genera una vez por semana, asi que el gasto es de
// centimos al mes en cualquiera de los dos.
const ModeloPorDefecto = anthropic.ModelClaudeOpus4_8

// El informe es texto corto, pero el pensamiento adaptativo tambien
// consume del mismo presupuesto: dejamos margen de sobra.
const maxTokens = 8000

// ConLLM redacta el informe con la API de Claude.
//
// Si la API falla, tarda demasiado o no hay clave, cae de vuelta en
// PorReglas: un informe algo mas seco siempre es mejor que ningun informe,
// y el honeypot no deja de capturar porque un servicio externo se caiga.
type ConLLM struct {
	Cliente  anthropic.Client
	Modelo   anthropic.Model
	Respaldo Generador
	Plazo    time.Duration
}

// NuevoConLLM crea el generador. Clave y modelo salen de la configuracion.
func NuevoConLLM(clave, modelo string) *ConLLM {
	m := ModeloPorDefecto
	if modelo != "" {
		m = anthropic.Model(modelo)
	}
	return &ConLLM{
		Cliente:  anthropic.NewClient(option.WithAPIKey(clave)),
		Modelo:   m,
		Respaldo: PorReglas{},
		Plazo:    2 * time.Minute,
	}
}

func (c *ConLLM) Nombre() string { return "llm:" + string(c.Modelo) }

// sistema fija el papel del modelo. El objetivo del proyecto entero cabe
// en estas lineas: traducir, no abrumar.
const sistema = `Eres el analista de un honeypot domestico. Tu lector NO es
un experto en seguridad: es la persona que administra un servidor pequeno y
quiere entender que esta pasando.

LO PRIMERO, Y CONDICIONA TODO LO DEMAS: esto es un SENUELO. Una maquina
puesta ahi a proposito para que la ataquen, aislada de la red real y sin
nada de valor dentro. Que la escaneen es su funcion. Que alguien consiga
entrar NO es un incidente: es la trampa haciendo su trabajo, y justo el
material que hacia falta.

Por eso NUNCA recomiendes aislar la maquina, desconectarla, reinstalarla,
cambiarle las contrasenas, bloquear IPs en su cortafuegos ni "contener el
incidente". Todo eso es cerrar el senuelo, que es lo contrario de para lo
que existe. Tampoco escribas como si hubiera una emergencia.

Lo que si aporta valor:
- Que buscaban y para que: reclutar el equipo en una botnet, minar
  criptomonedas, usarlo de pasarela, recolectar credenciales.
- Que habria significado en un servidor DE VERDAD y que habria que revisar
  alli. Esa es la leccion aprovechable.
- Que credenciales, rutas o ficheros estan circulando, por si aparecen en
  otro sitio.

UNICA EXCEPCION en la que si toca actuar sobre el senuelo: si los datos
sugieren que se esta usando para danar a terceros -reenviar trafico, servir
de rele, atacar hacia fuera-, eso si es un problema y hay que decirlo con
claridad.

Escribe en espanol, en tono tranquilo y directo. Reglas:

- La primera frase dice si hay algo que merezca tu atencion. Si no lo hay,
  dilo claramente: tranquilizar cuando toca es tan util como alertar.
- REGLA INNEGOCIABLE: el veredicto que te dan (VERDE, AMBAR o ROJO) manda
  sobre tu propio criterio, y el informe entero tiene que ser coherente con
  el. ROJO significa que alguien llego a actuar dentro del senuelo y merece
  leerse con atencion, NO que haya una emergencia. Si es VERDE, no siembres
  alarma. Nunca te contradigas entre el principio y el final.
- Explica que significan los datos, no los repitas. "4.000 intentos con
  root/admin" no es un hallazgo; "un bot probando contrasenas por defecto,
  el ruido normal de internet" si lo es.
  - Si te dan ATAQUES, son el material principal: cuenta que intentaban
    y que buscaban, no cuantos hubo. Un ataque con nombre y proposito
    vale mas que diez cifras sueltas.
  - Lo que venga [entre corchetes] sale de nuestro catalogo y es fiable:
    usalo. Para lo que NO lleve corchetes, no inventes que significa: si
    no sabes que es una ruta o un comando, describe lo que se ve y ya
    esta. Equivocarse con aplomo es peor que no explicar.
- Distingue el ruido de fondo automatizado de lo que sugiere intencion real.
  La inmensa mayoria del trafico de un honeypot es ruido.
- Termina con UNA conclusion concreta, coherente con el veredicto. En un
  senuelo la conclusion casi nunca es "haz algo": suele ser que aprender de
  lo que se ha visto. Con VERDE, decir que no hay nada que hacer es la
  respuesta correcta y completa.
- Nada de jerga sin explicar, ni markdown, ni listas de cifras. Prosa corta:
  entre 120 y 250 palabras.`

func (c *ConLLM) Generar(ctx context.Context, d Datos) (Resultado, error) {
	if d.SinActividad() {
		// Sin datos no hay nada que interpretar: gastar una llamada aqui
		// seria tirar el dinero.
		return c.Respaldo.Generar(ctx, d)
	}

	texto, err := c.Preguntar(ctx, sistema, datosComoTexto(d), maxTokens)
	if err != nil {
		return c.replegarse(ctx, d, err.Error())
	}
	return Resultado{Texto: texto, Redactado: c.Nombre()}, nil
}

// Preguntar manda un par sistema/usuario al modelo y devuelve el texto.
//
// Separado de Generar porque el informe del periodo no es lo unico que se
// le pide: tambien explica ataques concretos, con otro prompt y otra
// longitud. La fontaneria es la misma.
func (c *ConLLM) Preguntar(ctx context.Context, sistema, usuario string, tope int) (string, error) {
	ctx, cancelar := context.WithTimeout(ctx, c.Plazo)
	defer cancelar()

	adaptativo := anthropic.ThinkingConfigAdaptiveParam{}
	resp, err := c.Cliente.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     c.Modelo,
		MaxTokens: int64(tope),
		System:    []anthropic.TextBlockParam{{Text: sistema}},
		Thinking:  anthropic.ThinkingConfigParamUnion{OfAdaptive: &adaptativo},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(usuario)),
		},
	})
	if err != nil {
		return "", fmt.Errorf("%s", explicar(err))
	}

	var b strings.Builder
	for _, bloque := range resp.Content {
		if t, ok := bloque.AsAny().(anthropic.TextBlock); ok {
			b.WriteString(t.Text)
		}
	}
	texto := strings.TrimSpace(b.String())
	if texto == "" {
		return "", fmt.Errorf("el modelo devolvio un informe vacio")
	}
	return texto, nil
}

// replegarse entrega el informe por reglas y deja constancia — en el log y
// en la propia firma del resultado — de que el LLM no lo redacto.
func (c *ConLLM) replegarse(ctx context.Context, d Datos, motivo string) (Resultado, error) {
	log.Printf("informe por LLM no disponible (%s); se usa el generador por reglas", motivo)
	res, err := c.Respaldo.Generar(ctx, d)
	if err != nil {
		return res, err
	}
	res.Redactado = fmt.Sprintf("reglas (el LLM no estaba disponible: %s)", motivo)
	return res, nil
}

// explicar convierte el error en algo accionable en el log.
//
// El codigo de estado por si solo no sirve de nada: un 400 puede ser una
// peticion mal formada o el saldo de la cuenta agotado, y quien lea el log
// necesita saber cual de las dos. Por eso se rescata el mensaje que da la
// propia API en vez de traducir solo el numero.
func explicar(err error) string {
	var apiErr *anthropic.Error
	if errors.As(err, &apiErr) {
		if m := mensajeDeLaAPI(apiErr); m != "" {
			return fmt.Sprintf("HTTP %d: %s", apiErr.StatusCode, m)
		}
		switch apiErr.StatusCode {
		case 401:
			return "clave de API invalida o ausente"
		case 429:
			return "limite de peticiones alcanzado"
		default:
			return fmt.Sprintf("la API respondio %d", apiErr.StatusCode)
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "se agoto el tiempo de espera"
	}
	return err.Error()
}

// mensajeDeLaAPI saca el texto del cuerpo de error de la respuesta.
func mensajeDeLaAPI(apiErr *anthropic.Error) string {
	var cuerpo struct {
		Error struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal([]byte(apiErr.RawJSON()), &cuerpo); err != nil {
		return ""
	}
	return strings.TrimSpace(cuerpo.Error.Message)
}

// datosComoTexto arma lo que se le manda al modelo.
//
// Se envian agregados, nunca el log en bruto: son muchisimos menos tokens
// y evita sacar de casa mas datos de terceros de los imprescindibles.
func datosComoTexto(d Datos) string {
	var b strings.Builder
	r := d.Resumen

	fmt.Fprintf(&b, "VEREDICTO DEL CLASIFICADOR: %s\n", NivelDe(d.Niveles))
	fmt.Fprintf(&b, "%s\n\n", FraseSemaforo(d.Niveles, d.Idioma))
	fmt.Fprintf(&b, "Periodo: del %s al %s\n",
		d.Desde.Local().Format("02/01/2006"), d.Hasta.Local().Format("02/01/2006"))
	fmt.Fprintf(&b, "Total de eventos: %d, desde %d IPs distintas\n\n", r.Total, r.IPsUnicas)

	fmt.Fprintf(&b, "Reparto por nivel de atencion:\n")
	fmt.Fprintf(&b, "  ruido de fondo: %d\n", d.Niveles["ruido_fondo"])
	fmt.Fprintf(&b, "  a revisar: %d\n", d.Niveles["revisar"])
	fmt.Fprintf(&b, "  notables: %d\n\n", d.Niveles["notable"])

	seccion := func(titulo string, pares []store.Recuento) {
		if len(pares) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s:\n", titulo)
		for i, p := range pares {
			if i == 8 {
				break
			}
			fmt.Fprintf(&b, "  %s: %d\n", p.Valor, p.N)
		}
		b.WriteString("\n")
	}
	seccion("Tipos de evento", r.PorTipo)
	seccion("Paises de origen", r.PorPais)
	seccion("Usuarios mas probados", r.TopUsuarios)
	seccion("Contrasenas mas probadas", r.TopPasswords)

	if len(r.TopIPs) > 0 {
		b.WriteString("IPs mas activas (con su contexto):\n")
		for i, ip := range r.TopIPs {
			if i == 8 {
				break
			}
			fmt.Fprintf(&b, "  %s: %d eventos", ip.IP, ip.Eventos)
			if ip.Pais != "" {
				fmt.Fprintf(&b, ", pais %s", ip.Pais)
			}
			if ip.ISP != "" {
				fmt.Fprintf(&b, ", proveedor %s", ip.ISP)
			}
			if ip.TipoUso != "" {
				fmt.Fprintf(&b, ", tipo de red %s", ip.TipoUso)
			}
			if ip.Tor {
				b.WriteString(", nodo de salida TOR")
			}
			if ip.Reputacion > 0 {
				fmt.Fprintf(&b, ", reputacion %d/100 con %d denuncias previas",
					ip.Reputacion, ip.TotalReportes)
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}

	if t := AtaquesComoTexto(d.Episodios); t != "" {
		b.WriteString(t)
	}

	// Los destacados solo entran si no hay ataques: con ellos dicen lo
	// mismo evento a evento, y repetirlo invita a que el informe se
	// repita tambien.
	if len(d.Episodios) == 0 && len(d.Destacados) > 0 {
		b.WriteString("Eventos que el clasificador marco como no rutinarios:\n")
		for i, dest := range d.Destacados {
			if i == 10 {
				break
			}
			fmt.Fprintf(&b, "  [%s] %s desde %s: %s",
				dest.Clasificacion, dest.Timestamp.Local().Format("02/01 15:04"),
				dest.IP, dest.Motivo)
			if c := dest.Detalle["comando"]; c != "" {
				fmt.Fprintf(&b, " (comando: %s)", c)
			}
			b.WriteString("\n")
		}
	}
	return b.String()
}
