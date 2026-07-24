package report

import (
	"context"
	"fmt"
	"strings"
)

// topeCaracteresPrompt acota el mensaje que se manda al modelo. Los
// proveedores limitan los tokens por minuto -Groq gratis, 8000 TPM- y un solo
// ataque con un reconocimiento gigante de una linea puede generar mas de
// 10.000 tokens el solo, lo que devuelve un 413. Se recorta con aviso: para
// entender la intencion basta el principio, y el detalle completo sigue en el
// panel.
const topeCaracteresPrompt = 9000

// recortarPrompt deja el mensaje dentro del presupuesto, cortando en frontera
// de caracter para no partir un simbolo por la mitad.
func recortarPrompt(s string) string {
	r := []rune(s)
	if len(r) <= topeCaracteresPrompt {
		return s
	}
	return string(r[:topeCaracteresPrompt]) + "\n\n[...el resto se recorto por tamano...]"
}

// explicarCon es el nucleo comun de las explicaciones bajo demanda: pregunta
// al modelo y reconoce las negativas de su filtro. Lo comparten la
// explicacion de artefactos y la de campanas.
func explicarCon(ctx context.Context, e Explicador, sistema, usuario, idioma string, tope int) (string, error) {
	if e == nil {
		return "", fmt.Errorf("no hay ningun modelo configurado")
	}
	texto, err := e.Preguntar(ctx, sistema+instruccionIdioma(idioma), recortarPrompt(usuario), tope)
	if err != nil {
		return "", err
	}
	if EsNegativa(texto) {
		return "", fmt.Errorf("el modelo se nego a responder; su filtro ha leido " +
			"el analisis como una peticion de ayuda para atacar. Prueba con otro " +
			"modelo en Ajustes -> Informes")
	}
	return texto, nil
}

// instruccionIdioma anade, si toca, una orden final de idioma. El sistema de
// cada prompt esta en espanol y pide responder en espanol; para el ingles se
// sobrescribe al final, que es donde mas caso hace el modelo.
func instruccionIdioma(idioma string) string {
	if idioma == "en" {
		return "\n\nIMPORTANT — LANGUAGE OVERRIDE: ignore any instruction above " +
			"to answer in Spanish. Write your ENTIRE answer in clear, plain " +
			"English, keeping the same structure, tone and length."
	}
	return ""
}

// ── Artefactos ──────────────────────────────────────────────────────────

const sistemaArtefacto = `Eres un analista de seguridad DEFENSIVA. Te doy un
fichero que un atacante intento dejar en un SENUELO -una maquina puesta ahi a
proposito para que la ataquen, aislada y sin nada de valor-. Con su tipo, su
tamano y las cadenas de texto que lleva dentro, explica QUE ES y QUE HACE.

Describes lo que se ve en la muestra, para que la victima lo entienda. No das
instrucciones para atacar, no explicas como usarla ni como reproducir nada.

NUNCA recomiendes aislar la maquina, reinstalarla ni cambiar contrasenas: es
un senuelo, y que capture esto es la trampa funcionando.

Escribe para alguien con conocimientos minimos de informatica: cada termino
tecnico, explicalo ahi mismo con palabras llanas. En prosa corrida, sin
titulos ni listas ni markdown, cuenta tres cosas:

Primero, QUE ES: que clase de programa o script es -un descargador, un minero
de criptomonedas, un binario de botnet, un script de despliegue-.

Segundo, QUE HACE, deducido de sus cadenas: descargar otros binarios, darles
permiso de ejecucion, borrar registros, dejarse una puerta para volver,
propagarse a otras arquitecturas, conectar con un servidor de mando. Cita lo
que de verdad se vea.

Tercero, A QUE APUNTA y por que: que tipo de equipos busca y para que.

Si las cadenas no dan para tanto, dilo y se breve. Responde SIEMPRE en
espanol, tono tranquilo. Entre 120 y 220 palabras.`

// ExplicarArtefacto pide al modelo que cuente que es y que hace una muestra,
// a partir de su tipo y sus cadenas de texto -nunca ejecutandola-.
func ExplicarArtefacto(ctx context.Context, e Explicador, tipo string, bytes int64,
	cadenas, urls []string, idioma string, tope int) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "FICHERO capturado en el honeypot\nTipo: %s\nTamano: %d bytes\n", tipo, bytes)
	if len(urls) > 0 {
		fmt.Fprintf(&b, "Se descargaba de: %s\n", strings.Join(urls, ", "))
	}
	b.WriteString("\nCADENAS DE TEXTO QUE LLEVA DENTRO:\n")
	for _, c := range cadenas {
		fmt.Fprintf(&b, "  %s\n", c)
	}
	return explicarCon(ctx, e, sistemaArtefacto, b.String(), idioma, tope)
}

// ExplicarURL explica una direccion de descarga cuyo fichero NO se capturo:
// solo tenemos la URL/host y cuantas IPs la pidieron. Es lo unico que se puede
// contar de un intento sin muestra, y aun asi ensena de que va.
func ExplicarURL(ctx context.Context, e Explicador, url string, ips int, idioma string, tope int) (string, error) {
	var b strings.Builder
	b.WriteString("DIRECCION DE DESCARGA vista en el honeypot (el fichero NO se capturo)\n")
	fmt.Fprintf(&b, "URL/host: %s\n", url)
	fmt.Fprintf(&b, "La pidieron %d direcciones IP distintas.\n", ips)
	return explicarCon(ctx, e, sistemaURL, b.String(), idioma, tope)
}

const sistemaURL = `Eres un analista de seguridad DEFENSIVA. Te doy una URL o
host DESDE EL QUE un atacante intento descargar algo en un SENUELO -una maquina
puesta ahi a proposito para que la ataquen, aislada y sin valor-. No tenemos el
fichero: la descarga no se llego a capturar (TFTP no se guarda, el servidor ya
no lo servia, o solo consta el comando tecleado). Solo tenemos la direccion y
cuantas IPs distintas la pidieron.

Escribe para alguien con conocimientos minimos, sin dar instrucciones para
atacar ni reproducir nada, en prosa corrida, sin titulos ni listas ni markdown.
Cuenta tres cosas:

Primero, QUE SUELE SER una direccion asi: un servidor de reparto de malware -el
sitio del que los bots se traen su carga util- y como encaja en el ataque:
entrar, descargar esto, ejecutarlo.

Segundo, QUE PISTAS DA la propia direccion: el protocolo (TFTP es tipico de
equipos IoT que no traen wget ni curl; HTTP es lo comun), el nombre del fichero
si lo lleva (por ejemplo wget.sh, o un binario por arquitectura), y que cuantas
mas IPs la pidan, mas apunta a una campana automatizada y no a un ataque
dirigido a esta maquina.

Tercero, POR QUE quiza no tenemos el fichero y que se podria hacer, a alto
nivel y sin pasos, para analizarlo por fuera de forma segura.

Si la direccion no da para mas, dilo y se breve. Responde SIEMPRE en espanol,
tono tranquilo y didactico. Entre 100 y 200 palabras.`

// ── Campanas ────────────────────────────────────────────────────────────

const sistemaCampana = `Eres un analista de seguridad DEFENSIVA. Te doy una
CAMPANA detectada en un SENUELO -una maquina puesta ahi a proposito para que
la ataquen-: varios ataques que llegan desde IPs distintas pero comparten el
mismo guion (el mismo diccionario de credenciales, el mismo fichero que se
traen, la misma secuencia de comandos o las mismas rutas). Explica que
operacion es y como funciona.

Describes lo observado, para la victima. No das instrucciones para atacar.
NUNCA recomiendes aislar la maquina ni cerrar el senuelo: capturar esto es la
trampa funcionando.

Escribe para alguien con conocimientos minimos, traduciendo cada termino. En
prosa corrida, sin listas ni markdown, cuenta:

Primero, QUE OPERACION ES: por que varias IPs haciendo lo mismo son una sola
operacion y no incidentes sueltos, y de que tipo -una botnet reclutando
equipos, fuerza bruta repartida, la propagacion de un gusano-.

Segundo, QUE BUSCAN.

Tercero, POR QUE USAN MUCHAS IPS: que gana el atacante repartiendo el trabajo
-esquivar bloqueos por IP, ir mas rapido, esconder el origen-.

Responde SIEMPRE en espanol, tono tranquilo. Entre 120 y 200 palabras.`

// ExplicarCampana pide al modelo que cuente que operacion coordinada hay
// detras de una campana.
func ExplicarCampana(ctx context.Context, e Explicador, comparten, muestra string,
	numIPs int, paises []string, severidad, idioma string, tope int) (string, error) {
	var b strings.Builder
	fmt.Fprintf(&b, "CAMPANA. Lo que comparten los ataques: %s\n", comparten)
	fmt.Fprintf(&b, "El guion compartido, en concreto: %s\n", muestra)
	fmt.Fprintf(&b, "Alcance: %d IPs distintas", numIPs)
	if len(paises) > 0 {
		fmt.Fprintf(&b, ", desde estos paises: %s", strings.Join(paises, " "))
	}
	fmt.Fprintf(&b, "\nLo mas lejos que llego algun ataque de la campana: %s\n", severidad)
	return explicarCon(ctx, e, sistemaCampana, b.String(), idioma, tope)
}
