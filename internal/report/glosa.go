package report

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// sistemaGlosa pide una explicacion de UNA frase por linea, pensada para
// alguien que esta aprendiendo. Es lo que convierte el replay en algo
// didactico: cada comando, por soso que parezca, dice que hace y para que.
const sistemaGlosa = `Eres un profesor de ciberseguridad explicando a alguien que empieza. Te paso una lista numerada de lineas que un atacante ejecuto contra un honeypot: comandos de shell, peticiones o ordenes de un protocolo. Para CADA numero escribe UNA sola frase, en lenguaje llano y directo, que diga QUE hace esa linea y PARA QUE le sirve al atacante en ese punto del ataque. Sé concreto y util: por ejemplo, "[ -f /etc/os-release ]" comprueba que distribucion de Linux es para elegir el binario adecuado; "uname -m" averigua la arquitectura del procesador para descargar el malware compilado para ella; "chmod +x" da permiso de ejecucion al fichero que acaba de dejar. No repitas la linea ni uses jerga sin explicarla. Cuando proceda, nombra la tecnica en una palabra (persistencia, shell inversa, dropper, minado, reconocimiento) para que quien lee aprenda el termino. Si una linea es intrascendente, resumela en pocas palabras. Responde EXCLUSIVAMENTE con un objeto JSON valido cuyas claves son los numeros como cadena ("1","2",...) y los valores la frase. Nada de markdown ni texto fuera del JSON.`

// GlosarComandos pide al modelo una frase explicativa por cada linea y las
// devuelve alineadas con la entrada (cadena vacia donde el modelo no dijo
// nada). Es tolerante: el modelo a veces envuelve el JSON en texto o vallas.
func GlosarComandos(ctx context.Context, e Explicador, lineas []string, idioma string, tope int) ([]string, error) {
	if e == nil {
		return nil, fmt.Errorf("no hay ningun modelo configurado")
	}
	var b strings.Builder
	for i, l := range lineas {
		fmt.Fprintf(&b, "%d. %s\n", i+1, l)
	}
	bruto, err := e.Preguntar(ctx, sistemaGlosa+instruccionIdioma(idioma), recortarPrompt(b.String()), tope)
	if err != nil {
		return nil, err
	}
	if EsNegativa(bruto) {
		return nil, fmt.Errorf("el modelo se nego a responder; prueba con otro modelo en Ajustes -> Informes")
	}
	m := map[string]string{}
	if err := json.Unmarshal([]byte(extraerObjetoJSON(bruto)), &m); err != nil {
		return nil, fmt.Errorf("el modelo no devolvio un JSON utilizable")
	}
	out := make([]string, len(lineas))
	for i := range lineas {
		out[i] = strings.TrimSpace(m[fmt.Sprintf("%d", i+1)])
	}
	return out, nil
}

// extraerObjetoJSON recupera el primer objeto {...} de una respuesta que
// puede venir con texto o vallas de codigo alrededor.
func extraerObjetoJSON(s string) string {
	i := strings.IndexByte(s, '{')
	j := strings.LastIndexByte(s, '}')
	if i >= 0 && j > i {
		return s[i : j+1]
	}
	return s
}
