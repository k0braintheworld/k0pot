package artefacto

import (
	"regexp"
	"strconv"
	"strings"
)

// Indicadores son las senales que un fichero lleva DENTRO: las URLs y las IPs
// que trae escritas -el C2 de un binario, el wget de un dropper-. Extraerlas
// convierte cada muestra capturada en inteligencia sobre la infraestructura
// del atacante, y se saca leyendo bytes, sin ejecutar nada.
type Indicadores struct {
	URLs []string
	IPs  []string
}

var (
	reURLArt = regexp.MustCompile(`(?i)\b(?:https?|ftp|tftp)://[a-z0-9@:%._+~#=/?&\[\]-]{4,200}`)
	reIPArt  = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
)

// benignos son hosts que aparecen a menudo dentro de binarios legitimos (o del
// empaquetador UPX) y nunca son C2: se descartan para no ensuciar la lista.
var benignos = map[string]bool{
	"amazon.com": true, "www.amazon.com": true, "netflix.com": true, "www.netflix.com": true,
	"youtube.com": true, "www.youtube.com": true, "yahoo.com": true, "www.yahoo.com": true,
	"google.com": true, "www.google.com": true, "microsoft.com": true, "www.microsoft.com": true,
	"apple.com": true, "upx.sf.net": true, "sf.net": true, "schema.org": true,
	"www.w3.org": true, "w3.org": true, "example.com": true, "example.org": true,
	"bing.com": true, "www.bing.com": true, "facebook.com": true, "www.facebook.com": true,
	"twitter.com": true, "x.com": true, "instagram.com": true, "wikipedia.org": true,
	"mozilla.org": true, "live.com": true, "office.com": true, "cloudflare.com": true,
	"linkedin.com": true, "www.linkedin.com": true, "reddit.com": true, "www.reddit.com": true,
}

// topeIPsBinario: por encima de este tamano, un fichero es un binario grande
// donde las tiras que parecen IPs son casi siempre ruido (bytes que coinciden),
// no C2. Ahi solo se extraen URLs, que si son fiables. En droppers y binarios
// pequenos, la IP suelta suele ser el C2 de verdad, asi que si se extrae.
const topeIPsBinario = 1 << 20

// IndicadoresDe recorre las tiras de texto imprimible del fichero -un binario
// esta lleno de bytes que por azar parecerian una IP- y saca de ellas las URLs
// y las IPs con pinta de retrollamada, descartando lo benigno, las versiones y
// las direcciones reservadas, privadas o de relleno.
func IndicadoresDe(datos []byte) Indicadores {
	var ind Indicadores
	vistaURL, vistaIP := map[string]bool{}, map[string]bool{}
	sacarIPs := len(datos) < topeIPsBinario

	procesar := func(s string) {
		for _, u := range reURLArt.FindAllString(s, -1) {
			u = strings.TrimRight(u, ".,);:'\"")
			if urlInteresante(u) && !vistaURL[u] && len(ind.URLs) < 50 {
				vistaURL[u] = true
				ind.URLs = append(ind.URLs, u)
			}
		}
		if !sacarIPs {
			return
		}
		for _, ip := range reIPArt.FindAllString(s, -1) {
			if ipInteresante(ip) && !vistaIP[ip] && len(ind.IPs) < 40 {
				vistaIP[ip] = true
				ind.IPs = append(ind.IPs, ip)
			}
		}
	}

	inicio := -1
	for i := 0; i <= len(datos); i++ {
		imprimible := i < len(datos) && datos[i] >= 0x20 && datos[i] < 0x7f
		if imprimible {
			if inicio < 0 {
				inicio = i
			}
			continue
		}
		if inicio >= 0 {
			if i-inicio >= 4 {
				procesar(string(datos[inicio:i]))
			}
			inicio = -1
		}
	}
	return ind
}

// urlInteresante exige que el host tenga un punto (un dominio o una IP; descarta
// basura pegada como "http://invalidlookup") y no este en la lista de benignos.
func urlInteresante(u string) bool {
	i := strings.Index(u, "://")
	if i < 0 {
		return false
	}
	host := u[i+3:]
	if j := strings.IndexAny(host, "/:?@"); j >= 0 {
		host = host[:j]
	}
	host = strings.ToLower(host)
	if host == "" || !strings.Contains(host, ".") || benignos[host] {
		return false
	}
	return true
}

// ipInteresante descarta lo que no sirve como IOC: octetos invalidos, versiones
// (los ceros a la izquierda las delatan), direcciones de red o relleno (acaban
// en .0 o llevan varios ceros), rangos privados/reservados, DNS publicos y
// rangos de documentacion (TEST-NET), que en un binario son casi siempre ruido.
func ipInteresante(s string) bool {
	switch s {
	case "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9", "0.0.0.0":
		return false
	}
	octetos := strings.Split(s, ".")
	if len(octetos) != 4 {
		return false
	}
	var n [4]int
	ceros := 0
	for i, o := range octetos {
		if len(o) > 1 && o[0] == '0' {
			return false // "8.00.1": es una version, no una IP
		}
		v, err := strconv.Atoi(o)
		if err != nil || v > 255 {
			return false
		}
		n[i] = v
		if v == 0 {
			ceros++
		}
	}
	if n[3] == 0 || ceros >= 2 {
		return false // direccion de red o relleno de binario (x.x.x.0, x.0.0.0)
	}
	switch {
	case n[0] == 0 || n[0] == 127 || n[0] >= 224:
		return false // este host, loopback, multicast/reservado
	case n[0] == 10:
		return false // privada
	case n[0] == 192 && n[1] == 168:
		return false // privada
	case n[0] == 172 && n[1] >= 16 && n[1] <= 31:
		return false // privada
	case n[0] == 169 && n[1] == 254:
		return false // link-local
	case n[0] == 192 && n[1] == 0 && n[2] == 2:
		return false // TEST-NET-1 (documentacion)
	case n[0] == 198 && n[1] == 51 && n[2] == 100:
		return false // TEST-NET-2
	case n[0] == 203 && n[1] == 0 && n[2] == 113:
		return false // TEST-NET-3
	}
	return true
}
