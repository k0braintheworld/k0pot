package artefacto

import "strings"

// Clasificar da un juicio rapido y LOCAL sobre que clase de peligro es una
// muestra, para poder triar de un vistazo sin esperar a la IA ni a VirusTotal.
// Devuelve una clave de clase -"botnet", "dropper", "minero", "webshell",
// "prueba", "muestra" o ""- que el panel pinta y ordena. No ejecuta nada: solo
// lee bytes. tam es el tamano real del fichero (datos puede venir cortado).
func Clasificar(datos []byte, tipo string, tam int64) string {
	if tam <= 8 {
		return "prueba"
	}
	bajo := strings.ToLower(string(datos))

	if contieneAlguno(bajo, patronesMinero) {
		return "minero"
	}
	if contieneAlguno(bajo, patronesWebshell) {
		return "webshell"
	}

	// Un dropper puede o no llevar shebang: muchos son solo una tanda de
	// comandos que se cuelan por "| sh". Cuenta como texto tambien.
	if strings.HasPrefix(tipo, "Script") || tipo == "Texto" {
		descarga := strings.Contains(bajo, "wget") || strings.Contains(bajo, "curl") ||
			strings.Contains(bajo, "tftp")
		if descarga && (strings.Contains(bajo, "chmod") || arquitecturasEnTexto(bajo) >= 2) {
			return "dropper"
		}
	}

	if strings.Contains(tipo, "ELF") {
		if contieneAlguno(bajo, patronesBotnet) || arquitecturaIoT(tipo) {
			return "botnet"
		}
		return "muestra"
	}
	return ""
}

// RangoAmenaza ordena las clases: lo mas peligroso primero, las pruebas al
// final. Sirve para que la lista suba las muestras que importan.
func RangoAmenaza(clase string) int {
	switch clase {
	case "botnet":
		return 5
	case "dropper", "minero", "webshell":
		return 4
	case "muestra":
		return 2
	case "prueba":
		return 0
	default:
		return 1
	}
}

var patronesMinero = []string{
	"xmrig", "minerd", "cpuminer", "stratum+tcp", "cryptonight", "randomx",
	"--donate-level", "xmr-stak", "nicehash",
}

var patronesBotnet = []string{
	"mirai", "gafgyt", "boatnet", "tsunami", "hajime", "kaiten", "qbot",
	"/dev/watchdog", "tsource engine query", "lcogrew", "/bin/busybox",
}

var patronesWebshell = []string{
	"eval($_post", "eval($_get", "eval($_request", "base64_decode($_",
	"shell_exec(", "system($_", "assert($_", "passthru($_", "c99shell",
	"r57shell", "wso shell", "b374k",
}

// arquitecturas de CPU tipicas de routers, camaras y otros cacharros de IoT:
// un ELF para una de ellas casi nunca es un servidor, es una botnet.
var arquitecturasIoT = []string{"MIPS", "ARM", "SuperH", "PowerPC", "SPARC"}

// sufijos de arquitectura que lista un dropper cuando trae un binario por CPU.
var sufijosArch = []string{"arm", "arm5", "arm6", "arm7", "mips", "mipsel", "x86",
	"i586", "i686", "sh4", "ppc", "powerpc", "sparc", "m68k", "arc"}

func contieneAlguno(texto string, patrones []string) bool {
	for _, p := range patrones {
		if strings.Contains(texto, p) {
			return true
		}
	}
	return false
}

func arquitecturaIoT(tipo string) bool {
	for _, a := range arquitecturasIoT {
		if strings.Contains(tipo, a) {
			return true
		}
	}
	return false
}

// arquitecturasEnTexto cuenta cuantos sufijos de arquitectura distintos aparecen:
// un dropper de botnet nombra varios (arm7, mips, x86...) para cubrir cada
// cacharro. Se busca como palabra para no contar "arm" dentro de "alarma".
func arquitecturasEnTexto(bajo string) int {
	n := 0
	for _, a := range sufijosArch {
		if contienePalabra(bajo, a) {
			n++
		}
	}
	return n
}

func contienePalabra(texto, palabra string) bool {
	i := 0
	for {
		j := strings.Index(texto[i:], palabra)
		if j < 0 {
			return false
		}
		j += i
		antes := j == 0 || !esAlnum(texto[j-1])
		fin := j + len(palabra)
		despues := fin >= len(texto) || !esAlnum(texto[fin])
		if antes && despues {
			return true
		}
		i = j + 1
	}
}

func esAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}
