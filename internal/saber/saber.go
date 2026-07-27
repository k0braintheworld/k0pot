// Package saber traduce lo observado a lo que significa.
//
// Un honeypot registra "GET /SDK/webLanguage". Eso es un hecho, y no le
// dice nada a nadie que no se dedique a esto. Lo que hace falta saber es
// que esa ruta es del SDK de las camaras IP Hikvision y Dahua, y que
// quien la pide no esta escaneando al azar: busca videovigilancia
// expuesta para reclutarla en una botnet.
//
// Ese salto -del hecho al significado- es la razon de ser de k0Pot. Sin
// el, un panel de honeypot es un registro que solo entiende quien ya
// sabia la respuesta.
//
// El catalogo se amplia sin tocar codigo: basta anadir una entrada.
package saber

import "strings"

// Nota es lo que se sabe de una observacion.
type Nota struct {
	// Que identifica la tecnologia o la tecnica.
	Que string `json:"que"`
	// Por que importa. Se escribe en terminos de intencion, no de
	// tecnologia: quien lee el panel quiere saber que buscaban.
	Por string `json:"por,omitempty"`
}

// patron asocia una nota a un texto que aparece en la observacion.
type patron struct {
	// aguja se busca en minusculas dentro del valor observado.
	aguja string
	nota  Nota
}

// buscar devuelve la primera nota que case. El orden importa: las agujas
// mas especificas van antes, porque "/wp-admin" tambien contiene "admin".
func buscar(valor string, catalogo []patron) (Nota, bool) {
	v := strings.ToLower(valor)
	for _, p := range catalogo {
		if strings.Contains(v, p.aguja) {
			return p.nota, true
		}
	}
	return Nota{}, false
}

// DeRuta explica que buscaba una peticion HTTP.
func DeRuta(ruta string) (Nota, bool) { return buscar(ruta, rutas) }

// DeComando explica que hacia un comando tecleado en la shell falsa.
func DeComando(cmd string) (Nota, bool) { return buscar(cmd, comandos) }

// DeCliente explica que herramienta hay al otro lado.
func DeCliente(cliente string) (Nota, bool) { return buscar(cliente, clientes) }

// DeProveedor explica quien esta detras de la IP, cuando el operador es
// conocido.
//
// Importa mas de lo que parece: los escaneres de investigacion publica
// -Censys, Shodan, Shadowserver- tocan todos los puertos de internet a
// diario y no atacan a nadie. Sin distinguirlos, sus visitas se leen como
// hostiles y quien mire el panel aprendera a desconfiar de las alertas.
func DeProveedor(isp string) (Nota, bool) { return buscar(isp, proveedores) }

// DeCredencial explica de donde sale un par usuario:contrasena. Los
// diccionarios de las botnets de IoT son publicos y muy reconocibles: ver
// root:xc3511 es identificar a Mirai casi con certeza.
func DeCredencial(usuario, password string) (Nota, bool) {
	if n, hay := credenciales[strings.ToLower(usuario)+":"+strings.ToLower(password)]; hay {
		return n, true
	}
	return Nota{}, false
}

var rutas = []patron{
	// ── Camaras y grabadores ─────────────────────────────────────────
	{"/sdk/weblanguage", Nota{"SDK de camaras IP Hikvision y Dahua",
		"buscan videovigilancia expuesta para reclutarla en una botnet"}},
	{"/onvif", Nota{"protocolo ONVIF de camaras de red",
		"rastrean camaras a las que asomarse o secuestrar"}},
	{"/cgi-bin/snapshot", Nota{"captura de imagen de camaras IP",
		"comprueban si la camara responde sin pedir contrasena"}},

	// ── Ficheros que no deberian ser publicos ────────────────────────
	{"/.env", Nota{"fichero de entorno de Laravel, Django y similares",
		"suele llevar dentro contrasenas de base de datos y claves de API"}},
	{"/.git/", Nota{"repositorio Git expuesto",
		"con el se descarga el codigo fuente entero, historial incluido"}},
	{"/.aws/credentials", Nota{"credenciales de Amazon Web Services",
		"dan acceso directo a la factura y a los datos de la nube"}},
	{"id_rsa", Nota{"clave SSH privada",
		"con ella se entra sin necesidad de contrasena"}},
	{"/.ssh/", Nota{"directorio de claves SSH",
		"buscan claves privadas o dejar la suya en authorized_keys"}},
	{"/backup", Nota{"copias de seguridad accesibles",
		"un volcado de base de datos ahorra tener que entrar"}},

	// ── Gestores y paneles ───────────────────────────────────────────
	{"/wp-admin", Nota{"panel de WordPress", "prueban credenciales del gestor"}},
	{"/wp-login", Nota{"entrada de WordPress", "fuerza bruta contra el gestor"}},
	{"/xmlrpc.php", Nota{"XML-RPC de WordPress",
		"permite probar miles de contrasenas en una sola peticion"}},
	{"/phpmyadmin", Nota{"phpMyAdmin", "acceso directo a la base de datos"}},
	{"/manager/html", Nota{"gestor de Apache Tomcat",
		"desde ahi se despliega una aplicacion propia, que es ejecutar codigo"}},
	{"/solr/", Nota{"Apache Solr", "servicio con fallos conocidos de ejecucion remota"}},
	{"/actuator", Nota{"endpoints de Spring Boot Actuator",
		"exponen configuracion y, a veces, credenciales en claro"}},

	// ── Fallos concretos y muy explotados ────────────────────────────
	{"jndi:", Nota{"intento de Log4Shell (CVE-2021-44228)",
		"ejecuta codigo con solo lograr que el servidor registre el texto"}},
	{"/vendor/phpunit", Nota{"PHPUnit expuesto (CVE-2017-9841)",
		"ejecuta codigo PHP arbitrario; sigue siendo de los mas rentables"}},
	{"/cgi-bin/", Nota{"CGI clasico",
		"tanteo de Shellshock y de paneles de router antiguos"}},
	{"/boaform/admin", Nota{"servidor Boa de routers domesticos",
		"buscan routers con la contrasena de fabrica"}},
	{"/hnap1", Nota{"HNAP de routers D-Link", "fallo conocido de administracion remota"}},
	{"/gponform", Nota{"routers GPON de fibra",
		"fallo de 2018 que aun recluta miles de equipos"}},
	{"/shell", Nota{"acceso directo a una shell", "prueban si hay una puerta abierta"}},

	// ── Benigno, para no alarmar de mas ──────────────────────────────
	{"/favicon.ico", Nota{"icono del navegador",
		"lo pide cualquier navegador solo; no es un ataque"}},
	{"/robots.txt", Nota{"fichero para buscadores",
		"lo piden tanto buscadores legitimos como quien mapea el sitio"}},
}

var comandos = []patron{
	// ── Traerse el programa ──────────────────────────────────────────
	{"wget ", Nota{"descarga de un programa desde fuera",
		"el paso con el que una intrusion se convierte en infeccion"}},
	{"curl ", Nota{"descarga de un programa desde fuera",
		"el paso con el que una intrusion se convierte en infeccion"}},
	{"tftp", Nota{"descarga por TFTP",
		"habitual en equipos IoT, que no traen wget ni curl"}},
	{"busybox", Nota{"BusyBox",
		"marca inequivoca de botnet de IoT: Mirai y sus variantes lo usan"}},

	// ── Ejecutarlo ───────────────────────────────────────────────────
	{"chmod +x", Nota{"dar permiso de ejecucion",
		"preparan el fichero recien descargado para lanzarlo"}},
	{"chmod 777", Nota{"permisos totales sobre un fichero",
		"lo mismo, a lo bruto"}},

	// ── Enterarse de donde han caido ─────────────────────────────────
	{"/etc/shadow", Nota{"fichero de contrasenas cifradas",
		"se lo llevan para romperlo con calma fuera"}},
	{"/etc/passwd", Nota{"lista de usuarios del sistema",
		"reconocimiento: a quien pueden suplantar"}},
	{"uname", Nota{"version del sistema",
		"eligen que exploit y que binario les sirve"}},
	{"cpuinfo", Nota{"caracteristicas del procesador",
		"suelen medirlo antes de instalar un minero de criptomonedas"}},
	{"nproc", Nota{"numero de nucleos",
		"dimensionan la maquina, tipico paso previo al minado"}},

	// ── Quedarse ─────────────────────────────────────────────────────
	{"crontab", Nota{"tarea programada",
		"persistencia: quieren volver a arrancar tras un reinicio"}},
	{"authorized_keys", Nota{"clave SSH propia anadida",
		"puerta trasera que sobrevive a cambiar la contrasena"}},
	{"useradd", Nota{"creacion de un usuario", "se fabrican su propia entrada"}},
	{"adduser", Nota{"creacion de un usuario", "se fabrican su propia entrada"}},
	{"passwd ", Nota{"cambio de contrasena",
		"echan al dueno de su propia maquina"}},

	// ── Bajar las defensas y borrar el rastro ────────────────────────
	{"iptables -f", Nota{"borrado de las reglas de cortafuegos",
		"despejan el camino para lo que viene despues"}},
	{"ufw disable", Nota{"cortafuegos desactivado", "despejan el camino"}},
	{"history -c", Nota{"borrado del historial de comandos",
		"tapan lo que acaban de hacer"}},
	{"rm -rf /var/log", Nota{"borrado de los registros",
		"tapan lo que acaban de hacer"}},

	// ── Otros ────────────────────────────────────────────────────────
	{"/ip cloud print", Nota{"comando de RouterOS de MikroTik",
		"comprueban si han caido en un router MikroTik"}},
	{"free ", Nota{"memoria disponible", "dimensionan la maquina"}},

	// ── Reconocimiento del sistema (que maquina es) ──────────────────
	{"os-release", Nota{"identifican la distribucion de Linux",
		"eligen el binario o el metodo que funciona en ese sistema concreto"}},
	{"lscpu", Nota{"detalles del procesador",
		"miden la maquina, tipico paso previo al minado"}},
	{"whoami", Nota{"con que usuario estan dentro",
		"quieren saber si ya tienen permisos de administrador"}},
	{"hostname", Nota{"nombre de la maquina",
		"reconocimiento basico del equipo en el que han caido"}},
	{"/proc/mounts", Nota{"discos y puntos de montaje",
		"buscan donde pueden escribir y ejecutar"}},
	{"df ", Nota{"espacio libre en disco",
		"dimensionan la maquina antes de dejar su carga"}},
	{"ps aux", Nota{"lista de procesos en marcha",
		"buscan defensas, o mineros rivales que matar"}},
	{"ps -ef", Nota{"lista de procesos en marcha",
		"buscan defensas, o mineros rivales que matar"}},

	// ── Moverse a donde se puede escribir ────────────────────────────
	{"cd /tmp", Nota{"se mueven a una carpeta escribible",
		"/tmp casi siempre permite crear y ejecutar ficheros"}},
	{"/dev/shm", Nota{"carpeta en memoria escribible",
		"escriben ahi para dejar menos rastro en disco"}},
	{"ftpget", Nota{"descarga por FTP",
		"alternativa a wget en equipos minimos"}},

	// ── Ejecutar y ocultar lo que ejecutan ───────────────────────────
	{"sh -c", Nota{"lanzan una orden a traves del interprete",
		"forma habitual de encadenar comandos o de disimular lo que ejecutan"}},
	{"base64 -d", Nota{"descodifican texto oculto",
		"esconden el comando o el fichero real detras de base64"}},
	{"base64 --decode", Nota{"descodifican texto oculto",
		"esconden el comando o el fichero real detras de base64"}},
	{"echo -e", Nota{"escriben bytes crudos en un fichero",
		"montan a mano un binario o un script desde la propia shell"}},
	{"perl", Nota{"ejecutan un interprete Perl",
		"algunos bots traen su carga o su shell inversa en Perl"}},
	{"python -c", Nota{"ejecutan Python en una linea",
		"carga rapida o shell inversa sin dejar fichero"}},

	// ── Llamar de vuelta a casa (shell inversa) ──────────────────────
	{"/dev/tcp/", Nota{"abren una conexion de red desde bash",
		"shell inversa: la maquina llama de vuelta a su servidor"}},
	{"ncat", Nota{"netcat",
		"abren o reciben una conexion, tipico de shell inversa"}},
	{"nc -e", Nota{"netcat con shell",
		"les entregan una consola de tu maquina por la red"}},

	// ── Minado de criptomonedas ──────────────────────────────────────
	{"xmrig", Nota{"minero de Monero (XMRig)",
		"ponen tu CPU al 100% a generar criptomoneda para ellos"}},
	{"stratum", Nota{"protocolo de pool de minado",
		"el minero se conecta al pool donde cobran"}},
	{"minerd", Nota{"minero de criptomonedas", "aprovechan tu CPU para minar"}},
	{"cpuminer", Nota{"minero de criptomonedas", "aprovechan tu CPU para minar"}},

	// ── Quedarse y apagar defensas ───────────────────────────────────
	{"systemctl", Nota{"gestionan servicios del sistema",
		"crean un servicio para volver, o paran defensas y rivales"}},
	{"rc.local", Nota{"script de arranque del sistema",
		"persistencia: lo que metan ahi se ejecuta en cada reinicio"}},
	{"/etc/cron", Nota{"tarea programada del sistema",
		"persistencia: se relanza sola cada cierto tiempo"}},
	{"nohup", Nota{"dejan un proceso corriendo tras cerrar sesion",
		"su carga sigue viva aunque se desconecten"}},
	{"pkill", Nota{"matan procesos por nombre",
		"suelen cargarse mineros rivales o defensas"}},
	{"unset histfile", Nota{"desactivan el historial",
		"para no dejar rastro de lo que teclean"}},
	{"shred", Nota{"destruccion segura de ficheros",
		"borran pruebas para que no se puedan recuperar"}},
	{"/tool fetch", Nota{"descarga en RouterOS de MikroTik",
		"traen su carga aprovechando un router MikroTik"}},
}

var proveedores = []patron{
	// ── Investigacion publica: escanean, pero no atacan ──────────────
	{"censys", Nota{"Censys, inventario publico de internet",
		"escanean internet entera para investigacion; no van a por ti"}},
	{"shodan", Nota{"Shodan, buscador de dispositivos conectados",
		"escanean internet entera; su visita no es un ataque"}},
	{"shadowserver", Nota{"Shadowserver, fundacion de seguridad sin animo de lucro",
		"escanean para avisar a los duenos de equipos vulnerables"}},
	{"binaryedge", Nota{"BinaryEdge, inventario de internet", "escaneo de investigacion"}},
	{"rapid7", Nota{"Rapid7, proyecto Sonar", "escaneo de investigacion"}},
	{"internet-measurement", Nota{"Internet Measurement, escaneo academico",
		"escaneo de investigacion"}},
	{"driftnet", Nota{"Driftnet, inventario de internet", "escaneo de investigacion"}},

	// ── Alojamiento barato, de donde sale casi todo lo hostil ────────
	{"digitalocean", Nota{"DigitalOcean",
		"alojamiento barato y de alta rotacion: origen habitual de escaneo hostil"}},
	{"vultr", Nota{"Vultr", "alojamiento barato: origen habitual de escaneo hostil"}},
	{"linode", Nota{"Linode", "alojamiento barato: origen habitual de escaneo hostil"}},
	{"hetzner", Nota{"Hetzner", "alojamiento barato: origen habitual de escaneo hostil"}},
	{"ovh", Nota{"OVH", "alojamiento barato: origen habitual de escaneo hostil"}},
	{"chinanet", Nota{"ChinaNet", "una de las redes con mas trafico de escaneo del mundo"}},

	// ── Intermediarios: la IP no dice quien hay detras ───────────────
	{"cloudflare", Nota{"Cloudflare",
		"es un intermediario: la IP no identifica a quien esta detras"}},
	{"tor", Nota{"red Tor", "el origen real queda oculto tras la red de anonimato"}},
}

var clientes = []patron{
	{"zgrab", Nota{"ZGrab, escaner de internet a gran escala",
		"barrido masivo; no van a por ti en particular"}},
	{"masscan", Nota{"Masscan", "barrido masivo de puertos"}},
	{"nmap", Nota{"Nmap", "escaneo de puertos y servicios"}},
	{"censys", Nota{"Censys", "inventario publico de internet, no es hostil"}},
	{"shodan", Nota{"Shodan", "inventario publico de internet, no es hostil"}},
	{"paramiko", Nota{"Paramiko, libreria SSH de Python",
		"hay un script detras, no una persona"}},
	{"libssh", Nota{"libssh", "hay una herramienta automatizada detras"}},
	{"ssh-2.0-go", Nota{"cliente SSH escrito en Go",
		"herramienta a medida; frecuente en escaneres modernos"}},
	{"curl/", Nota{"curl", "peticion automatizada"}},
	{"wget", Nota{"wget", "peticion automatizada"}},
	{"python-requests", Nota{"libreria requests de Python", "hay un script detras"}},
	{"mozilla/", Nota{"navegador",
		"es un navegador de verdad; puede ser una persona mirando"}},
}

// credenciales son pares conocidos de diccionarios publicos. La clave va
// en minusculas, con el formato usuario:contrasena.
var credenciales = map[string]Nota{
	"root:xc3511":       {"credencial de fabrica de camaras XiongMai", "esta en el codigo de Mirai"},
	"root:vizxv":        {"credencial de fabrica de camaras Dahua", "esta en el codigo de Mirai"},
	"root:7ujmko0admin": {"credencial de fabrica de grabadores Dahua", "esta en el codigo de Mirai"},
	"root:juantech":     {"credencial de fabrica de grabadores", "esta en el codigo de Mirai"},
	"root:888888":       {"credencial de fabrica de grabadores", "diccionario de Mirai"},
	"root:54321":        {"credencial de fabrica", "diccionario de Mirai"},
	"admin:admin":       {"credencial por defecto universal", "primer intento de cualquier bot"},
	"admin:1234":        {"credencial por defecto de routers", "primer intento de cualquier bot"},
	"root:root":         {"credencial por defecto universal", "primer intento de cualquier bot"},
	"support:support":   {"credencial de fabrica de routers", "diccionario de Mirai"},
	"pi:raspberry":      {"credencial por defecto de Raspberry Pi", "buscan Raspberrys sin configurar"},
	"ubnt:ubnt":         {"credencial de fabrica de Ubiquiti", "buscan antenas y routers Ubiquiti"},
}
