package saber

import "strings"

// SinShell dice si en ese protocolo un "comando" es un verbo del propio
// protocolo y no una linea tecleada en una shell.
//
// La distincion decide si algo es una intrusion o un simple sondeo. Un
// PING de Redis no es nadie actuando dentro de la maquina; tratarlo como
// tal ahoga las alertas de verdad entre ruido.
//
// Es una lista de exclusiones a proposito, no de inclusiones: ante un
// protocolo que no conocemos conviene alertar y que alguien lo mire.
// Callarse ante lo desconocido es como se pierden los incidentes.
func SinShell(protocolo string) bool {
	switch strings.ToLower(protocolo) {
	case "redis", "ftp", "http", "smtp":
		return true
	}
	return false
}

// Verbo es lo que se sabe de una orden de protocolo.
type Verbo struct {
	Nota
	// Grave separa el reconocimiento del intento real. En Redis la
	// diferencia es enorme: INFO solo mira, pero CONFIG SET es el primer
	// paso de la via clasica para escribir una clave SSH ajena en el
	// disco. Meterlos en el mismo saco tira por tierra el matiz.
	Grave bool
}

// DeVerbo explica una orden de protocolo y dice si es un intento real.
func DeVerbo(protocolo, comando string) (Verbo, bool) {
	orden := strings.ToUpper(strings.TrimSpace(comando))
	// Se compara por prefijo: llegan como "CONFIG SET dir /var/spool/cron".
	for _, v := range verbos[strings.ToLower(protocolo)] {
		if strings.HasPrefix(orden, v.prefijo) {
			return v.verbo, true
		}
	}
	return Verbo{}, false
}

type verboPatron struct {
	prefijo string
	verbo   Verbo
}

// El orden importa: lo mas especifico primero, porque "CONFIG SET" tambien
// empieza por "CONFIG".
var verbos = map[string][]verboPatron{
	"redis": {
		// ── Intentos reales ──────────────────────────────────────────
		{"CONFIG SET", Verbo{Nota{"cambio de configuracion en caliente",
			"primer paso de la via clasica de Redis para escribir un fichero " +
				"ajeno en el disco, como una clave SSH o una tarea de cron"}, true}},
		{"MODULE LOAD", Verbo{Nota{"carga de un modulo nativo",
			"es ejecucion de codigo directa en el servidor"}, true}},
		{"SLAVEOF", Verbo{Nota{"replicacion desde otro servidor",
			"se usa para que Redis cargue lo que mande la maquina del atacante"}, true}},
		{"REPLICAOF", Verbo{Nota{"replicacion desde otro servidor",
			"se usa para que Redis cargue lo que mande la maquina del atacante"}, true}},
		{"EVAL", Verbo{Nota{"ejecucion de un script Lua",
			"corre codigo dentro del servidor"}, true}},
		{"FLUSHALL", Verbo{Nota{"borrado de todos los datos",
			"destructivo; suele acompanar a un secuestro por rescate"}, true}},
		{"FLUSHDB", Verbo{Nota{"borrado de la base de datos", "destructivo"}, true}},
		{"BGSAVE", Verbo{Nota{"volcado a disco",
			"junto a CONFIG SET decide donde se escribe el fichero"}, true}},
		{"DEBUG", Verbo{Nota{"comando de depuracion de Redis",
			"algunos permiten tumbar el servidor"}, true}},

		// ── Reconocimiento: miran, no tocan ──────────────────────────
		{"PING", Verbo{Nota{"comprobacion de que el servicio responde",
			"primer paso de cualquier inventario automatico"}, false}},
		{"INFO", Verbo{Nota{"version y estado del servidor",
			"asi averiguan si la version tiene fallos conocidos"}, false}},
		{"COMMAND", Verbo{Nota{"lista de comandos disponibles",
			"reconocimiento del servicio"}, false}},
		{"CONFIG GET", Verbo{Nota{"lectura de la configuracion",
			"miran como esta montado, todavia sin tocar nada"}, false}},
		{"DBSIZE", Verbo{Nota{"numero de claves guardadas",
			"tantean si la base tiene contenido"}, false}},
		{"CLIENT", Verbo{Nota{"informacion de conexiones", "reconocimiento"}, false}},
		{"ECHO", Verbo{Nota{"prueba de eco", "comprueban que hablan Redis de verdad"}, false}},
		{"TIME", Verbo{Nota{"hora del servidor", "reconocimiento"}, false}},
		{"QUIT", Verbo{Nota{"cierre ordenado de la conexion",
			"lo hacen los escaneres educados; un atacante no suele despedirse"}, false}},
		{"NONEXISTENT", Verbo{Nota{"comando inexistente a proposito",
			"provocan un error para reconocer el servidor por como se queja; " +
				"es la firma de un inventario automatico"}, false}},
	},
	"ftp": {
		{"SITE EXEC", Verbo{Nota{"ejecucion de un programa via FTP",
			"fallo antiguo que da ejecucion de codigo"}, true}},
		{"STOR", Verbo{Nota{"subida de un fichero",
			"suben algo al servidor, no solo miran"}, true}},
		{"DELE", Verbo{Nota{"borrado de un fichero", "destructivo"}, true}},
		{"USER", Verbo{Nota{"identificacion de usuario", "reconocimiento"}, false}},
		{"SYST", Verbo{Nota{"tipo de sistema operativo",
			"averiguan que hay detras antes de elegir el exploit"}, false}},
		{"FEAT", Verbo{Nota{"funciones que admite el servidor", "reconocimiento"}, false}},
		{"LIST", Verbo{Nota{"listado de directorio", "miran que hay"}, false}},
		{"QUIT", Verbo{Nota{"cierre ordenado de la conexion", "escaneo educado"}, false}},
	},
}
