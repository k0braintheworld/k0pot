package cebo

import "strings"

// Este fichero cierra el otro extremo del cebo. El resto del paquete detecta
// cuando una credencial senuelo VUELVE (el mordisco); aqui se detecta el paso
// anterior: que alguien ha LEIDO la pieza de botin donde estaba escrita.
//
// Tener las dos mitades permite dos cosas que por separado no se pueden:
//
//   - Medir si el engano funciona: de los que entran, cuantos llegan a abrir
//     el botin. Sin esto solo se sabe cuantos muerden, que es la punta del
//     embudo y no dice si el cebo se esta leyendo y descartando.
//   - Saber si el botin CIRCULA: si una IP muerde un cebo sin haberlo leido
//     nunca aqui, esa credencial le llego por otra via. Alguien se la paso, o
//     la vendio. Es la prueba de que lo capturado salio del honeypot.

// Plantado es una pieza del botin y las marcas que delatan que la han abierto.
type Plantado struct {
	// Nombre describe la pieza en llano, para el panel.
	Nombre string
	// Marcas son fragmentos que solo aparecen si citan ese fichero. Se
	// eligen distintivos a proposito: contar de mas falsearia la medida.
	Marcas []string
}

// plantados refleja lo que deploy/loot planta en el sistema de ficheros falso
// de Cowrie. Si se anade botin alli, se anade aqui.
var plantados = []Plantado{
	{"el .env de la aplicacion", []string{".env"}},
	{"el historial de la shell", []string{"bash_history"}},
	{"la clave SSH privada", []string{"id_rsa"}},
	{"los hosts SSH conocidos", []string{"known_hosts"}},
	{"la configuracion SSH", []string{".ssh/config"}},
	{"las credenciales de AWS", []string{"aws/credentials"}},
	{"el historial de MySQL", []string{"mysql_history"}},
	{"el volcado de usuarios", []string{"acme_prod_users"}},
	{"el crontab del sistema", []string{"/etc/crontab"}},
}

// Plantados devuelve una copia del catalogo de botin.
func Plantados() []Plantado {
	out := make([]Plantado, len(plantados))
	copy(out, plantados)
	return out
}

// Tocados devuelve, sin repetir, el nombre de cada pieza de botin citada en
// los comandos. Vacio si no abrieron ninguna.
//
// Es deliberadamente estricto. Un "crontab -l" a secas no cuenta: lista el
// crontab del usuario, no el fichero que plantamos, y darlo por bueno inflaria
// el embudo con gente que nunca vio el cebo.
func Tocados(comandos []string) []string {
	var out []string
	vistos := map[string]bool{}
	for _, cmd := range comandos {
		c := strings.ToLower(cmd)
		for _, p := range plantados {
			if vistos[p.Nombre] {
				continue
			}
			for _, m := range p.Marcas {
				if strings.Contains(c, strings.ToLower(m)) {
					vistos[p.Nombre] = true
					out = append(out, p.Nombre)
					break
				}
			}
		}
	}
	return out
}
