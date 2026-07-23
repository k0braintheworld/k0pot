// Package model define el esquema comun de evento al que se normalizan
// todos los honeypots. Es la pieza que independiza el nucleo de honey
// del honeypot concreto que este por debajo.
package model

import "time"

// Clasificacion indica cuanta atencion humana merece un evento.
type Clasificacion string

const (
	// RuidoFondo: escaneo automatizado masivo, el ruido normal de internet.
	RuidoFondo Clasificacion = "ruido_fondo"
	// Revisar: se sale del patron habitual, conviene una mirada.
	Revisar Clasificacion = "revisar"
	// Notable: comportamiento que sugiere intencion real, no solo escaneo.
	Notable Clasificacion = "notable"
)

// TipoEvento es la accion que realizo el atacante.
type TipoEvento string

const (
	LoginFallido     TipoEvento = "login_fallido"
	LoginExitoso     TipoEvento = "login_exitoso"
	ComandoEjecutado TipoEvento = "comando_ejecutado"
	PeticionHTTP     TipoEvento = "peticion_http"
	DescargaFichero  TipoEvento = "descarga_fichero"
	Conexion         TipoEvento = "conexion"
	// HuellaCliente identifica el software que usa el atacante. Vale su
	// propio tipo porque delata a que familia de bot pertenece.
	HuellaCliente TipoEvento = "huella_cliente"
	// TunelSolicitado: pidieron reenviar trafico a traves de la maquina.
	// No es reconocimiento: es usar el servidor, y por eso va aparte.
	TunelSolicitado TipoEvento = "tunel_solicitado"
)

// Origen describe quien esta detras de una IP, una vez enriquecida.
//
// Los campos salen de una sola consulta a AbuseIPDB. TipoUso es el mas
// util para un informe humano: distingue un centro de datos (casi siempre
// un bot) de una conexion domestica (mas probable que sea una persona o
// una maquina infectada).
type Origen struct {
	IP            string `json:"ip"`
	Pais          string `json:"pais,omitempty"`     // codigo ISO: "CN", "RU"...
	ISP           string `json:"isp,omitempty"`      // "Google LLC"
	TipoUso       string `json:"tipo_uso,omitempty"` // "Data Center/Web Hosting"
	Reputacion    int    `json:"reputacion"`         // 0-100, mayor = peor
	TotalReportes int    `json:"total_reportes"`     // denuncias acumuladas
	Tor           bool   `json:"tor"`
	// Ciudad y coordenadas, si hay base GeoIP. El pais viene de AbuseIPDB;
	// esto lo afina a nivel de ciudad para el mapa.
	Ciudad       string    `json:"ciudad,omitempty"`
	Latitud      float64   `json:"latitud,omitempty"`
	Longitud     float64   `json:"longitud,omitempty"`
	Enriquecido  bool      `json:"enriquecido"`
	ConsultadoEn time.Time `json:"consultado_en,omitempty"`
}

// Evento es la unidad normalizada que recorre todo el pipeline:
// collector -> enrich -> classify -> store -> report.
type Evento struct {
	ID int64 `json:"id"`
	// IDExterno es un identificador estable del evento dentro del log de
	// origen. Con restriccion UNIQUE hace la ingesta idempotente: releer
	// un log no duplica nada.
	IDExterno     string            `json:"id_externo,omitempty"`
	Timestamp     time.Time         `json:"timestamp"`
	Honeypot      string            `json:"honeypot"`  // "cowrie", "httptrap", ...
	Protocolo     string            `json:"protocolo"` // "ssh", "telnet", "http"
	SesionID      string            `json:"sesion_id,omitempty"`
	IP            string            `json:"ip"`
	Tipo          TipoEvento        `json:"tipo"`
	Detalle       map[string]string `json:"detalle,omitempty"` // usuario, password, comando...
	Clasificacion Clasificacion     `json:"clasificacion"`
	// Motivo explica en lenguaje llano por que se clasifico asi.
	Motivo string `json:"motivo,omitempty"`
}
