package web

// DestinoTunel agrega los destinos a los que atacantes pidieron reenviar
// trafico, para ver que infraestructura real intentan alcanzar a traves
// del honeypot.
type DestinoTunel struct {
	Destino string   `json:"destino"`
	Veces   int      `json:"veces"`
	IPs     []string `json:"ips"`
	Primera string   `json:"primera,omitempty"`
	Ultima  string   `json:"ultima,omitempty"`
}
