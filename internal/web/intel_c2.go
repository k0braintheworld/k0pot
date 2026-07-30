package web

// NodoC2 es un host de infraestructura de atacante: un C2, un servidor de
// segunda fase o un punto de descarga de malware. Se agrega de todas las
// fuentes (muestras embebidas, callbacks de exploits, URLs de descarga)
// para dar una vista unica de "contra quien nos enfrentamos".
type NodoC2 struct {
	Host     string   `json:"host"`
	Fuentes  []string `json:"fuentes"`
	Veces    int      `json:"veces"`
	Primera  string   `json:"primera,omitempty"`
	Ultima   string   `json:"ultima,omitempty"`
	Familias []string `json:"familias,omitempty"`
}
