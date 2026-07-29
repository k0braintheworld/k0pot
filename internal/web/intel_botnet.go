package web

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/store"
)

// FamiliaBotnet agrupa los episodios que comparten la firma de una familia
// de malware IoT reconocible por sus comandos.
type FamiliaBotnet struct {
	Familia     string   `json:"familia"`
	Descripcion string   `json:"descripcion"`
	Episodios   int      `json:"episodios"`
	IPs         int      `json:"ips"`
	Ejemplo     []string `json:"ejemplo,omitempty"`
	Primera     string   `json:"primera,omitempty"`
	Ultima      string   `json:"ultima,omitempty"`
}

// firmas de familia: se buscan en orden; la primera que case gana.
var firmasBotnet = []struct {
	familia string
	desc    string
	claves  []string
}{
	{"Mirai", "botnet IoT que recluta dispositivos con credenciales por defecto para DDoS",
		[]string{"/bin/busybox", "MIRAI", "dvrHelper", "ECCHI", ".anime", "LZRD", "SORA",
			"UNSTABLE", "OWARI", "JOSHO", "KYTON", "x86_64.bot", "mips.bot",
			"arm7.bot", "mpsl.bot", "x86.bot", "i586.bot", "i686.bot"}},
	{"Gafgyt", "variante de Bashlite/Qbot para DDoS desde IoT",
		[]string{"GAFGYT", "BASHLITE", "QBOT", "LIZKEBAB", "TORLUS"}},
	{"Mozi", "botnet P2P que se propaga por Telnet y exploits de routers",
		[]string{"MOZI", "mozi.m", "mozi.a"}},
	{"Hajime", "botnet P2P rival de Mirai que intenta parchear dispositivos",
		[]string{"HAJIME", ".i.hajime", "atk.scanLOAD"}},
	{"XorDDoS", "troyano Linux que usa XOR para cifrar sus comunicaciones",
		[]string{"xorddos", "XOR.DDoS", "xor."}},
	{"Tsunami/Kaiten", "IRC bot clásico usado para DDoS",
		[]string{"TSUNAMI", "KAITEN", "IRCBOT"}},
	{"CoinMiner", "minero de criptomonedas que secuestra recursos",
		[]string{"xmrig", "minerd", "stratum+tcp", "cpuminer", "cryptonight",
			"randomx", "monero"}},
	{"ShellBot", "bot basado en Perl/Python que conecta a IRC",
		[]string{"udpflood", "tcpflood", "httpflood", "DDoS Perl",
			"ShellBOT", "perlbot", "phpbot"}},
}

func clasificarBotnet(comandos []string) string {
	texto := strings.ToLower(strings.Join(comandos, " "))
	for _, f := range firmasBotnet {
		for _, c := range f.claves {
			if strings.Contains(texto, strings.ToLower(c)) {
				return f.familia
			}
		}
	}
	return ""
}

func (s *Servidor) botnets(w http.ResponseWriter, r *http.Request) {
	desde := time.Now().AddDate(0, 0, -dias(r))
	eps, err := s.Almacen.Episodios(store.FiltroEpisodios{Desde: desde, Limite: 2000})
	if err != nil {
		http.Error(w, "no se pudieron leer los ataques", http.StatusInternalServerError)
		return
	}

	type agg struct {
		familia string
		desc    string
		ips     map[string]bool
		n       int
		ejemplo []string
		primera time.Time
		ultima  time.Time
	}
	por := map[string]*agg{}

	for _, ep := range eps {
		if len(ep.Comandos) == 0 {
			continue
		}
		fam := clasificarBotnet(ep.Comandos)
		if fam == "" {
			continue
		}
		a := por[fam]
		if a == nil {
			var desc string
			for _, f := range firmasBotnet {
				if f.familia == fam {
					desc = f.desc
					break
				}
			}
			a = &agg{familia: fam, desc: desc, ips: map[string]bool{}}
			por[fam] = a
		}
		a.n++
		a.ips[ep.IP] = true
		if a.primera.IsZero() || ep.Inicio.Before(a.primera) {
			a.primera = ep.Inicio
		}
		if ep.Fin.After(a.ultima) {
			a.ultima = ep.Fin
		}
		if len(a.ejemplo) == 0 && len(ep.Comandos) > 0 {
			lim := ep.Comandos
			if len(lim) > 5 {
				lim = lim[:5]
			}
			a.ejemplo = lim
		}
	}

	out := make([]FamiliaBotnet, 0, len(por))
	for _, a := range por {
		out = append(out, FamiliaBotnet{
			Familia:     a.familia,
			Descripcion: a.desc,
			Episodios:   a.n,
			IPs:         len(a.ips),
			Ejemplo:     a.ejemplo,
			Primera:     a.primera.UTC().Format(time.RFC3339),
			Ultima:      a.ultima.UTC().Format(time.RFC3339),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Episodios > out[j].Episodios })
	responderJSON(w, out)
}
