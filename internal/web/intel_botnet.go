package web

import "strings"

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
	{"Tsunami/Kaiten", "IRC bot clasico usado para DDoS",
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
