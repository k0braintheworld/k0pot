package cebo

import "testing"

// El embudo del panel se apoya entero en esta funcion: si cuenta de mas, el
// engano parecera funcionar mejor de lo que funciona.
func TestTocadosReconoceElBotin(t *testing.T) {
	casos := []struct {
		nombre   string
		comandos []string
		quiere   string
	}{
		{"env", []string{"cat /root/.env"}, "el .env de la aplicacion"},
		{"historial", []string{"cat ~/.bash_history"}, "el historial de la shell"},
		{"clave ssh", []string{"cat /root/.ssh/id_rsa"}, "la clave SSH privada"},
		{"aws", []string{"cat .aws/credentials"}, "las credenciales de AWS"},
		{"crontab del sistema", []string{"cat /etc/crontab"}, "el crontab del sistema"},
		{"volcado", []string{"less acme_prod_users.sql"}, "el volcado de usuarios"},
	}
	for _, c := range casos {
		t.Run(c.nombre, func(t *testing.T) {
			got := Tocados(c.comandos)
			if len(got) != 1 || got[0] != c.quiere {
				t.Fatalf("Tocados(%q) = %v, queria [%q]", c.comandos, got, c.quiere)
			}
		})
	}
}

// Contar de mas es peor que contar de menos: inflaria el embudo con gente que
// nunca vio el cebo, y entonces la medida deja de servir para decidir nada.
func TestTocadosNoCuentaLoQueNoEsBotin(t *testing.T) {
	inocentes := [][]string{
		{"crontab -l"},           // el crontab del usuario, no el que plantamos
		{"uname -a", "whoami"},   // reconocimiento normal
		{"cd /tmp && ls -la"},    // moverse por el sistema
		{"printenv"},             // parecido a .env, pero no lo cita
		{"wget http://x/bot.sh"}, // descarga, no lectura de botin
	}
	for _, cmds := range inocentes {
		if got := Tocados(cmds); len(got) != 0 {
			t.Errorf("Tocados(%q) = %v, no deberia contar nada", cmds, got)
		}
	}
}

// Un mismo botin citado dos veces es UNA pieza abierta, no dos.
func TestTocadosNoRepite(t *testing.T) {
	got := Tocados([]string{"cat /root/.env", "grep DB_PASSWORD /root/.env"})
	if len(got) != 1 {
		t.Fatalf("Tocados = %v, queria una sola pieza", got)
	}
}

func TestTocadosVariasPiezas(t *testing.T) {
	got := Tocados([]string{"cat /root/.env", "cat /root/.ssh/id_rsa"})
	if len(got) != 2 {
		t.Fatalf("Tocados = %v, queria dos piezas", got)
	}
}
