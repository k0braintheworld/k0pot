package web

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// vidaCertificado es lo que dura el certificado que se genera solo. Dos
// anos: bastante para no molestar, poco para que una clave filtrada no
// valga indefinidamente.
const vidaCertificado = 2 * 365 * 24 * time.Hour

// CertificadoAuto carga el certificado del panel, y lo genera si no hay.
//
// Es autofirmado a proposito: el panel vive en una red interna y no tiene
// un nombre publico con el que pedirle uno a una autoridad. El navegador
// avisara la primera vez, y eso es correcto —no hay forma de que verifique
// a nadie—, pero el trafico va cifrado, que es lo que evita que la
// contrasena del panel viaje en claro por la red.
func CertificadoAuto(dir string, nombres []string) (tls.Certificate, error) {
	crt := filepath.Join(dir, "panel.crt")
	clave := filepath.Join(dir, "panel.key")

	if c, err := tls.LoadX509KeyPair(crt, clave); err == nil {
		if hoja, err := x509.ParseCertificate(c.Certificate[0]); err == nil {
			// Se regenera antes de caducar, no despues: un panel que deja
			// de abrirse un martes por la manana sin haber tocado nada es
			// exactamente lo que no debe pasar.
			if time.Now().Before(hoja.NotAfter.Add(-24 * time.Hour)) {
				return c, nil
			}
		}
	}

	pemCrt, pemClave, err := generarAutofirmado(nombres)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, fmt.Errorf("creando %s: %w", dir, err)
	}
	if err := os.WriteFile(crt, pemCrt, 0o644); err != nil {
		return tls.Certificate{}, fmt.Errorf("escribiendo el certificado: %w", err)
	}
	// La clave privada, solo para su dueno.
	if err := os.WriteFile(clave, pemClave, 0o600); err != nil {
		return tls.Certificate{}, fmt.Errorf("escribiendo la clave: %w", err)
	}
	return tls.X509KeyPair(pemCrt, pemClave)
}

func generarAutofirmado(nombres []string) (crt, clave []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serie, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	plantilla := x509.Certificate{
		SerialNumber:          serie,
		Subject:               pkix.Name{CommonName: "k0Pot", Organization: []string{"k0Pot"}},
		NotBefore:             time.Now().Add(-time.Hour), // margen por relojes desfasados
		NotAfter:              time.Now().Add(vidaCertificado),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	// Se incluyen todas las direcciones por las que se puede llegar: si la
	// del navegador no esta en el certificado, el aviso del navegador es
	// distinto y mas alarmante que el de "autofirmado".
	for _, n := range nombres {
		if ip := net.ParseIP(n); ip != nil {
			plantilla.IPAddresses = append(plantilla.IPAddresses, ip)
		} else if n != "" {
			plantilla.DNSNames = append(plantilla.DNSNames, n)
		}
	}
	plantilla.IPAddresses = append(plantilla.IPAddresses, net.ParseIP("127.0.0.1"))
	plantilla.DNSNames = append(plantilla.DNSNames, "localhost")

	der, err := x509.CreateCertificate(rand.Reader, &plantilla, &plantilla, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	bytesClave, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: bytesClave}), nil
}

// conexionEspiada permite mirar el primer byte sin consumirlo.
//
// Cambiar el panel a HTTPS dejaria a todo el que tenga el enlace viejo
// mirando un error ilegible del navegador -o peor, un timeout- sin pista de
// que ahora hay que escribir https. Se mira ese primer byte: 0x16 es el
// saludo de TLS; cualquier otra cosa es HTTP en claro y merece una
// redireccion en vez de un error.
type conexionEspiada struct {
	net.Conn
	lector *bufio.Reader
	visto  bool
	esTLS  bool
}

func (c *conexionEspiada) Read(p []byte) (int, error) { return c.lector.Read(p) }

// EsTLS mira el primer byte sin consumirlo.
func (c *conexionEspiada) EsTLS() bool {
	if !c.visto {
		c.visto = true
		if b, err := c.lector.Peek(1); err == nil && b[0] == 0x16 {
			c.esTLS = true
		}
	}
	return c.esTLS
}

// ServirTLS levanta el panel en HTTPS, redirigiendo a quien llegue en claro.
func ServirTLS(direccion string, manejador http.Handler, cert tls.Certificate) error {
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}

	base, err := net.Listen("tcp", direccion)
	if err != nil {
		return fmt.Errorf("escuchando en %s: %w", direccion, err)
	}
	defer base.Close()

	cifradas := nuevoOyente(base.Addr())
	claras := nuevoOyente(base.Addr())
	defer cifradas.Close()
	defer claras.Close()

	srv := &http.Server{
		Handler:      conCabecerasTLS(manejador),
		ReadTimeout:  20 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	// A quien llegue por HTTP se le manda al mismo sitio en https.
	redirector := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(),
				http.StatusPermanentRedirect)
		}),
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go srv.Serve(tls.NewListener(cifradas, cfg))
	go redirector.Serve(claras)

	for {
		c, err := base.Accept()
		if err != nil {
			return err
		}
		c = &conexionEspiada{Conn: c, lector: bufio.NewReader(c)}
		// El vistazo al primer byte se hace en su propia goroutine: un
		// cliente que abre la conexion y no manda nada bloquearia el bucle
		// de aceptacion entero, que es una forma trivial de tumbar el panel.
		go func(c net.Conn) {
			espiada := c.(*conexionEspiada)
			c.SetReadDeadline(time.Now().Add(10 * time.Second))
			esTLS := espiada.EsTLS()
			c.SetReadDeadline(time.Time{})
			if esTLS {
				cifradas.entregar(espiada)
				return
			}
			claras.entregar(espiada)
		}(c)
	}
}

// conCabecerasTLS anade lo que solo tiene sentido sobre HTTPS.
func conCabecerasTLS(siguiente http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			// Un ano. Le dice al navegador que no vuelva a intentar HTTP,
			// lo que cierra la ventana de la primera peticion en claro.
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		siguiente.ServeHTTP(w, r)
	})
}

// oyenteCanal es un net.Listener alimentado a mano.
//
// Hacen falta dos servidores sobre el mismo puerto -uno cifrado y otro que
// redirige- y http.Server necesita un Listener para cada uno. Este entrega
// las conexiones que le pasen en vez de aceptarlas del sistema.
type oyenteCanal struct {
	conexiones chan net.Conn
	cerrado    chan struct{}
	unaVez     sync.Once
	dir        net.Addr
}

func nuevoOyente(dir net.Addr) *oyenteCanal {
	return &oyenteCanal{
		conexiones: make(chan net.Conn),
		cerrado:    make(chan struct{}),
		dir:        dir,
	}
}

func (o *oyenteCanal) entregar(c net.Conn) {
	select {
	case o.conexiones <- c:
	case <-o.cerrado:
		c.Close()
	}
}

func (o *oyenteCanal) Accept() (net.Conn, error) {
	select {
	case c := <-o.conexiones:
		return c, nil
	case <-o.cerrado:
		return nil, net.ErrClosed
	}
}

func (o *oyenteCanal) Close() error {
	o.unaVez.Do(func() { close(o.cerrado) })
	return nil
}

func (o *oyenteCanal) Addr() net.Addr { return o.dir }
