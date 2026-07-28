// Comando k0pot: binario unico que recoge, enriquece, almacena y reporta
// la actividad capturada por los honeypots.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	nethttp "net/http"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/k0braintheworld/k0pot/internal/auth"
	"github.com/k0braintheworld/k0pot/internal/aviso"
	"github.com/k0braintheworld/k0pot/internal/classify"
	"github.com/k0braintheworld/k0pot/internal/collector"
	"github.com/k0braintheworld/k0pot/internal/config"
	"github.com/k0braintheworld/k0pot/internal/enrich"
	"github.com/k0braintheworld/k0pot/internal/episodio"
	"github.com/k0braintheworld/k0pot/internal/geoip"
	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/report"
	"github.com/k0braintheworld/k0pot/internal/retencion"
	"github.com/k0braintheworld/k0pot/internal/saber"
	"github.com/k0braintheworld/k0pot/internal/store"
	"github.com/k0braintheworld/k0pot/internal/trampa"
	"github.com/k0braintheworld/k0pot/internal/web"
)

var version = "0.0.7-dev"

func main() {
	var (
		rutaLog = flag.String("log", "data/cowrie/log/cowrie.json",
			"fichero JSON que escribe Cowrie")
		rutaBD = flag.String("bd", "data/honey.db",
			"base de datos SQLite")
		rutaEnv = flag.String("env", ".env",
			"fichero con la configuracion (claves de API)")
		resumir = flag.Bool("resumen", false,
			"muestra un resumen de lo capturado y sale")
		dias = flag.Int("dias", 1,
			"dias hacia atras que abarca el resumen")
		sinEnriquecer = flag.Bool("sin-enriquecer", false,
			"no consulta AbuseIPDB (util sin conexion)")
		informe = flag.Bool("informe", false,
			"redacta un informe en lenguaje natural y sale")
		sinLLM = flag.Bool("sin-llm", false,
			"el informe se redacta solo con reglas, sin llamar a la API")
		// Por defecto solo escucha en local: el panel muestra datos de
		// ataques y este binario corre en una maquina expuesta a ellos.
		// Abrirlo a la red es una decision consciente, no el arranque.
		escuchar = flag.String("web", "",
			"sirve el panel en esta direccion, p.ej. 127.0.0.1:8080")
		crearUsuario = flag.String("crear-usuario", "",
			"da de alta una cuenta del panel y sale")
		cambiarContrasena = flag.String("cambiar-contrasena", "",
			"cambia la contrasena de una cuenta y sale")
		listarUsuarios = flag.Bool("usuarios", false,
			"lista las cuentas del panel y sale")
		asistente = flag.Bool("configurar", false,
			"asistente de configuracion inicial y sale")
		revisar = flag.Bool("reclasificar", false,
			"vuelve a juzgar los eventos guardados con el criterio de hoy y sale")
	)
	flag.Parse()

	cargarEnv(*rutaEnv)

	almacen, err := store.Abrir(*rutaBD)
	if err != nil {
		log.Fatalf("base de datos: %v", err)
	}
	defer almacen.Cerrar()

	ajustes, err := config.Abrir(almacen)
	if err != nil {
		log.Fatalf("configuracion: %v", err)
	}

	if *crearUsuario != "" {
		if err := altaUsuario(almacen, *crearUsuario); err != nil {
			log.Fatalf("alta de usuario: %v", err)
		}
		return
	}

	if *cambiarContrasena != "" {
		if err := resetearContrasena(almacen, *cambiarContrasena); err != nil {
			log.Fatalf("cambio de contrasena: %v", err)
		}
		return
	}

	if *listarUsuarios {
		if err := listarCuentas(almacen); err != nil {
			log.Fatalf("listando cuentas: %v", err)
		}
		return
	}

	if *asistente {
		if err := configurar(almacen, ajustes, *rutaEnv); err != nil {
			log.Fatalf("configuracion: %v", err)
		}
		return
	}

	if *revisar {
		if err := reclasificar(almacen, ajustes, time.Now().AddDate(0, 0, -*dias)); err != nil {
			log.Fatalf("reclasificando: %v", err)
		}
		return
	}

	if *escuchar != "" {
		if err := servirPanel(almacen, ajustes, *escuchar, *rutaBD, *sinLLM); err != nil {
			log.Fatalf("panel: %v", err)
		}
		return
	}

	if *informe {
		if err := mostrarInforme(almacen, ajustes, *dias, *sinLLM); err != nil {
			log.Fatalf("informe: %v", err)
		}
		return
	}

	if *resumir {
		if err := mostrarResumen(almacen, *dias); err != nil {
			log.Fatalf("resumen: %v", err)
		}
		return
	}

	if err := ejecutar(almacen, ajustes, *rutaLog, *sinEnriquecer, *sinLLM); err != nil {
		log.Fatalf("%v", err)
	}
}

// cargarEnv vuelca un fichero clave=valor al entorno. Lo ya definido en
// el entorno manda, para poder sobreescribir sin tocar el fichero.
func cargarEnv(ruta string) {
	f, err := os.Open(ruta)
	if err != nil {
		return // sin fichero de configuracion se funciona igual
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		linea := strings.TrimSpace(sc.Text())
		if linea == "" || strings.HasPrefix(linea, "#") {
			continue
		}
		clave, valor, ok := strings.Cut(linea, "=")
		if !ok {
			continue
		}
		clave = strings.TrimSpace(clave)
		if _, definida := os.LookupEnv(clave); !definida {
			os.Setenv(clave, strings.Trim(strings.TrimSpace(valor), `"'`))
		}
	}
}

// ejecutar lanza la ingesta y, en paralelo, el enriquecimiento.
func ejecutar(almacen *store.Store, ajustes *config.Gestor, rutaLog string, sinEnriquecer, sinLLM bool) error {
	ctx, parar := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer parar()

	var grupo sync.WaitGroup

	// El enriquecimiento va por su cuenta a proposito: depende de una API
	// externa, y ni su lentitud ni su caida deben frenar la captura.
	// La base GeoIP se abre una vez y se comparte. Si no hay fichero queda
	// inactiva, y k0Pot funciona igual con la ubicacion a nivel de pais.
	geo, err := geoip.Abrir(ajustes.Actual().RutaGeoIP)
	if err != nil {
		log.Printf("GeoIP: %v (se seguira sin ubicacion de ciudad)", err)
		geo, _ = geoip.Abrir("")
	} else if geo.Activo() {
		log.Printf("GeoIP activo: %s", ajustes.Actual().RutaGeoIP)
	}
	defer geo.Cerrar()

	if !sinEnriquecer {
		grupo.Add(1)
		go func() {
			defer grupo.Done()
			enriquecerEnBucle(ctx, almacen, ajustes, geo)
		}()
	}

	// Trampas nativas. Guardan directamente, sin pasar por un fichero de
	// log que haya que seguir.
	sup := trampa.NuevoSupervisor(func(ev *model.Evento) {
		guardarEvento(almacen, ajustes, ev)
	})
	defer sup.Parar()

	// Tareas de mantenimiento: releer la configuracion (la cambia el panel,
	// que es otro proceso), aplicar la retencion y ajustar las trampas.
	grupo.Add(1)
	go func() {
		defer grupo.Done()
		mantenimiento(ctx, almacen, ajustes, sup, sinLLM)
	}()

	err = ingerir(ctx, almacen, ajustes, rutaLog)
	parar()
	grupo.Wait()
	return err
}

// ingerir sigue el log del honeypot y guarda cada evento reconocido.
func ingerir(ctx context.Context, almacen *store.Store, ajustes *config.Gestor, rutaLog string) error {
	log.Printf("k0Pot %s | siguiendo %s", version, rutaLog)

	var nuevos, repetidos, ignorados, malos int
	ultimoAviso := time.Now()

	seguidor := collector.NuevoSeguidor(rutaLog)
	err := seguidor.Seguir(ctx, func(linea []byte) error {
		ev, err := collector.ParsearCowrie(linea)
		switch {
		case errors.Is(err, collector.ErrIgnorado):
			ignorados++
			return nil
		case err != nil:
			// Una linea corrupta no debe tumbar la ingesta: la contamos
			// y seguimos, que el honeypot no para por nosotros.
			malos++
			log.Printf("linea ilegible: %v", err)
			return nil
		}

		// Se clasifica con el contexto que haya de la IP ahora mismo.
		// Si el enriquecimiento aun no ha llegado, bastan las senales
		// del propio evento: al enriquecer se vuelve a clasificar.
		origen, _, err := almacen.OrigenDe(ev.IP)
		if err != nil {
			return err
		}
		// Se lee la configuracion en cada evento: el panel puede haber
		// cambiado los umbrales, y el Gestor ya cachea en memoria.
		c := ajustes.Actual()
		clasificador := &classify.Clasificador{Umbrales: classify.Umbrales{
			ReputacionAlta: c.ReputacionAlta,
			DenunciasAltas: c.DenunciasAltas,
		}}
		veredicto := clasificador.Clasificar(ev, origen)
		ev.Clasificacion = veredicto.Clasificacion
		ev.Motivo = veredicto.Motivo

		insertado, err := almacen.Guardar(ev)
		if err != nil {
			return err
		}
		if insertado {
			nuevos++
		} else {
			repetidos++
		}

		if time.Since(ultimoAviso) > 30*time.Second {
			log.Printf("nuevos=%d repetidos=%d ignorados=%d ilegibles=%d",
				nuevos, repetidos, ignorados, malos)
			ultimoAviso = time.Now()
		}
		return nil
	})

	if errors.Is(err, context.Canceled) {
		log.Printf("parando | nuevos=%d repetidos=%d ignorados=%d ilegibles=%d",
			nuevos, repetidos, ignorados, malos)
		return nil
	}
	return err
}

// mantenimiento relee la configuracion y aplica la retencion.
func mantenimiento(ctx context.Context, almacen *store.Store, ajustes *config.Gestor, sup *trampa.Supervisor, sinLLM bool) {
	const intervalo = 30 * time.Second
	ultimaPurga := time.Time{}
	ultimoAprendizaje := time.Time{}
	// ultimoEvento marca hasta donde se han convertido eventos en
	// episodios. Arranca a cero a proposito: al iniciar se reconstruye todo
	// una vez, que es lo que hace falta tras actualizar o restaurar.
	var ultimoEvento int64

	for {
		if err := ajustes.Recargar(); err != nil {
			log.Printf("recargando configuracion: %v", err)
		}

		if n, err := reconstruirEpisodios(almacen, ultimoEvento); err != nil {
			log.Printf("reconstruyendo episodios: %v", err)
		} else {
			ultimoEvento = n
		}

		if err := avisarDeLoGrave(ctx, almacen, ajustes.Actual()); err != nil {
			log.Printf("avisos: %v", err)
		}
		if err := enviarResumen(ctx, almacen, ajustes.Actual()); err != nil {
			log.Printf("resumen: %v", err)
		}

		// Aprendizaje en segundo plano: cada par de minutos, glosar unos
		// comandos nuevos con la cuota que sobre. Espaciado para no cargar el
		// bucle ni quemar la cuota de golpe.
		if time.Since(ultimoAprendizaje) > 2*time.Minute {
			ultimoAprendizaje = time.Now()
			if n, err := aprenderComandos(ctx, almacen, ajustes.Actual(), sinLLM); err != nil {
				log.Printf("aprendizaje: %v", err)
			} else if n > 0 {
				log.Printf("aprendizaje: %d comandos nuevos glosados", n)
			}
		}

		// Activar o desactivar un servicio desde el panel surte efecto
		// aqui, sin reiniciar nada.
		c := ajustes.Actual()
		sup.Aplicar(ctx, c.EscuchaHoneypots, deseadoDe(c))

		// La purga es cara y no urge: una vez por hora basta.
		if time.Since(ultimaPurga) > time.Hour {
			ultimaPurga = time.Now()
			c := ajustes.Actual()
			r, err := retencion.Aplicar(almacen, retencion.Politica{
				EventosDias:   c.RetencionDias,
				EpisodiosDias: c.RetencionEpisodiosDias,
				DirCowrie:     "data/cowrie/lib",
			}, time.Now())
			switch {
			case err != nil:
				log.Printf("retencion: %v", err)
			case !r.Vacio():
				log.Printf("retencion: borrados %s", r)
			}
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(intervalo):
		}
	}
}

// enviarResumen manda por el canal de avisos un digest del periodo, si toca.
// Se autolimita leyendo cuando se envio el ultimo, para no repetirlo en cada
// vuelta del bucle ni tras un reinicio.
func enviarResumen(ctx context.Context, almacen *store.Store, c config.Config) error {
	if !c.ResumenActivo || c.AvisoCanal == "" {
		return nil
	}
	dias := 7
	cada := 7 * 24 * time.Hour
	if c.ResumenCadencia == "diario" {
		dias, cada = 1, 24*time.Hour
	}
	if ult, _ := almacen.LeerEstado("ultimo_resumen"); ult != "" {
		if t, err := time.Parse(time.RFC3339, ult); err == nil && time.Since(t) < cada-time.Hour {
			return nil
		}
	}
	desde := time.Now().AddDate(0, 0, -dias)
	resumen, err := almacen.Resumir(desde)
	if err != nil {
		return err
	}
	niveles, _ := almacen.PorClasificacion(desde)
	ataques, _ := almacen.Episodios(store.FiltroEpisodios{Desde: desde, Limite: 50})
	nuevos, _ := almacen.ArtefactosNuevos(desde)
	res, _ := report.PorReglas{}.Generar(ctx, report.Datos{
		Desde: desde, Hasta: time.Now(), Resumen: resumen,
		Niveles: niveles, Episodios: ataques, Idioma: c.Idioma,
	})
	cuerpo := res.Texto
	if len(nuevos) > 0 {
		if c.Idioma == "en" {
			cuerpo += fmt.Sprintf("\n%d new malware sample(s) captured.", len(nuevos))
		} else {
			cuerpo += fmt.Sprintf("\n%d muestra(s) de malware nueva(s).", len(nuevos))
		}
	}
	canal, err := aviso.De(aviso.Config{
		Canal: c.AvisoCanal, Destino: c.AvisoDestino, Clave: c.ClaveAviso,
		Servidor: c.AvisoServidor, Enlace: c.AvisoEnlace,
	}, nil)
	if err != nil || canal == nil {
		return err
	}
	titulo := "k0Pot: resumen"
	if c.Idioma == "en" {
		titulo = "k0Pot: summary"
	}
	if err := canal.Enviar(ctx, aviso.Mensaje{Titulo: titulo, Cuerpo: cuerpo, Enlace: c.AvisoEnlace}); err != nil {
		return err
	}
	return almacen.GuardarEstado("ultimo_resumen", time.Now().Format(time.RFC3339))
}

// aprenderComandos glosa en segundo plano, con la cuota que sobre, los
// comandos nuevos que k0pot va viendo, para que al abrir un ataque las
// explicaciones ya esten hechas sin tener que pedirlas. Reserva parte de la
// cuota diaria para lo que pida el usuario en directo y avanza despacio: unas
// pocas formas por vuelta, empezando por las mas repetidas.
func aprenderComandos(ctx context.Context, almacen *store.Store, c config.Config, sinLLM bool) (int, error) {
	if sinLLM || !c.UsarLLM || !c.AprendizajeAutomatico {
		return 0, nil
	}
	ex, ok := generadorDe(almacen, c, sinLLM).(report.Explicador)
	if !ok {
		return 0, nil
	}
	idioma := c.Idioma
	if idioma == "" {
		idioma = "es"
	}
	// 0 = sin tope global: cada modelo se limita por su proveedor (429).
	tope := c.InformeTopeDiario
	dia := time.Now().Format("2006-01-02")
	if tope > 0 {
		if usadas, _ := almacen.CuotaLLMUsada(dia); usadas >= tope {
			return 0, nil // agotado el tope global de hoy
		}
	}

	grupos, err := almacen.ComandosRecientesAgrupados(time.Now().AddDate(0, 0, -30))
	if err != nil {
		return 0, err
	}
	type forma struct {
		norm, repr string
		veces      int
	}
	porNorm := map[string]*forma{}
	for _, g := range grupos {
		if g.Comando == "" || saber.ComandoConocido(g.Protocolo, g.Comando) {
			continue // el catalogo fijo ya lo explica
		}
		n := saber.NormalizarComando(g.Comando)
		if n == "" {
			continue
		}
		if _, ya := almacen.GlosaAprendida(n, idioma); ya {
			continue
		}
		f := porNorm[n]
		if f == nil {
			f = &forma{norm: n, repr: g.Comando}
			porNorm[n] = f
		}
		f.veces += g.Veces
	}
	if len(porNorm) == 0 {
		return 0, nil
	}
	orden := make([]*forma, 0, len(porNorm))
	for _, f := range porNorm {
		orden = append(orden, f)
	}
	// Primero lo mas repetido: es lo que mas probablemente vera el usuario.
	sort.Slice(orden, func(i, j int) bool { return orden[i].veces > orden[j].veces })

	const maxPorTanda = 12
	const maxCharsTanda = 6000
	const maxTandas = 1
	aprendidas := 0
	for t := 0; t < maxTandas && len(orden) > 0; t++ {
		// Lote por presupuesto de tamano: un comando largo -un reconocimiento
		// de miles de bytes- va casi solo, para que quepa entero en el prompt
		// y el modelo no lo trunque.
		var lote []*forma
		chars := 0
		for len(orden) > 0 && len(lote) < maxPorTanda {
			f := orden[0]
			if len(lote) > 0 && chars+len(f.repr) > maxCharsTanda {
				break
			}
			lote = append(lote, f)
			chars += len(f.repr) + 8
			orden = orden[1:]
		}
		if ok, _ := almacen.ConsumirCuotaLLM(dia, tope); !ok {
			break // agotado el presupuesto de fondo de hoy
		}
		lineas := make([]string, len(lote))
		for i, f := range lote {
			lineas[i] = f.repr
		}
		_ = almacen.GuardarEstado("ia_activa_hasta", time.Now().Add(25*time.Second).UTC().Format(time.RFC3339))
		cctx, cancelar := context.WithTimeout(ctx, 90*time.Second)
		glosas, err := report.GlosarComandos(cctx, ex, lineas, idioma, 3000)
		cancelar()
		if err != nil {
			almacen.DevolverCuotaLLM(dia)
			return aprendidas, err
		}
		for i, f := range lote {
			if g := strings.TrimSpace(glosas[i]); g != "" {
				_ = almacen.GuardarGlosaAprendida(f.norm, idioma, g)
				aprendidas++
			}
		}
		_ = almacen.GuardarEstado("ia_pausa_hasta", "") // funciono: hay tokens de nuevo
	}
	return aprendidas, nil
}

// avisarDeLoGrave saca del panel lo que no puede esperar a que alguien
// mire.
//
// Solo se avisa de lo que supera la severidad configurada, y una vez por
// ataque. Un honeypot expuesto genera cientos de eventos diarios: mandarlos
// todos garantiza que se dejen de leer, que es peor que no mandar ninguno.
func avisarDeLoGrave(ctx context.Context, almacen *store.Store, c config.Config) error {
	if !c.AvisosActivos || c.AvisoCanal == "" {
		return nil
	}
	canal, err := aviso.De(aviso.Config{
		Canal: c.AvisoCanal, Destino: c.AvisoDestino,
		Clave: c.ClaveAviso, Servidor: c.AvisoServidor, Enlace: c.AvisoEnlace,
	}, nil)
	if err != nil || canal == nil {
		return err
	}

	pendientes, err := almacen.EpisodiosPorAvisar(c.AvisoMinima)
	if err != nil || len(pendientes) == 0 {
		return err
	}
	mensaje, hay := aviso.Redactar(pendientes, c.AvisoEnlace, c.Idioma)
	if !hay {
		return nil
	}
	if err := canal.Enviar(ctx, mensaje); err != nil {
		// No se marcan como avisados: se reintenta en el ciclo siguiente.
		// Perder un aviso por un fallo de red seria justo lo contrario de
		// lo que esta funcion existe para evitar.
		return fmt.Errorf("enviando por %s: %w", canal.Nombre(), err)
	}
	log.Printf("aviso enviado por %s: %d ataque(s)", canal.Nombre(), len(pendientes))
	return almacen.MarcarAvisados(pendientes)
}

// reconstruirEpisodios agrupa en ataques los eventos nuevos y devuelve
// hasta que ID se ha procesado.
//
// Solo se rehace la parte que puede haber cambiado: desde el evento nuevo
// mas antiguo, retrocediendo un hueco. Un evento que llega ahora solo
// puede alargar un episodio cuya ultima actividad este dentro de esa
// ventana; lo anterior ya esta cerrado y volver a calcularlo seria releer
// el historico entero cada treinta segundos.
//
// Los episodios son datos derivados: se pueden borrar y rehacer sin
// perder nada, porque la verdad siguen siendo los eventos.
func reconstruirEpisodios(almacen *store.Store, ultimoID int64) (int64, error) {
	maxID, minNuevo, err := almacen.NovedadesDesde(ultimoID)
	if err != nil {
		return ultimoID, err
	}
	if maxID == ultimoID {
		return ultimoID, nil // nada nuevo que agrupar
	}

	eventos, err := almacen.EventosDesde(minNuevo.Add(-episodio.HuecoPorDefecto))
	if err != nil {
		return ultimoID, err
	}
	if err := almacen.GuardarEpisodios(
		episodio.Agrupar(eventos, episodio.HuecoPorDefecto)); err != nil {
		return ultimoID, err
	}
	return maxID, nil
}

// certificadoDelPanel carga el certificado configurado, o genera uno.
//
// Si el usuario ha puesto los suyos se usan tal cual: querra uno emitido
// por su propia autoridad y no que se lo sustituyamos. Si no, se genera un
// autofirmado que incluye la direccion por la que se esta sirviendo, para
// que el aviso del navegador sea el de "autofirmado" y no el mas alarmante
// de "este certificado no es para este sitio".
func certificadoDelPanel(c config.Config, direccion string) (tls.Certificate, error) {
	if c.TLSCert != "" && c.TLSClave != "" {
		cert, err := tls.LoadX509KeyPair(c.TLSCert, c.TLSClave)
		if err != nil {
			return tls.Certificate{}, fmt.Errorf(
				"no se pudo cargar el certificado configurado: %w", err)
		}
		return cert, nil
	}
	// Solo la direccion por la que se sirve el panel.
	//
	// Enumerar todas las interfaces seria comodo, pero un certificado
	// publica lo que contiene: quien abra el panel veria ahi la IP expuesta
	// del honeypot y las redes internas de Docker. Es un mapa de la maquina
	// a cambio de ahorrarse escribir bien una direccion.
	var nombres []string
	host, _, err := net.SplitHostPort(direccion)
	if err == nil && host != "" && host != "0.0.0.0" && host != "::" {
		nombres = append(nombres, host)
	} else if dirs, err := net.InterfaceAddrs(); err == nil {
		// Atado a todas: no queda mas remedio que enumerar, pero se dejan
		// fuera las locales de enlace y las de los puentes de contenedores,
		// que nadie va a usar para abrir el panel.
		for _, d := range dirs {
			ipnet, ok := d.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() || ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			if v4 := ipnet.IP.To4(); v4 == nil || v4[0] == 172 {
				continue
			}
			// La interfaz expuesta, fuera: el panel no se sirve por ahi
			// -el cortafuegos lo impide- y anunciarla en el certificado
			// del panel de gestion es regalar el mapa de la maquina.
			if ipnet.IP.String() == c.EscuchaHoneypots {
				continue
			}
			nombres = append(nombres, ipnet.IP.String())
		}
	}
	return web.CertificadoAuto("data/tls", nombres)
}

// deseadoDe traduce la configuracion a lo que el supervisor entiende.
func deseadoDe(c config.Config) map[string]trampa.Deseado {
	out := map[string]trampa.Deseado{}
	for _, t := range trampa.Disponibles() {
		sv, hay := c.Servicios[t.ID()]
		if !hay {
			sv = config.Servicio{Activo: false, Puerto: t.PuertoPorDefecto()}
		}
		out[t.ID()] = trampa.Deseado{Activo: sv.Activo, Puerto: sv.Puerto}
	}
	return out
}

// reclasificar vuelve a juzgar los eventos ya guardados con el criterio de
// hoy.
//
// La clasificacion se congela al ingerir, asi que cada mejora del
// clasificador se queda solo para lo que llegue despues: lo capturado
// conserva para siempre el veredicto de la version que lo vio. En un
// proyecto cuyo valor es precisamente que el clasificador aprenda, eso
// deja el historico contando cosas que ya sabemos que son falsas.
//
// Se aprovecha ademas el enriquecimiento posterior: cuando se juzgo el
// evento quiza no se sabia aun de quien era la IP.
func reclasificar(almacen *store.Store, ajustes *config.Gestor, desde time.Time) error {
	eventos, err := almacen.EventosDesde(desde)
	if err != nil {
		return err
	}
	c := ajustes.Actual()
	clasificador := &classify.Clasificador{Umbrales: classify.Umbrales{
		ReputacionAlta: c.ReputacionAlta,
		DenunciasAltas: c.DenunciasAltas,
	}}

	// El origen se cachea: un escaneo deja cientos de eventos de la misma
	// IP y consultarla una vez por evento seria absurdo.
	origenes := map[string]model.Origen{}
	var cambiados int

	for i := range eventos {
		ev := &eventos[i]
		origen, visto := origenes[ev.IP]
		if !visto {
			origen, _, err = almacen.OrigenDe(ev.IP)
			if err != nil {
				return err
			}
			origenes[ev.IP] = origen
		}

		v := clasificador.Clasificar(ev, origen)
		if v.Clasificacion == ev.Clasificacion && v.Motivo == ev.Motivo {
			continue
		}
		log.Printf("  %s %s: %s -> %s", ev.Timestamp.Format("02/01 15:04"),
			ev.Tipo, ev.Clasificacion, v.Clasificacion)
		if err := almacen.Reclasificar(ev.ID, v.Clasificacion, v.Motivo); err != nil {
			return err
		}
		cambiados++
	}

	// Los episodios se derivan de la clasificacion, asi que hay que
	// rehacerlos: si no, seguirian con la severidad calculada del veredicto
	// viejo.
	if _, err := almacen.PurgarEpisodios(time.Now().Add(time.Second)); err != nil {
		return err
	}
	log.Printf("%d eventos revisados, %d cambiaron de veredicto", len(eventos), cambiados)
	log.Printf("los ataques se rehacen solos en el proximo ciclo del collector")
	return nil
}

// guardarEvento clasifica y persiste lo que capture una trampa. Es el mismo
// camino que sigue lo que llega de Cowrie.
func guardarEvento(almacen *store.Store, ajustes *config.Gestor, ev *model.Evento) {
	origen, _, err := almacen.OrigenDe(ev.IP)
	if err != nil {
		log.Printf("guardando evento de trampa: %v", err)
		return
	}
	c := ajustes.Actual()
	veredicto := (&classify.Clasificador{Umbrales: classify.Umbrales{
		ReputacionAlta: c.ReputacionAlta,
		DenunciasAltas: c.DenunciasAltas,
	}}).Clasificar(ev, origen)
	ev.Clasificacion = veredicto.Clasificacion
	ev.Motivo = veredicto.Motivo

	if _, err := almacen.Guardar(ev); err != nil {
		log.Printf("guardando evento de trampa: %v", err)
	}
}

// enriquecerEnBucle resuelve por tandas las IPs que aun no tienen contexto.
func enriquecerEnBucle(ctx context.Context, almacen *store.Store, ajustes *config.Gestor, geo *geoip.Localizador) {
	const (
		intervalo = 30 * time.Second
		porTanda  = 20
	)
	var cliente *enrich.AbuseIPDB
	var claveActiva string
	// Arranca vacia a proposito: si ya hay base configurada, el primer ciclo
	// la trata como "recien puesta" y sitúa de una vez las IP que se
	// conocian de una ejecucion anterior pero llegaron sin base. Empezar
	// con la ruta real dejaria esas IP sin ubicar hasta que caducaran.
	rutaGeoActiva := ""

	for {
		c := ajustes.Actual()
		if c.RutaGeoIP != rutaGeoActiva {
			rutaGeoActiva = c.RutaGeoIP
			if err := geo.Recargar(c.RutaGeoIP); err != nil {
				log.Printf("GeoIP: %v", err)
			} else if geo.Activo() {
				// Base nueva: se sitúan las IP que ya se conocian pero no
				// tenian coordenadas, para que el mapa se ilumine ya y no
				// dentro de una semana cuando caduque su enriquecimiento.
				if n := situarConocidas(almacen, geo); n > 0 {
					log.Printf("GeoIP: %d IPs ya conocidas situadas por ciudad", n)
				}
			}
		}
		switch {
		case !c.EnriquecerActivo || c.ClaveAbuseIPDB == "":
			cliente = nil
		case c.ClaveAbuseIPDB != claveActiva:
			// La clave cambio desde el panel: cliente nuevo, con su
			// contador de cuota a cero.
			claveActiva = c.ClaveAbuseIPDB
			cliente = enrich.NuevoAbuseIPDB(claveActiva)
			cliente.Reserva = c.ReservaCuota
		default:
			cliente.Reserva = c.ReservaCuota
		}

		if cliente == nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(intervalo):
			}
			continue
		}

		caducidad := time.Duration(c.CaducidadIPDias) * 24 * time.Hour
		if n, err := enriquecerTanda(ctx, almacen, cliente, geo, caducidad, porTanda); err != nil {
			if errors.Is(err, context.Canceled) {
				return
			}
			log.Printf("enriquecimiento: %v", err)
		} else if n > 0 {
			log.Printf("enriquecidas %d IPs", n)
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(intervalo):
		}
	}
}

func enriquecerTanda(ctx context.Context, almacen *store.Store,
	e enrich.Enriquecedor, geo *geoip.Localizador, caducidad time.Duration, limite int) (int, error) {

	ips, err := almacen.IPsPendientes(caducidad, limite)
	if err != nil {
		return 0, err
	}

	var hechas int
	for _, ip := range ips {
		if ctx.Err() != nil {
			return hechas, ctx.Err()
		}
		// Las IPs privadas no existen en internet: gastar cuota en ellas
		// seria tirar consultas de un presupuesto diario corto. Se marcan
		// como resueltas para no volver a mirarlas.
		if !enrich.EsConsultable(ip) {
			if err := almacen.GuardarOrigen(marcarNoConsultable(ip)); err != nil {
				return hechas, err
			}
			continue
		}

		origen, err := e.Enriquecer(ctx, ip)
		if errors.Is(err, enrich.ErrSinCuota) {
			log.Print("cuota de AbuseIPDB agotada; se reanudara mas tarde")
			return hechas, nil
		}
		if err != nil {
			log.Printf("no se pudo enriquecer %s: %v", ip, err)
			continue
		}
		// La ciudad y las coordenadas salen de la base local, no de la API:
		// no gasta cuota. El pais de GeoIP solo se usa si AbuseIPDB no dio
		// uno; ante discrepancia manda AbuseIPDB, que es quien clasifica.
		if lugar, ok := geo.Situar(ip); ok {
			origen.Ciudad = lugar.Ciudad
			origen.Latitud = lugar.Latitud
			origen.Longitud = lugar.Longitud
			if origen.Pais == "" {
				origen.Pais = lugar.Pais
			}
		}
		if err := almacen.GuardarOrigen(origen); err != nil {
			return hechas, err
		}
		// Ahora que sabemos quien hay detras, sus eventos pueden merecer
		// otra lectura.
		if err := reclasificarIP(almacen, origen); err != nil {
			return hechas, err
		}
		hechas++
	}
	return hechas, nil
}

// situarConocidas rellena ciudad y coordenadas de las IP que ya tenian
// ficha pero llegaron antes de haber base GeoIP. Es gratis: consulta un
// fichero local, no la API.
func situarConocidas(almacen *store.Store, geo *geoip.Localizador) int {
	ips, err := almacen.IPsSinUbicar(5000)
	if err != nil {
		log.Printf("GeoIP: %v", err)
		return 0
	}
	var hechas int
	for _, ip := range ips {
		lugar, ok := geo.Situar(ip)
		if !ok || !lugar.TieneCoordenadas() {
			continue // privada, o la base no la conoce: se deja como esta
		}
		if err := almacen.ActualizarUbicacion(ip, lugar.Ciudad, lugar.Latitud, lugar.Longitud); err != nil {
			log.Printf("GeoIP: %v", err)
			continue
		}
		hechas++
	}
	return hechas
}

// reclasificarIP repasa los eventos de una IP con su contexto ya resuelto.
func reclasificarIP(almacen *store.Store, origen model.Origen) error {
	eventos, err := almacen.EventosDeIP(origen.IP)
	if err != nil {
		return err
	}
	c := classify.Nuevo()
	for i := range eventos {
		ev := &eventos[i]
		veredicto := c.Clasificar(ev, origen)
		if veredicto.Clasificacion == ev.Clasificacion {
			continue
		}
		if err := almacen.Reclasificar(ev.ID, veredicto.Clasificacion, veredicto.Motivo); err != nil {
			return err
		}
	}
	return nil
}

func marcarNoConsultable(ip string) model.Origen {
	return model.Origen{
		IP:           ip,
		TipoUso:      "Red privada",
		Enriquecido:  true,
		ConsultadoEn: time.Now().UTC(),
	}
}

// altaUsuario crea una cuenta del panel leyendo la contrasena de la
// terminal.
//
// Es a proposito un comando de servidor y no una pantalla de alta en el
// panel: una pantalla de "crea el primer administrador" abre una ventana en
// la que cualquiera de la red puede reclamar la cuenta antes que tu.
func altaUsuario(almacen *store.Store, nombre string) error {
	if _, err := almacen.UsuarioPorNombre(nombre); err == nil {
		return fmt.Errorf("el usuario %q ya existe", nombre)
	}

	fmt.Fprintf(os.Stderr, "Contrasena para %q (minimo %d caracteres): ", nombre, auth.LongitudMinima)
	primera, err := leerContrasena()
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, "Reptela: ")
	segunda, err := leerContrasena()
	if err != nil {
		return err
	}
	if primera != segunda {
		return errors.New("las contrasenas no coinciden")
	}

	hash, err := auth.Hash(primera)
	if err != nil {
		return err
	}
	if _, err := almacen.CrearUsuario(nombre, hash); err != nil {
		return err
	}
	fmt.Printf("Usuario %q creado. Ya puedes entrar en el panel.\n", nombre)
	return nil
}

// entradaEstandar es UNO solo para todo el proceso: un bufio.Reader nuevo
// por llamada se lleva al buffer todo lo que haya pendiente, y la segunda
// lectura se encuentra con EOF aunque quedara texto por leer.
var entradaEstandar = bufio.NewReader(os.Stdin)

// resetearContrasena cambia la clave de una cuenta desde el servidor, sin
// pedir la anterior: quien tiene acceso al servidor ya podria hacerlo a
// mano sobre la base de datos. Es la salida cuando alguien se queda fuera.
func resetearContrasena(almacen *store.Store, nombre string) error {
	u, err := almacen.UsuarioPorNombre(nombre)
	if err != nil {
		return fmt.Errorf("no existe la cuenta %q", nombre)
	}

	fmt.Fprintf(os.Stderr, "Nueva contrasena para %q (minimo %d caracteres): ",
		nombre, auth.LongitudMinima)
	primera, err := leerContrasena()
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stderr, "Repitela: ")
	segunda, err := leerContrasena()
	if err != nil {
		return err
	}
	if primera != segunda {
		return errors.New("las contrasenas no coinciden")
	}

	hash, err := auth.Hash(primera)
	if err != nil {
		return err
	}
	if err := almacen.CambiarHash(u.ID, hash); err != nil {
		return err
	}
	// Cerrar las sesiones abiertas: si alguien estaba dentro, deja de estarlo.
	if err := almacen.BorrarSesionesDe(u.ID); err != nil {
		return err
	}
	fmt.Printf("Contrasena de %q cambiada. Las sesiones abiertas se han cerrado.\n", nombre)
	return nil
}

// listarCuentas ayuda a saber que hay dado de alta sin abrir la base de datos.
func listarCuentas(almacen *store.Store) error {
	cuentas, err := almacen.ListarUsuarios()
	if err != nil {
		return err
	}
	if len(cuentas) == 0 {
		fmt.Println("No hay ninguna cuenta. Crea una con -crear-usuario.")
		return nil
	}
	fmt.Printf("%-20s %-22s %s\n", "CUENTA", "CREADA", "ULTIMO ACCESO")
	for _, u := range cuentas {
		ultimo := "nunca"
		if !u.UltimoAcceso.IsZero() {
			ultimo = u.UltimoAcceso.Local().Format("2006-01-02 15:04")
		}
		fmt.Printf("%-20s %-22s %s\n", u.Nombre,
			u.CreadoEn.Local().Format("2006-01-02 15:04"), ultimo)
	}
	return nil
}

// leerContrasena la pide sin eco si hay terminal; si la entrada viene por
// tuberia, la lee tal cual para poder automatizar.
func leerContrasena() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		return strings.TrimSpace(string(b)), err
	}
	linea, err := entradaEstandar.ReadString(0x0a)
	if err != nil && linea == "" {
		// Sin terminal y sin nada en la entrada. Un "EOF" pelado no le dice
		// a nadie que le falta escribir la contrasena: pasa al ejecutarlo
		// desde un script o con la entrada redirigida.
		return "", fmt.Errorf("no hay contrasena en la entrada: ejecutalo desde " +
			"una terminal, o pasala por tuberia (echo 'tuClave' | k0pot -crear-usuario ...)")
	}
	return strings.TrimSpace(linea), nil
}

// servirPanel levanta el panel web.
func servirPanel(almacen *store.Store, ajustes *config.Gestor, direccion, rutaBD string, sinLLM bool) error {
	// La direccion del flag es el punto de partida, pero manda la
	// configuracion si la hay: es lo que se edita desde el panel.
	direccion = direccionDelPanel(direccion, ajustes.Actual().EscuchaPanel)

	srv := &web.Servidor{
		Almacen:   almacen,
		Config:    ajustes,
		Version:   version,
		Generador: generadorDe(almacen, ajustes.Actual(), sinLLM),
		Trampas:   trampa.Disponibles(),
		// Donde Cowrie deja lo que consigue capturar. Que el directorio no
		// exista es lo normal hasta que alguien descargue algo.
		DirDescargas: "data/cowrie/lib/downloads",
		RutaBD:       rutaBD,
		DirCowrie:    "data/cowrie/lib",
	}
	// Al guardar ajustes se rehace el generador, para que cambiar de modelo
	// o de clave surta efecto sin reiniciar el servicio.
	srv.AlCambiarConfig = func(c config.Config) {
		srv.Generador = generadorDe(almacen, c, sinLLM)
	}

	http := &nethttp.Server{
		Addr:              direccion,
		Handler:           srv.Rutas(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, parar := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer parar()

	go func() {
		<-ctx.Done()
		cierre, cancelar := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelar()
		http.Shutdown(cierre)
	}()

	// Barredor de narrativas: en segundo plano genera las explicaciones de
	// ataques, campanas y artefactos que faltan, para que aparezcan solas al
	// abrirlos sin llamar al modelo en ese momento.
	go srv.BarrerExplicaciones(ctx)

	if c := ajustes.Actual(); c.PanelHTTPS {
		cert, err := certificadoDelPanel(c, direccion)
		if err != nil {
			return err
		}
		log.Printf("k0Pot %s | panel en https://%s", version, direccion)
		log.Printf("quien entre por http sera redirigido; el navegador avisara " +
			"del certificado autofirmado la primera vez")
		if err := web.ServirTLS(direccion, srv.Rutas(), cert); err != nil {
			return fmt.Errorf("panel: %w", err)
		}
		return nil
	}

	log.Printf("k0Pot %s | panel en http://%s", version, direccion)
	log.Printf("sin cifrar: la contrasena del panel viaja en claro. " +
		"Se activa HTTPS en Ajustes → General")
	if err := http.ListenAndServe(); err != nil && err != nethttp.ErrServerClosed {
		return err
	}
	log.Print("panel detenido")
	return nil
}

// direccionDelPanel combina el puerto del flag con la interfaz configurada.
//
// Si la configuracion trae una IP que no existe en la maquina, atarse a ella
// dejaria el panel sin arrancar y sin forma de entrar a arreglarlo. Por eso
// se comprueba antes y, si no cuadra, se avisa y se sigue con lo del flag.
func direccionDelPanel(delFlag, configurada string) string {
	if configurada == "" {
		return delFlag
	}
	_, puerto, err := net.SplitHostPort(delFlag)
	if err != nil {
		return delFlag
	}

	if configurada != "0.0.0.0" && !tieneDireccion(configurada) {
		log.Printf("la interfaz configurada para el panel (%s) no existe en esta maquina; "+
			"se mantiene %s", configurada, delFlag)
		return delFlag
	}
	return net.JoinHostPort(configurada, puerto)
}

// tieneDireccion comprueba que la IP este realmente en alguna interfaz.
func tieneDireccion(ip string) bool {
	dirs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, d := range dirs {
		if ipnet, ok := d.(*net.IPNet); ok && ipnet.IP.String() == ip {
			return true
		}
	}
	return false
}

// generadorDe elige quien redacta el informe segun la configuracion. Sin
// clave, con el LLM desactivado o con -sin-llm, honey sigue informando:
// solo con textos mas escuetos.
// hookTokens devuelve una funcion que acumula los tokens de cada llamada al
// modelo en la cuota del dia, para el contador en vivo de la cabecera.
func hookTokens(almacen *store.Store) func(int) {
	return func(n int) {
		_ = almacen.SumarTokensLLM(time.Now().Format("2006-01-02"), n)
	}
}

func generadorDe(almacen *store.Store, c config.Config, sinLLM bool) report.Generador {
	if sinLLM || !c.UsarLLM {
		return report.PorReglas{}
	}
	var gens []report.ModeloGen
	for _, m := range c.ModelosEfectivos() {
		if m.Clave == "" {
			continue
		}
		id := m.Proveedor
		if id == "" {
			id = "compatible"
		}
		prov, ok := config.ProveedorPorID(m.Proveedor)
		modelo := m.Modelo
		if modelo == "" && ok {
			modelo = prov.Modelo
		}
		esAnthropic := (ok && prov.Tipo == config.ProveedorAnthropic) || m.Proveedor == "anthropic"
		var g report.Explicador
		if esAnthropic {
			cl := report.NuevoConLLM(m.Clave, modelo)
			cl.AlUsar = hookTokens(almacen)
			g = cl
		} else {
			url := ""
			if ok {
				url = prov.URLBase
			}
			cc := report.NuevoCompatible(url, m.Clave, modelo)
			cc.AlUsar = hookTokens(almacen)
			g = cc
		}
		gens = append(gens, report.ModeloGen{ID: id, Gen: g})
	}
	if len(gens) == 0 {
		return report.PorReglas{}
	}
	return &report.Multiplexor{
		Modelos:    gens,
		Disponible: func(id string) bool { return disponibleProv(almacen, id) },
		AlAgotar:   func(id string, err error) { marcarAgotadoProv(almacen, id, err) },
		Respaldo:   report.PorReglas{},
	}
}

// disponibleProv dice si un proveedor tiene tokens ahora (no esta en pausa por
// un 429 reciente). El multiplexor lo usa para saltarse el agotado sin gastar
// una llamada.
func disponibleProv(almacen *store.Store, id string) bool {
	v, _ := almacen.LeerEstado("ia_pausa:" + id)
	if v == "" {
		return true
	}
	hasta, err := time.Parse(time.RFC3339, v)
	return err != nil || !time.Now().Before(hasta)
}

// marcarAgotadoProv apunta que un proveedor se quedo sin tokens: pausa 5 min y,
// si el 429 revela el tope diario, lo guarda.
func marcarAgotadoProv(almacen *store.Store, id string, err error) {
	// Un limite por minuto (lo normal en tiers free como Gemini) se recupera
	// enseguida: pausa corta. Un limite POR DIA (Groq TPD) no vale la pena
	// reintentarlo tan seguido: pausa larga.
	espera := 60 * time.Second
	m := strings.ToLower(err.Error())
	if strings.Contains(m, "per day") || strings.Contains(m, "tpd") || strings.Contains(m, "daily") {
		espera = 15 * time.Minute
	}
	_ = almacen.GuardarEstado("ia_pausa:"+id, time.Now().Add(espera).UTC().Format(time.RFC3339))
	if lim := report.LimiteDiarioDeTokens(err); lim > 0 {
		_ = almacen.GuardarEstado("tokens_limite:"+id, strconv.Itoa(lim))
	}
}

// reunirDatos junta en una sola estructura todo lo que un informe necesita.
func reunirDatos(almacen *store.Store, dias int) (report.Datos, error) {
	desde := time.Now().AddDate(0, 0, -dias)

	resumen, err := almacen.Resumir(desde)
	if err != nil {
		return report.Datos{}, err
	}
	niveles, err := almacen.PorClasificacion(desde)
	if err != nil {
		return report.Datos{}, err
	}
	destacados, err := almacen.Destacados(desde, 20)
	if err != nil {
		return report.Datos{}, err
	}
	return report.Datos{
		Desde: desde, Hasta: time.Now(),
		Resumen: resumen, Niveles: niveles, Destacados: destacados,
	}, nil
}

func mostrarInforme(almacen *store.Store, ajustes *config.Gestor, dias int, sinLLM bool) error {
	datos, err := reunirDatos(almacen, dias)
	if err != nil {
		return err
	}

	res, err := generadorDe(almacen, ajustes.Actual(), sinLLM).Generar(context.Background(), datos)
	if err != nil {
		return err
	}

	fmt.Printf("\n  k0Pot %s — informe de los ultimos %d dia(s)\n", version, dias)
	fmt.Printf("  ─────────────────────────────────────\n\n")
	for _, linea := range strings.Split(strings.TrimSpace(res.Texto), "\n") {
		fmt.Printf("  %s\n", linea)
	}
	fmt.Printf("\n  (redactado por: %s)\n\n", res.Redactado)
	return nil
}

func mostrarResumen(almacen *store.Store, dias int) error {
	desde := time.Now().AddDate(0, 0, -dias)
	r, err := almacen.Resumir(desde)
	if err != nil {
		return err
	}

	fmt.Printf("\n  k0Pot %s — ultimos %d dia(s)\n", version, dias)
	fmt.Printf("  ─────────────────────────────────────\n\n")

	if r.Total == 0 {
		fmt.Printf("  Sin actividad registrada.\n\n")
		return nil
	}

	niveles, err := almacen.PorClasificacion(desde)
	if err != nil {
		return err
	}
	fmt.Printf("  %s\n\n", semaforo(niveles))

	fmt.Printf("  %d eventos desde %d IPs distintas\n", r.Total, r.IPsUnicas)
	fmt.Printf("  entre %s y %s\n\n",
		r.Primero.Local().Format("02/01 15:04"),
		r.Ultimo.Local().Format("02/01 15:04"))

	if err := mostrarDestacados(almacen, desde); err != nil {
		return err
	}

	fmt.Printf("  Por tipo de evento\n")
	for _, c := range r.PorTipo {
		fmt.Printf("    %-22s %6d\n", c.Valor, c.N)
	}

	if len(r.PorPais) > 0 {
		fmt.Printf("\n  Por pais de origen\n")
		for _, c := range r.PorPais {
			fmt.Printf("    %-22s %6d\n", c.Valor, c.N)
		}
	}

	fmt.Printf("\n  IPs mas activas\n")
	for _, a := range r.TopIPs {
		fmt.Printf("    %-16s %6d  %s\n", a.IP, a.Eventos, contexto(a))
	}

	imprimirTop := func(titulo string, cs []store.Recuento) {
		if len(cs) == 0 {
			return
		}
		fmt.Printf("\n  %s\n", titulo)
		for _, c := range cs {
			fmt.Printf("    %-22s %6d\n", recortar(c.Valor, 22), c.N)
		}
	}
	imprimirTop("Usuarios mas probados", r.TopUsuarios)
	imprimirTop("Contrasenas mas probadas", r.TopPasswords)
	fmt.Println()
	return nil
}

// contexto resume en una linea quien hay detras de una IP.
func contexto(a store.IPActiva) string {
	if !a.Enriquecido {
		return "(sin datos todavia)"
	}
	var partes []string
	if a.Pais != "" {
		partes = append(partes, a.Pais)
	}
	if a.ISP != "" {
		partes = append(partes, recortar(a.ISP, 24))
	}
	if a.Tor {
		partes = append(partes, "TOR")
	}
	if a.Reputacion > 0 {
		partes = append(partes, fmt.Sprintf("reputacion %d/100, %d denuncias",
			a.Reputacion, a.TotalReportes))
	}
	if len(partes) == 0 {
		return "(sin datos publicos)"
	}
	return strings.Join(partes, " · ")
}

// semaforo resume en una frase si hay algo de lo que preocuparse. Es la
// linea mas importante del informe: cuando no pasa nada hay que decirlo
// con claridad, no enterrar al lector en cifras.
func semaforo(niveles map[model.Clasificacion]int) string {
	notables := niveles[model.Notable]
	revisar := niveles[model.Revisar]

	switch {
	case notables > 0:
		return fmt.Sprintf("ROJO — %d evento(s) piden que los mires: "+
			"alguien no se limito a llamar a la puerta", notables)
	case revisar > 0:
		return fmt.Sprintf("AMBAR — %d evento(s) se salen de lo normal, "+
			"pero nada indica que hayan entrado", revisar)
	default:
		return "VERDE — todo es ruido de fondo automatizado; " +
			"no hay nada que requiera tu atencion"
	}
}

// mostrarDestacados lista lo que no es ruido, con su explicacion.
func mostrarDestacados(almacen *store.Store, desde time.Time) error {
	destacados, err := almacen.Destacados(desde, 10)
	if err != nil {
		return err
	}
	if len(destacados) == 0 {
		return nil
	}

	fmt.Printf("  Lo que merece una mirada\n")
	for _, d := range destacados {
		etiqueta := "revisar"
		if d.Clasificacion == model.Notable {
			etiqueta = "NOTABLE"
		}
		origen := d.IP
		if d.Pais != "" {
			origen += " (" + d.Pais + ")"
		}
		fmt.Printf("    [%s] %s  %s\n", etiqueta,
			d.Timestamp.Local().Format("02/01 15:04"), origen)
		fmt.Printf("             %s\n", d.Motivo)
		if c := d.Detalle["comando"]; c != "" {
			fmt.Printf("             comando: %s\n", recortar(c, 60))
		}
	}
	fmt.Println()
	return nil
}

func recortar(s string, max int) string {
	if s == "" {
		return "(vacio)"
	}
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}
