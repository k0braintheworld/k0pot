package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// NombreReglas es como se firma el generador determinista. Sirve ademas
// para saber que una generacion NO va a costar tokens.
const NombreReglas = "reglas"

// Huella resume los datos de un informe en una cadena corta.
//
// Solo entra el CONTENIDO, nunca el instante de la consulta: "hasta" es
// time.Now() y cambiaria en cada refresco del panel, que es precisamente
// lo que hay que evitar. Si la huella no cambia, un informe nuevo diria
// exactamente lo mismo que el guardado y no merece una llamada de pago.
func Huella(d Datos) string {
	// Los mapas se serializan con las claves ordenadas, asi que la huella
	// es estable entre ejecuciones.
	crudo, err := json.Marshal(struct {
		Resumen    *store.Resumen              `json:"r"`
		Niveles    map[model.Clasificacion]int `json:"n"`
		Destacados []store.Destacado           `json:"d"`
		// Los ataques entran en la huella: si no, un ataque nuevo que no
		// mueva los recuentos no dispararia un informe nuevo, que es
		// justo el caso en que hace falta.
		Episodios []store.EpisodioFila `json:"e"`
	}{d.Resumen, d.Niveles, d.Destacados, d.Episodios})
	if err != nil {
		// Ante la duda, huella imposible de repetir: se regenera. Mas vale
		// gastar una llamada que servir un informe que no corresponde.
		return fmt.Sprintf("indeterminada-%d", time.Now().UnixNano())
	}
	suma := sha256.Sum256(crudo)
	return hex.EncodeToString(suma[:16])
}

// Almacen es lo que Programado necesita de la base de datos.
type Almacen interface {
	GuardarInforme(store.InformeGuardado) error
	UltimoInforme() (store.InformeGuardado, bool, error)
	ConsumirCuotaLLM(dia string, tope int) (bool, error)
	CuotaLLMUsada(dia string) (int, error)
}

// Programado decide CUANDO se redacta un informe, no como.
//
// El panel pide el informe en cada refresco, cada 20 s por defecto. Sin
// freno eso son mas de cuatro mil llamadas diarias a la API por una sola
// pestaña abierta, que agotan la cuota del dia en unas horas y dejan el
// panel dando informes de reglas justo cuando podrian hacer falta.
//
// Hay tres frenos, y los tres hacen falta:
//
//   - Huella: si los datos no cambiaron, se sirve el guardado.
//   - Intervalo: en un honeypot expuesto llegan eventos sin parar, asi que
//     la huella cambiaria continuamente. Sola no frena nada.
//   - Tope diario: limite duro. Los dos anteriores son heuristicas; este
//     es el que garantiza que la cuota no se puede agotar.
//
// No se genera en segundo plano a proposito: si nadie mira el panel, no se
// gasta un solo token.
type Programado struct {
	Gen Generador
	// Respaldo redacta cuando se agota el tope diario. Siempre PorReglas:
	// es gratis, instantaneo y nunca falla.
	Respaldo  Generador
	Alm       Almacen
	Intervalo time.Duration
	// TopeDiario <= 0 significa sin limite.
	TopeDiario int
	// Ahora existe para poder probar el paso del tiempo.
	Ahora func() time.Time
}

// Servido es un informe listo para el panel, con el porque de haberlo
// regenerado o no. Ese porque se ensena: un informe con hora pero sin
// explicacion invita a pensar que esta atascado.
type Servido struct {
	store.InformeGuardado
	Fresco     bool
	Motivo     string
	CuotaUsada int
	CuotaTope  int
}

func (p *Programado) ahora() time.Time {
	if p.Ahora != nil {
		return p.Ahora()
	}
	return time.Now()
}

// Asegurar devuelve el informe vigente, redactando uno nuevo solo si toca.
// Con forzar se salta el intervalo y la huella, pero nunca el tope diario.
func (p *Programado) Asegurar(ctx context.Context, d Datos, dias int, forzar bool) (Servido, error) {
	huella := Huella(d)
	ahora := p.ahora()
	dia := ahora.Format("2006-01-02")

	previo, hay, err := p.Alm.UltimoInforme()
	if err != nil {
		return Servido{}, err
	}

	regenerar, motivo := p.decidir(previo, hay, huella, dias, ahora, forzar)
	usada, _ := p.Alm.CuotaLLMUsada(dia)

	if !regenerar {
		return Servido{
			InformeGuardado: previo, Fresco: false, Motivo: motivo,
			CuotaUsada: usada, CuotaTope: p.TopeDiario,
		}, nil
	}

	gen := p.Gen
	// Solo se consume cuota si el generador cuesta dinero. Las reglas son
	// gratis y no tiene sentido racionarlas.
	if gen.Nombre() != NombreReglas {
		permitido, err := p.Alm.ConsumirCuotaLLM(dia, p.TopeDiario)
		if err != nil {
			return Servido{}, err
		}
		if !permitido {
			gen = p.Respaldo
			motivo = fmt.Sprintf(
				"alcanzado el tope de %d informes con IA hoy; lo redactan las reglas",
				p.TopeDiario)
		}
		usada, _ = p.Alm.CuotaLLMUsada(dia)
	}

	res, err := gen.Generar(ctx, d)
	if err != nil {
		// Un fallo al redactar no debe dejar al panel sin informe: si habia
		// uno guardado, sigue siendo mejor que un error en pantalla.
		if hay {
			return Servido{
				InformeGuardado: previo, Fresco: false,
				Motivo:     "no se pudo redactar uno nuevo: " + err.Error(),
				CuotaUsada: usada, CuotaTope: p.TopeDiario,
			}, nil
		}
		return Servido{}, err
	}

	nuevo := store.InformeGuardado{
		Texto: res.Texto, Generador: res.Redactado,
		Huella: huella, Dias: dias, Momento: ahora,
	}
	if err := p.Alm.GuardarInforme(nuevo); err != nil {
		return Servido{}, err
	}
	return Servido{
		InformeGuardado: nuevo, Fresco: true, Motivo: motivo,
		CuotaUsada: usada, CuotaTope: p.TopeDiario,
	}, nil
}

// decidir separa la politica de la fontaneria, que es lo unico que hay que
// leer para entender cuando se gasta una llamada.
func (p *Programado) decidir(
	previo store.InformeGuardado, hay bool, huella string,
	dias int, ahora time.Time, forzar bool,
) (bool, string) {
	switch {
	case !hay:
		return true, "primer informe"
	case forzar:
		return true, "regenerado a mano"
	case previo.Dias != dias:
		// Otro rango de fechas es otra pregunta, no el mismo informe.
		return true, "cambio el periodo consultado"
	case previo.Huella == huella:
		return false, "sin novedades desde el ultimo informe"
	case ahora.Sub(previo.Momento) < p.Intervalo:
		faltan := p.Intervalo - ahora.Sub(previo.Momento)
		return false, fmt.Sprintf(
			"hay datos nuevos; se actualiza en %s", faltan.Round(time.Minute))
	default:
		return true, "hay datos nuevos"
	}
}
