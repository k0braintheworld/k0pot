package report

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// NombreReglas es como se firma el generador determinista.
const NombreReglas = "reglas"

// Huella resume los datos de un informe en una cadena corta.
//
// Solo entra el CONTENIDO, nunca el instante de la consulta: "hasta" es
// time.Now() y cambiaria en cada refresco del panel. Sirve para saber si un
// informe guardado sigue describiendo lo que hay.
func Huella(d Datos) string {
	crudo, err := json.Marshal(struct {
		Resumen    *store.Resumen              `json:"r"`
		Niveles    map[model.Clasificacion]int `json:"n"`
		Destacados []store.Destacado           `json:"d"`
		Episodios  []store.EpisodioFila        `json:"e"`
	}{d.Resumen, d.Niveles, d.Destacados, d.Episodios})
	if err != nil {
		return fmt.Sprintf("indeterminada-%d", time.Now().UnixNano())
	}
	suma := sha256.Sum256(crudo)
	return hex.EncodeToString(suma[:16])
}

// Almacen es lo que Politica necesita de la base de datos.
type Almacen interface {
	GuardarInforme(store.InformeGuardado) error
	UltimoInforme() (store.InformeGuardado, bool, error)
	ConsumirCuotaLLM(dia string, tope int) (bool, error)
	CuotaLLMUsada(dia string) (int, error)
}

// Politica decide quien redacta cada informe.
//
// El panel pide el informe en cada refresco, cada 20 s por defecto. Que esa
// peticion cueste dinero es una mala idea por dos motivos: gasta la cuota
// del dia en mirar el panel, y la gasta en lo rutinario, que es cuando
// menos aporta un modelo.
//
// Asi que el reparto es tajante: lo automatico lo redactan las REGLAS, que
// son deterministas, instantaneas y gratis; y el modelo entra SOLO cuando
// alguien lo pide a mano. Asi la cuota se gasta en los informes que alguien
// va a leer de verdad.
type Politica struct {
	// Gen es el generador configurado; puede ser el modelo o las reglas.
	Gen Generador
	// Reglas redacta lo automatico y hace de red cuando el modelo falla.
	Reglas Generador
	Alm    Almacen
	// TopeDiario acota las peticiones a mano. <= 0 significa sin limite.
	TopeDiario int
	// Ahora existe para poder probar el paso del tiempo.
	Ahora func() time.Time
}

// devolver deshace una llamada apuntada que no llego a hacerse. Se ignora
// el error a proposito: fallar al devolver cuota no puede impedir entregar
// el informe que el usuario esta esperando.
func (p *Politica) devolver(dia string) {
	if d, ok := p.Alm.(interface{ DevolverCuotaLLM(string) error }); ok {
		_ = d.DevolverCuotaLLM(dia)
	}
}

// Servido es un informe listo para el panel.
type Servido struct {
	store.InformeGuardado
	// ConIA distingue lo que redacto el modelo de lo que salio de reglas.
	ConIA bool
	// Desactualizado avisa de que el informe con IA se redacto con datos
	// que ya no son los de ahora. Se ensena en vez de regenerarlo solo:
	// quien lo pidio decide si vuelve a gastar.
	Desactualizado bool
	Motivo         string
	CuotaUsada     int
	CuotaTope      int
}

func (p *Politica) ahora() time.Time {
	if p.Ahora != nil {
		return p.Ahora()
	}
	return time.Now()
}

func (p *Politica) usaIA() bool { return p.Gen != nil && !loEscribieronLasReglas(p.Gen.Nombre()) }

// loEscribieronLasReglas reconoce la firma del generador determinista.
//
// No basta con comparar por igualdad: cuando el modelo falla, ConLLM se
// repliega y firma "reglas (el LLM no estaba disponible: ...)" para no
// atribuir el texto a quien no lo escribio. Comparar con == daba por
// redactado con IA justo lo que la IA no habia podido redactar.
func loEscribieronLasReglas(firma string) bool {
	return firma == NombreReglas || strings.HasPrefix(firma, NombreReglas+" ")
}

// Automatico es el informe de cada refresco: siempre por reglas, siempre
// gratis.
//
// Si hay uno con IA guardado se sirve ese, porque es mejor y ya esta
// pagado, avisando cuando los datos han cambiado desde entonces.
func (p *Politica) Automatico(ctx context.Context, d Datos, dias int) (Servido, error) {
	huella := Huella(d)
	dia := p.ahora().Format("2006-01-02")
	usada, _ := p.Alm.CuotaLLMUsada(dia)

	previo, hay, err := p.Alm.UltimoInforme()
	if err != nil {
		return Servido{}, err
	}
	if hay && previo.Dias == dias && !loEscribieronLasReglas(previo.Generador) {
		s := Servido{
			InformeGuardado: previo, ConIA: true,
			Desactualizado: previo.Huella != huella,
			CuotaUsada:     usada, CuotaTope: p.TopeDiario,
		}
		if s.Desactualizado {
			s.Motivo = "hay actividad nueva desde este informe"
		}
		return s, nil
	}

	res, err := p.Reglas.Generar(ctx, d)
	if err != nil {
		return Servido{}, err
	}
	motivo := "resumen automatico"
	if p.usaIA() {
		motivo = "resumen automatico; pulsa para redactarlo con IA"
	}
	return Servido{
		InformeGuardado: store.InformeGuardado{
			Texto: res.Texto, Generador: res.Redactado,
			Huella: huella, Dias: dias, Momento: p.ahora(),
		},
		Motivo: motivo, CuotaUsada: usada, CuotaTope: p.TopeDiario,
	}, nil
}

// AMano redacta con el modelo porque alguien lo ha pedido.
func (p *Politica) AMano(ctx context.Context, d Datos, dias int) (Servido, error) {
	huella := Huella(d)
	ahora := p.ahora()
	dia := ahora.Format("2006-01-02")

	if !p.usaIA() {
		// Sin modelo configurado no hay nada que pedir a mano; se devuelve
		// el de reglas para no dejar el panel en blanco.
		return p.Automatico(ctx, d, dias)
	}

	permitido, err := p.Alm.ConsumirCuotaLLM(dia, p.TopeDiario)
	if err != nil {
		return Servido{}, err
	}
	usada, _ := p.Alm.CuotaLLMUsada(dia)
	if !permitido {
		s, err := p.Automatico(ctx, d, dias)
		if err != nil {
			return Servido{}, err
		}
		s.Motivo = fmt.Sprintf("alcanzado el tope de %d informes con IA hoy", p.TopeDiario)
		s.CuotaUsada, s.CuotaTope = usada, p.TopeDiario
		return s, nil
	}

	res, err := p.Gen.Generar(ctx, d)
	if err != nil {
		p.devolver(dia)
		s, errAuto := p.Automatico(ctx, d, dias)
		if errAuto != nil {
			return Servido{}, err
		}
		s.Motivo = "no se pudo redactar con IA: " + err.Error()
		s.CuotaUsada, s.CuotaTope = usada, p.TopeDiario
		return s, nil
	}

	nuevo := store.InformeGuardado{
		Texto: res.Texto, Generador: res.Redactado,
		Huella: huella, Dias: dias, Momento: ahora,
	}
	conIA := !loEscribieronLasReglas(res.Redactado)
	if !conIA {
		// El modelo no llego a redactar: se replegó a reglas y no consumio
		// nada suyo, asi que la llamada apuntada se devuelve.
		p.devolver(dia)
	}
	if conIA {
		// Solo se guarda lo que de verdad redacto el modelo. Guardar un
		// repliegue lo serviria despues como si fuera un informe con IA
		// ya pagado, y ni lo es ni volveria a intentarse.
		if err := p.Alm.GuardarInforme(nuevo); err != nil {
			return Servido{}, err
		}
	}
	motivo := "redactado con IA"
	if !conIA {
		motivo = "la IA no estaba disponible; lo redactaron las reglas"
	}
	return Servido{
		InformeGuardado: nuevo, ConIA: conIA,
		Motivo: motivo, CuotaUsada: usada, CuotaTope: p.TopeDiario,
	}, nil
}
