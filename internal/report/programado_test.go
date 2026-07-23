package report

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/store"
)

// almacenFalso guarda en memoria lo justo para probar la politica.
type almacenFalso struct {
	informe store.InformeGuardado
	hay     bool
	cuota   map[string]int
}

func nuevoAlmacen() *almacenFalso {
	return &almacenFalso{cuota: map[string]int{}}
}

func (a *almacenFalso) GuardarInforme(i store.InformeGuardado) error {
	a.informe, a.hay = i, true
	return nil
}

func (a *almacenFalso) UltimoInforme() (store.InformeGuardado, bool, error) {
	return a.informe, a.hay, nil
}

func (a *almacenFalso) ConsumirCuotaLLM(dia string, tope int) (bool, error) {
	if tope > 0 && a.cuota[dia] >= tope {
		return false, nil
	}
	a.cuota[dia]++
	return true, nil
}

func (a *almacenFalso) CuotaLLMUsada(dia string) (int, error) { return a.cuota[dia], nil }

// generadorFalso cuenta cuantas veces se le pide un texto: eso es
// exactamente lo que se factura.
type generadorFalso struct {
	nombre string
	veces  int
	fallo  error
}

func (g *generadorFalso) Generar(context.Context, Datos) (Resultado, error) {
	g.veces++
	if g.fallo != nil {
		return Resultado{}, g.fallo
	}
	return Resultado{Texto: "texto", Redactado: g.nombre}, nil
}

func (g *generadorFalso) Nombre() string { return g.nombre }

func datosCon(total int) Datos {
	return Datos{
		Resumen: &store.Resumen{Total: total},
		Niveles: map[model.Clasificacion]int{model.RuidoFondo: total},
	}
}

// montar deja un Programado con reloj controlado y tope generoso.
func montar(tope int) (*Programado, *generadorFalso, *generadorFalso, *time.Time) {
	llm := &generadorFalso{nombre: "llm:falso"}
	reglas := &generadorFalso{nombre: NombreReglas}
	ahora := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	p := &Programado{
		Gen: llm, Respaldo: reglas, Alm: nuevoAlmacen(),
		Intervalo: 15 * time.Minute, TopeDiario: tope,
		Ahora: func() time.Time { return ahora },
	}
	return p, llm, reglas, &ahora
}

func TestPrimerInformeSeRedacta(t *testing.T) {
	p, llm, _, _ := montar(50)
	s, err := p.Asegurar(context.Background(), datosCon(3), 7, false)
	if err != nil {
		t.Fatal(err)
	}
	if llm.veces != 1 {
		t.Fatalf("se esperaba 1 llamada, hubo %d", llm.veces)
	}
	if !s.Fresco {
		t.Error("el primer informe deberia venir marcado como fresco")
	}
}

// El caso que motivo todo esto: el panel refrescando sin parar.
func TestPanelRefrescandoNoGastaLlamadas(t *testing.T) {
	p, llm, _, _ := montar(50)
	d := datosCon(3)
	for i := 0; i < 200; i++ {
		if _, err := p.Asegurar(context.Background(), d, 7, false); err != nil {
			t.Fatal(err)
		}
	}
	if llm.veces != 1 {
		t.Fatalf("200 refrescos con los mismos datos gastaron %d llamadas, se esperaba 1", llm.veces)
	}
}

func TestDatosNuevosDentroDelIntervaloEsperan(t *testing.T) {
	p, llm, _, reloj := montar(50)
	if _, err := p.Asegurar(context.Background(), datosCon(3), 7, false); err != nil {
		t.Fatal(err)
	}
	*reloj = reloj.Add(5 * time.Minute) // menos que el intervalo
	s, err := p.Asegurar(context.Background(), datosCon(99), 7, false)
	if err != nil {
		t.Fatal(err)
	}
	if llm.veces != 1 {
		t.Fatalf("se regenero antes de tiempo: %d llamadas", llm.veces)
	}
	if s.Fresco {
		t.Error("no deberia venir marcado como fresco")
	}
}

func TestDatosNuevosPasadoElIntervaloRegeneran(t *testing.T) {
	p, llm, _, reloj := montar(50)
	if _, err := p.Asegurar(context.Background(), datosCon(3), 7, false); err != nil {
		t.Fatal(err)
	}
	*reloj = reloj.Add(20 * time.Minute)
	if _, err := p.Asegurar(context.Background(), datosCon(99), 7, false); err != nil {
		t.Fatal(err)
	}
	if llm.veces != 2 {
		t.Fatalf("se esperaban 2 llamadas, hubo %d", llm.veces)
	}
}

func TestForzarSaltaElIntervalo(t *testing.T) {
	p, llm, _, _ := montar(50)
	if _, err := p.Asegurar(context.Background(), datosCon(3), 7, false); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Asegurar(context.Background(), datosCon(3), 7, true); err != nil {
		t.Fatal(err)
	}
	if llm.veces != 2 {
		t.Fatalf("el boton no regenero: %d llamadas", llm.veces)
	}
}

// El freno duro: pase lo que pase, la cuota diaria no se rebasa.
func TestTopeDiarioNoSeRebasa(t *testing.T) {
	p, llm, reglas, reloj := montar(3)
	for i := 0; i < 30; i++ {
		if _, err := p.Asegurar(context.Background(), datosCon(i), 7, true); err != nil {
			t.Fatal(err)
		}
		*reloj = reloj.Add(time.Minute)
	}
	if llm.veces != 3 {
		t.Fatalf("se rebaso el tope: %d llamadas al LLM, tope 3", llm.veces)
	}
	if reglas.veces != 27 {
		t.Fatalf("las reglas debian cubrir el resto: %d", reglas.veces)
	}
}

func TestTopeSeRenuevaAlCambiarDeDia(t *testing.T) {
	p, llm, _, reloj := montar(2)
	for i := 0; i < 5; i++ {
		if _, err := p.Asegurar(context.Background(), datosCon(i), 7, true); err != nil {
			t.Fatal(err)
		}
	}
	if llm.veces != 2 {
		t.Fatalf("tope del primer dia: %d", llm.veces)
	}
	*reloj = reloj.Add(24 * time.Hour)
	if _, err := p.Asegurar(context.Background(), datosCon(9), 7, true); err != nil {
		t.Fatal(err)
	}
	if llm.veces != 3 {
		t.Fatalf("el dia nuevo deberia traer cuota limpia: %d", llm.veces)
	}
}

func TestCambiarElPeriodoRegenera(t *testing.T) {
	p, llm, _, _ := montar(50)
	d := datosCon(3)
	if _, err := p.Asegurar(context.Background(), d, 7, false); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Asegurar(context.Background(), d, 30, false); err != nil {
		t.Fatal(err)
	}
	if llm.veces != 2 {
		t.Fatalf("otro periodo es otra pregunta: %d llamadas", llm.veces)
	}
}

// Si la API falla, el panel debe seguir ensenando el ultimo informe bueno
// en vez de un error.
func TestFalloAlRedactarConservaElAnterior(t *testing.T) {
	p, llm, _, reloj := montar(50)
	if _, err := p.Asegurar(context.Background(), datosCon(3), 7, false); err != nil {
		t.Fatal(err)
	}
	llm.fallo = errors.New("HTTP 429: rate limit")
	*reloj = reloj.Add(20 * time.Minute)
	s, err := p.Asegurar(context.Background(), datosCon(99), 7, false)
	if err != nil {
		t.Fatalf("no deberia propagar el error habiendo informe previo: %v", err)
	}
	if s.Texto != "texto" {
		t.Error("se perdio el informe anterior")
	}
	if s.Motivo == "" {
		t.Error("hay que explicar por que no se actualizo")
	}
}

// La huella no puede depender del instante de la consulta: si dependiera,
// cada refresco del panel pareceria un dato nuevo.
func TestHuellaIgnoraElInstanteDeConsulta(t *testing.T) {
	d1 := datosCon(5)
	d1.Desde, d1.Hasta = time.Now().Add(-time.Hour), time.Now()
	d2 := datosCon(5)
	d2.Desde, d2.Hasta = time.Now().Add(-time.Hour), time.Now().Add(time.Minute)
	if Huella(d1) != Huella(d2) {
		t.Error("la huella cambia solo por consultar en otro momento")
	}
}

func TestHuellaCambiaConLosDatos(t *testing.T) {
	if Huella(datosCon(5)) == Huella(datosCon(6)) {
		t.Error("datos distintos deberian dar huellas distintas")
	}
}
