package report

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/k0braintheworld/k0pot/internal/model"
	"github.com/k0braintheworld/k0pot/internal/store"
)

type almacenFalso struct {
	informe store.InformeGuardado
	hay     bool
	cuota   map[string]int
}

func nuevoAlmacen() *almacenFalso { return &almacenFalso{cuota: map[string]int{}} }

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

func (a *almacenFalso) DevolverCuotaLLM(dia string) error {
	if a.cuota[dia] > 0 {
		a.cuota[dia]--
	}
	return nil
}

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
	return Resultado{Texto: "texto del modelo", Redactado: g.nombre}, nil
}
func (g *generadorFalso) Nombre() string { return g.nombre }

func datosCon(total int) Datos {
	return Datos{
		Resumen: &store.Resumen{Total: total},
		Niveles: map[model.Clasificacion]int{model.RuidoFondo: total},
	}
}

func montar(tope int) (*Politica, *generadorFalso, *generadorFalso, *time.Time) {
	llm := &generadorFalso{nombre: "llm:falso"}
	reglas := &generadorFalso{nombre: NombreReglas}
	ahora := time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)
	p := &Politica{
		Gen: llm, Reglas: reglas, Alm: nuevoAlmacen(), TopeDiario: tope,
		Ahora: func() time.Time { return ahora },
	}
	return p, llm, reglas, &ahora
}

// Lo que motiva el reparto: el panel refresca cada 20 s y eso no puede
// costar dinero.
func TestElRefrescoDelPanelNoGastaNiUnaLlamada(t *testing.T) {
	p, llm, reglas, _ := montar(50)
	for i := 0; i < 200; i++ {
		if _, err := p.Automatico(context.Background(), datosCon(i), 7); err != nil {
			t.Fatal(err)
		}
	}
	if llm.veces != 0 {
		t.Errorf("el automatico llamo al modelo %d veces", llm.veces)
	}
	if reglas.veces == 0 {
		t.Error("las reglas deberian haber redactado")
	}
}

func TestSoloSeGastaCuandoSePide(t *testing.T) {
	p, llm, _, _ := montar(50)
	if _, err := p.AMano(context.Background(), datosCon(3), 7); err != nil {
		t.Fatal(err)
	}
	if llm.veces != 1 {
		t.Fatalf("llamadas = %d, se esperaba 1", llm.veces)
	}
}

// Un informe con IA ya pagado se sigue sirviendo: es mejor que el de
// reglas y no cuesta nada volver a ensenarlo.
func TestElInformeConIASeConservaYSeReutiliza(t *testing.T) {
	p, llm, _, _ := montar(50)
	d := datosCon(3)
	if _, err := p.AMano(context.Background(), d, 7); err != nil {
		t.Fatal(err)
	}
	s, err := p.Automatico(context.Background(), d, 7)
	if err != nil {
		t.Fatal(err)
	}
	if !s.ConIA || s.Texto != "texto del modelo" {
		t.Errorf("deberia servirse el guardado: %+v", s)
	}
	if s.Desactualizado {
		t.Error("los datos no han cambiado: no deberia constar como desfasado")
	}
	if llm.veces != 1 {
		t.Errorf("se volvio a pagar: %d llamadas", llm.veces)
	}
}

// Si llega actividad nueva se avisa, pero NO se regenera solo: quien lo
// pidio decide si vuelve a gastar.
func TestConDatosNuevosAvisaPeroNoRegeneraSolo(t *testing.T) {
	p, llm, _, _ := montar(50)
	if _, err := p.AMano(context.Background(), datosCon(3), 7); err != nil {
		t.Fatal(err)
	}
	s, err := p.Automatico(context.Background(), datosCon(99), 7)
	if err != nil {
		t.Fatal(err)
	}
	if !s.Desactualizado {
		t.Error("deberia avisar de que hay actividad nueva")
	}
	if llm.veces != 1 {
		t.Errorf("no debia regenerar solo: %d llamadas", llm.veces)
	}
}

// El tope acota lo que se puede pedir a mano, por si alguien se apoya en
// el boton.
func TestElTopeDiarioAcotaLasPeticionesAMano(t *testing.T) {
	p, llm, _, _ := montar(3)
	var ultimo Servido
	for i := 0; i < 20; i++ {
		s, err := p.AMano(context.Background(), datosCon(i), 7)
		if err != nil {
			t.Fatal(err)
		}
		ultimo = s
	}
	if llm.veces != 3 {
		t.Fatalf("se rebaso el tope: %d llamadas", llm.veces)
	}
	// Rebasado el tope se sigue devolviendo un informe -el ultimo pagado,
	// que es mejor que degradar a reglas- pero diciendo por que no es nuevo.
	if ultimo.Texto == "" {
		t.Error("el panel no puede quedarse sin informe")
	}
	if !strings.Contains(ultimo.Motivo, "tope") {
		t.Errorf("hay que explicar por que no se redacto: %q", ultimo.Motivo)
	}
}

// Y si no hay ninguno pagado que reutilizar, responden las reglas.
func TestSinTopeYSinInformePrevioRespondenLasReglas(t *testing.T) {
	p, llm, reglas, _ := montar(0)
	p.TopeDiario = -1 // agotado desde el principio
	p.Alm = &almacenFalso{cuota: map[string]int{"2026-07-23": 99}}
	p.TopeDiario = 1

	if _, err := p.AMano(context.Background(), datosCon(3), 7); err != nil {
		t.Fatal(err)
	}
	if llm.veces != 0 {
		t.Errorf("no deberia haber llamado al modelo: %d", llm.veces)
	}
	if reglas.veces == 0 {
		t.Error("sin nada guardado deberian responder las reglas")
	}
}

func TestElTopeSeRenuevaCadaDia(t *testing.T) {
	p, llm, _, reloj := montar(2)
	for i := 0; i < 5; i++ {
		p.AMano(context.Background(), datosCon(i), 7)
	}
	*reloj = reloj.Add(24 * time.Hour)
	if _, err := p.AMano(context.Background(), datosCon(9), 7); err != nil {
		t.Fatal(err)
	}
	if llm.veces != 3 {
		t.Errorf("el dia nuevo deberia traer cuota limpia: %d", llm.veces)
	}
}

// Si la API falla, el panel no puede quedarse sin informe.
func TestSiFallaLaIACaeEnReglasYLoExplica(t *testing.T) {
	p, llm, _, _ := montar(50)
	llm.fallo = errors.New("HTTP 429: rate limit")

	s, err := p.AMano(context.Background(), datosCon(3), 7)
	if err != nil {
		t.Fatalf("no deberia propagar: %v", err)
	}
	if s.ConIA {
		t.Error("no lo redacto la IA")
	}
	if !strings.Contains(s.Motivo, "429") {
		t.Errorf("el motivo deberia citar el fallo: %q", s.Motivo)
	}
}

// Sin modelo configurado, pedirlo a mano no puede romper nada.
func TestSinModeloConfiguradoDevuelveElDeReglas(t *testing.T) {
	reglas := &generadorFalso{nombre: NombreReglas}
	p := &Politica{Gen: reglas, Reglas: reglas, Alm: nuevoAlmacen(), TopeDiario: 40}

	s, err := p.AMano(context.Background(), datosCon(3), 7)
	if err != nil {
		t.Fatal(err)
	}
	if s.ConIA {
		t.Error("sin modelo no puede constar como redactado con IA")
	}
}

func TestOtroPeriodoNoReutilizaElInformeGuardado(t *testing.T) {
	p, _, _, _ := montar(50)
	d := datosCon(3)
	if _, err := p.AMano(context.Background(), d, 7); err != nil {
		t.Fatal(err)
	}
	s, err := p.Automatico(context.Background(), d, 30)
	if err != nil {
		t.Fatal(err)
	}
	if s.ConIA {
		t.Error("un informe de 7 dias no vale para una consulta de 30")
	}
}

func TestHuellaIgnoraElInstanteDeConsulta(t *testing.T) {
	d1, d2 := datosCon(5), datosCon(5)
	d1.Hasta = time.Now()
	d2.Hasta = time.Now().Add(time.Minute)
	if Huella(d1) != Huella(d2) {
		t.Error("la huella cambia solo por consultar en otro momento")
	}
}

func TestHuellaCambiaConLosDatos(t *testing.T) {
	if Huella(datosCon(5)) == Huella(datosCon(6)) {
		t.Error("datos distintos deberian dar huellas distintas")
	}
}

// Cuando el modelo falla, ConLLM se repliega y firma "reglas (el LLM no
// estaba disponible: ...)" para no atribuir el texto a quien no lo
// escribio. Comparar esa firma con == daba por redactado con IA justo lo
// que la IA no habia podido redactar, y el panel lo anunciaba como tal.
func TestUnRepliegueAReglasNoCuentaComoIA(t *testing.T) {
	llm := &generadorFalso{nombre: "reglas (el LLM no estaba disponible: HTTP 429)"}
	p := &Politica{
		Gen: &generadorFalso{nombre: "llm:falso"}, Reglas: llm,
		Alm: nuevoAlmacen(), TopeDiario: 40,
	}
	// El generador configurado devuelve la firma de repliegue.
	p.Gen = llm

	s, err := p.AMano(context.Background(), datosCon(3), 7)
	if err != nil {
		t.Fatal(err)
	}
	if s.ConIA {
		t.Errorf("firma %q se tomo por IA", s.Generador)
	}

	// Y no se guarda: si se guardara, el refresco siguiente lo serviria
	// como un informe con IA ya pagado que nunca existio.
	sig, err := p.Automatico(context.Background(), datosCon(3), 7)
	if err != nil {
		t.Fatal(err)
	}
	if sig.ConIA {
		t.Error("un repliegue guardado se sirve luego como si fuera IA")
	}
}

// La cuota se apunta antes de llamar, para que dos peticiones simultaneas
// no rebasen el tope. Si el proveedor falla no ha consumido nada suyo, asi
// que descontarla igual gastaria el presupuesto del usuario en las averias
// del proveedor.
func TestUnaLlamadaFallidaNoGastaCuota(t *testing.T) {
	p, llm, _, _ := montar(40)
	llm.fallo = errors.New("HTTP 429: rate limit")

	if _, err := p.AMano(context.Background(), datosCon(3), 7); err != nil {
		t.Fatal(err)
	}
	usada, _ := p.Alm.CuotaLLMUsada("2026-07-23")
	if usada != 0 {
		t.Errorf("se gasto %d de cuota en una llamada que fallo", usada)
	}
}

func TestUnaLlamadaBuenaSiGastaCuota(t *testing.T) {
	p, _, _, _ := montar(40)
	if _, err := p.AMano(context.Background(), datosCon(3), 7); err != nil {
		t.Fatal(err)
	}
	usada, _ := p.Alm.CuotaLLMUsada("2026-07-23")
	if usada != 1 {
		t.Errorf("cuota usada = %d, se esperaba 1", usada)
	}
}
