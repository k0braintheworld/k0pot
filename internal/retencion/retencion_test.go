package retencion

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

type almacenFalso struct {
	corteEventos, corteEpisodios time.Time
	eventos, episodios           int64
}

func (a *almacenFalso) PurgarEventos(t time.Time) (int64, error) {
	a.corteEventos = t
	return a.eventos, nil
}
func (a *almacenFalso) PurgarEpisodios(t time.Time) (int64, error) {
	a.corteEpisodios = t
	return a.episodios, nil
}

var ahora = time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC)

// Lo importante del paquete: los dos plazos son independientes. Tirar los
// episodios con el mismo plazo que los eventos pierde la memoria larga
// para ahorrar lo que no ocupaba.
func TestLosDosPlazosSonIndependientes(t *testing.T) {
	a := &almacenFalso{eventos: 10, episodios: 2}
	if _, err := Aplicar(a, Politica{EventosDias: 30, EpisodiosDias: 365}, ahora); err != nil {
		t.Fatal(err)
	}
	if d := ahora.Sub(a.corteEventos).Hours() / 24; d < 29 || d > 31 {
		t.Errorf("corte de eventos a %.0f dias, se esperaban 30", d)
	}
	if d := ahora.Sub(a.corteEpisodios).Hours() / 24; d < 364 || d > 366 {
		t.Errorf("corte de episodios a %.0f dias, se esperaban 365", d)
	}
}

// 0 significa conservar siempre, y tiene que poder ponerse en uno solo.
func TestCeroConservaSiempre(t *testing.T) {
	a := &almacenFalso{}
	if _, err := Aplicar(a, Politica{EventosDias: 0, EpisodiosDias: 90}, ahora); err != nil {
		t.Fatal(err)
	}
	if !a.corteEventos.IsZero() {
		t.Error("con 0 no deberia haberse purgado ningun evento")
	}
	if a.corteEpisodios.IsZero() {
		t.Error("los episodios si tenian plazo")
	}
}

// Lo que de verdad ocupa son las grabaciones y los binarios capturados: un
// evento son cientos de bytes, una grabacion puede ser megas.
func TestSeBorranLasGrabacionesYDescargasCaducadas(t *testing.T) {
	dir := t.TempDir()
	viejo := ahora.AddDate(0, 0, -60)

	for _, sub := range []string{"tty", "downloads"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
		antiguo := filepath.Join(dir, sub, "antiguo")
		reciente := filepath.Join(dir, sub, "reciente")
		os.WriteFile(antiguo, make([]byte, 1024), 0o644)
		os.WriteFile(reciente, make([]byte, 512), 0o644)
		os.Chtimes(antiguo, viejo, viejo)
	}

	r, err := Aplicar(&almacenFalso{}, Politica{EventosDias: 30, DirCowrie: dir}, ahora)
	if err != nil {
		t.Fatal(err)
	}
	if r.Ficheros != 2 {
		t.Errorf("borro %d ficheros, se esperaban 2", r.Ficheros)
	}
	if r.BytesLibre != 2048 {
		t.Errorf("libero %d bytes, se esperaban 2048", r.BytesLibre)
	}
	for _, sub := range []string{"tty", "downloads"} {
		if _, err := os.Stat(filepath.Join(dir, sub, "reciente")); err != nil {
			t.Errorf("se borro un fichero que no habia caducado en %s", sub)
		}
	}
}

// Sin plazo de eventos tampoco se tocan los ficheros: son el detalle de
// esas mismas sesiones y no se pueden interpretar sin ellas.
func TestSinPlazoDeEventosNoSeBorranFicheros(t *testing.T) {
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "tty"), 0o755)
	f := filepath.Join(dir, "tty", "grabacion")
	os.WriteFile(f, []byte("x"), 0o644)
	viejo := ahora.AddDate(-1, 0, 0)
	os.Chtimes(f, viejo, viejo)

	r, err := Aplicar(&almacenFalso{}, Politica{EpisodiosDias: 30, DirCowrie: dir}, ahora)
	if err != nil {
		t.Fatal(err)
	}
	if r.Ficheros != 0 {
		t.Error("no habia plazo de eventos: no deberia borrar grabaciones")
	}
}

func TestQueNoExistaElDirectorioNoEsUnFallo(t *testing.T) {
	if _, err := Aplicar(&almacenFalso{},
		Politica{EventosDias: 30, DirCowrie: "/no/existe/en/ningun/sitio"}, ahora); err != nil {
		t.Errorf("deberia ignorarse: %v", err)
	}
}

// El -wal cuenta: puede ser mayor que la propia base y es espacio real,
// aunque no lo parezca mirando solo el fichero principal.
func TestMedirCuentaElWAL(t *testing.T) {
	dir := t.TempDir()
	bd := filepath.Join(dir, "k0pot.db")
	os.WriteFile(bd, make([]byte, 1000), 0o644)
	os.WriteFile(bd+"-wal", make([]byte, 5000), 0o644)

	u := Medir(bd, "")
	if u.BaseDatos != 6000 {
		t.Errorf("base de datos = %d, se esperaban 6000", u.BaseDatos)
	}
	if u.Legible["total"] == "" {
		t.Error("falta el tamano ya escrito")
	}
}

func TestEnBytesSeLee(t *testing.T) {
	casos := map[int64]string{500: "500 B", 2048: "2 KB", 5 * 1024 * 1024: "5.0 MB"}
	for b, quiero := range casos {
		if s := EnBytes(b); s != quiero {
			t.Errorf("EnBytes(%d) = %q, se esperaba %q", b, s, quiero)
		}
	}
}
