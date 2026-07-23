package report

import (
	"context"
	"fmt"
	"strings"
)

// PorReglas redacta el informe con plantillas. Es instantaneo, gratuito y
// funciona sin conexion, asi que es tanto el generador del dia a dia como
// la red de seguridad cuando el LLM no esta disponible.
type PorReglas struct{}

func (PorReglas) Nombre() string { return "reglas" }

func (PorReglas) Generar(_ context.Context, d Datos) (Resultado, error) {
	var b strings.Builder

	fmt.Fprintf(&b, "%s\n\n", FraseSemaforo(d.Niveles))

	if d.SinActividad() {
		b.WriteString("Sin actividad registrada en el periodo.\n")
		return Resultado{Texto: b.String(), Redactado: "reglas"}, nil
	}

	r := d.Resumen
	fmt.Fprintf(&b, "Entre el %s y el %s se registraron %d eventos desde %d IPs distintas.\n",
		d.Desde.Local().Format("2/1"), d.Hasta.Local().Format("2/1"),
		r.Total, r.IPsUnicas)

	if ruido := d.Niveles["ruido_fondo"]; ruido > 0 && r.Total > 0 {
		porcentaje := ruido * 100 / r.Total
		fmt.Fprintf(&b, "El %d%% es ruido de fondo: bots automatizados probando "+
			"contrasenas por defecto, el trafico normal de estar en internet.\n",
			porcentaje)
	}

	if len(r.PorPais) > 0 {
		var paises []string
		for i, p := range r.PorPais {
			if i == 3 {
				break
			}
			paises = append(paises, fmt.Sprintf("%s (%d)", p.Valor, p.N))
		}
		fmt.Fprintf(&b, "Origen principal: %s.\n", strings.Join(paises, ", "))
	}

	if len(r.TopUsuarios) > 0 {
		var usuarios []string
		for i, u := range r.TopUsuarios {
			if i == 5 {
				break
			}
			usuarios = append(usuarios, u.Valor)
		}
		fmt.Fprintf(&b, "Usuarios mas probados: %s.\n", strings.Join(usuarios, ", "))
	}

	// Los ataques van antes que los eventos sueltos: es la lectura que
	// alguien quiere, aunque sin LLM salga en tono telegrafico.
	if len(d.Episodios) > 0 {
		b.WriteString("\n")
		for i, e := range d.Episodios {
			if i == 5 {
				fmt.Fprintf(&b, "  (y %d ataques mas)\n", len(d.Episodios)-5)
				break
			}
			fmt.Fprintf(&b, "  [%s] %s contra %s: %s\n",
				e.Severidad, e.IP, e.Protocolo, e.Resumen)
		}
	}

	if len(d.Episodios) > 0 {
		// Ya se han listado los ataques arriba, que cuentan lo mismo pero
		// agrupado: repetirlos evento a evento solo alarga el informe.
		return Resultado{Texto: b.String(), Redactado: "reglas"}, nil
	}
	if len(d.Destacados) == 0 {
		b.WriteString("\nNo hubo ningun evento fuera de lo habitual.\n")
		return Resultado{Texto: b.String(), Redactado: "reglas"}, nil
	}

	b.WriteString("\nLo que merece una mirada:\n")
	for i, dest := range d.Destacados {
		if i == 5 {
			fmt.Fprintf(&b, "  (y %d mas)\n", len(d.Destacados)-5)
			break
		}
		origen := dest.IP
		if dest.Pais != "" {
			origen += " (" + dest.Pais + ")"
		}
		fmt.Fprintf(&b, "  - %s desde %s: %s\n",
			dest.Timestamp.Local().Format("2/1 15:04"), origen, dest.Motivo)
	}
	return Resultado{Texto: b.String(), Redactado: "reglas"}, nil
}
