#!/usr/bin/env python3
"""Convierte el GeoJSON de Natural Earth en el mapa compacto que usa el panel.

Natural Earth es de dominio publico (naturalearthdata.com/about/terms-of-use).
Se ejecuta a mano cuando haya que regenerar el mapa; su salida se versiona,
asi que el binario no depende de nada externo en tiempo de ejecucion.

    python3 tools/genmapa.py ne_110m_admin_0_countries.geojson \\
        internal/web/static/mundo.json
"""
import json
import sys

ANCHO, ALTO = 1000.0, 500.0
# Grados por debajo de los cuales una isla no aporta nada a escala mundial.
AREA_MINIMA = 0.6
DECIMALES = 1


def proyectar(lon, lat):
    """Equirectangular: simple, sin distorsion de area en latitudes medias."""
    x = (lon + 180.0) / 360.0 * ANCHO
    y = (90.0 - lat) / 180.0 * ALTO
    return round(x, DECIMALES), round(y, DECIMALES)


def area_aprox(anillo):
    """Area por la formula del cordon de zapato, en grados cuadrados."""
    s = 0.0
    for i in range(len(anillo) - 1):
        x1, y1 = anillo[i][0], anillo[i][1]
        x2, y2 = anillo[i + 1][0], anillo[i + 1][1]
        s += x1 * y2 - x2 * y1
    return abs(s) / 2.0


def anillo_a_path(anillo):
    puntos = []
    previo = None
    for lon, lat in anillo:
        p = proyectar(lon, lat)
        if p != previo:  # descartar puntos repetidos tras redondear
            puntos.append(p)
            previo = p
    if len(puntos) < 3:
        return ""
    d = f"M{puntos[0][0]} {puntos[0][1]}"
    for x, y in puntos[1:]:
        d += f"L{x} {y}"
    return d + "Z"


def poligonos(geom):
    if geom["type"] == "Polygon":
        return [geom["coordinates"]]
    if geom["type"] == "MultiPolygon":
        return geom["coordinates"]
    return []


def main():
    entrada, salida = sys.argv[1], sys.argv[2]
    with open(entrada) as f:
        gj = json.load(f)

    paises = {}
    for feature in gj["features"]:
        props = feature["properties"]
        iso = props.get("ISO_A2_EH") or props.get("ISO_A2") or ""
        if not iso or iso == "-99":
            continue
        nombre = props.get("NAME") or iso

        partes, mayor, area_mayor = [], None, 0.0
        for poly in poligonos(feature["geometry"]):
            exterior = poly[0]  # los anillos interiores (lagos) no se pintan
            a = area_aprox(exterior)
            if a < AREA_MINIMA:
                continue
            d = anillo_a_path(exterior)
            if d:
                partes.append(d)
            if a > area_mayor:
                area_mayor, mayor = a, exterior

        if not partes:
            continue

        # Punto representativo: centro del poligono mas grande, que para
        # pintar un circulito va mejor que el centroide de todo el pais.
        xs = [p[0] for p in mayor]
        ys = [p[1] for p in mayor]
        cx, cy = proyectar((min(xs) + max(xs)) / 2, (min(ys) + max(ys)) / 2)

        paises[iso] = {"n": nombre, "d": " ".join(partes), "c": [cx, cy]}

    with open(salida, "w") as f:
        json.dump({"ancho": ANCHO, "alto": ALTO, "paises": paises},
                  f, separators=(",", ":"))
    print(f"{len(paises)} paises escritos en {salida}")


if __name__ == "__main__":
    main()
