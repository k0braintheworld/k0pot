// Panel de k0Pot.
//
// REGLA INNEGOCIABLE: los datos vienen de atacantes. Todo lo remoto entra al
// DOM por textContent o createTextNode. Nada de las APIs prohibidas que
// comprueba el test de web_test.go, ni plantillas de cadena volcadas al DOM.
// Los unicos setAttribute con datos son sobre geometria SVG procedente de
// nuestro propio mundo.json, que no es contenido remoto.
"use strict";

const SVG = "http://www.w3.org/2000/svg";
const $ = (id) => document.getElementById(id);
const rango = () => $("rango").value;

async function traer(ruta) {
  const resp = await fetch(`${ruta}?dias=${encodeURIComponent(rango())}`);
  if (!resp.ok) throw new Error(`${ruta} respondio ${resp.status}`);
  return resp.json();
}

function nodo(etiqueta, clase, texto) {
  const el = document.createElement(etiqueta);
  if (clase) el.className = clase;
  if (texto !== undefined) el.textContent = texto;
  return el;
}

function svg(etiqueta, atributos) {
  const el = document.createElementNS(SVG, etiqueta);
  for (const [k, v] of Object.entries(atributos || {})) el.setAttribute(k, v);
  return el;
}

// ─── Mapa ──────────────────────────────────────────────────────────────

let mundo = null;

async function cargarMundo() {
  if (mundo) return mundo;
  const resp = await fetch("mundo.json");
  if (!resp.ok) throw new Error("no se pudo cargar el mapa");
  mundo = await resp.json();
  return mundo;
}

// arco traza la curva de un ataque desde su origen hasta el honeypot.
//
// Es una bezier cuadratica cuyo punto de control se desplaza perpendicular
// a la recta: cuanto mas lejos esta el origen, mas se levanta el arco, que
// es lo que hace legible un mapa con muchas lineas cruzandose.
function arco(desde, hasta) {
  const [x1, y1] = desde;
  const [x2, y2] = hasta;
  const dx = x2 - x1;
  const dy = y2 - y1;
  const distancia = Math.hypot(dx, dy);

  // Perpendicular normalizada, hacia arriba del lienzo.
  const cx = (x1 + x2) / 2 + (-dy / (distancia || 1)) * distancia * 0.22;
  const cy = (y1 + y2) / 2 + (dx / (distancia || 1)) * distancia * 0.22;
  return `M${x1} ${y1} Q${cx.toFixed(1)} ${cy.toFixed(1)} ${x2} ${y2}`;
}

// pintarAtaques dibuja una linea por cada evento reciente que tenga pais.
//
// Se redibuja en cada refresco: la animacion CSS se reproduce entonces de
// nuevo y el mapa "late" con la actividad, que es el efecto buscado.
// aLienzo convierte latitud y longitud a coordenadas del SVG.
//
// El mapa es equirectangular -la misma proyeccion que usa tools/genmapa.py
// al generarlo-, asi que la conversion es directa. Si las dos formulas
// dejaran de coincidir, la marca apareceria desplazada respecto al dibujo.
function aLienzo(lat, lon, m) {
  return [((lon + 180) / 360) * m.ancho, ((90 - lat) / 180) * m.alto];
}

// delLienzo hace el camino inverso, para poder elegir el sitio pinchando.
function delLienzo(x, y, m) {
  return [90 - (y / m.alto) * 180, (x / m.ancho) * 360 - 180];
}

function pintarAtaques(lienzo, m, recientes, paisPropio, propio) {
  // Las coordenadas mandan sobre el pais: el centroide de un pais grande
  // deja la marca a cientos de kilometros de donde esta la maquina.
  const destino = (propio && (propio.lat || propio.lon))
    ? aLienzo(propio.lat, propio.lon, m)
    : m.paises[paisPropio]?.c;
  if (!destino) return 0;

  const capa = svg("g", { class: "ataques" });
  let dibujados = 0;

  for (const ev of recientes) {
    const origen = m.paises[ev.pais]?.c;
    if (!origen || ev.pais === paisPropio) continue;
    if (dibujados >= 18) break; // mas lineas solo ensucian

    const linea = svg("path", {
      d: arco(origen, destino),
      class: `ataque ${ev.clasificacion === "notable" ? "notable" : ev.clasificacion === "revisar" ? "revisar" : ""}`,
    });
    // El retardo va por CSSOM: la CSP bloquea los atributos style en linea.
    linea.style.animationDelay = `${(dibujados * 0.14).toFixed(2)}s`;
    capa.appendChild(linea);
    dibujados++;
  }

  if (dibujados > 0) lienzo.appendChild(capa);

  // Marca del propio honeypot, para que se vea a donde apuntan.
  const casa = svg("g", { class: "marca-propia" });
  casa.appendChild(svg("circle", { cx: destino[0], cy: destino[1], r: 9, class: "diana" }));
  casa.appendChild(svg("circle", { cx: destino[0], cy: destino[1], r: 3.5, class: "centro" }));
  const t = svg("title");
  t.textContent = (propio && (propio.lat || propio.lon))
    ? `Aqui esta el honeypot (${propio.lat.toFixed(2)}, ${propio.lon.toFixed(2)})`
    : `Aqui esta el honeypot (${m.paises[paisPropio]?.n || paisPropio})`;
  casa.appendChild(t);
  lienzo.appendChild(casa);

  return dibujados;
}

async function pintarMapa(porPais, recientes, paisPropio, propio) {
  const m = await cargarMundo();
  const cont = $("mapa");
  cont.replaceChildren();

  const total = porPais.reduce((s, p) => s + p.N, 0);
  const porIso = new Map(porPais.map((p) => [p.Valor, p.N]));
  const maximo = Math.max(1, ...porPais.map((p) => p.N));

  const lienzo = svg("svg", {
    viewBox: `0 0 ${m.ancho} ${m.alto}`,
    class: "lienzo-mapa",
    role: "img",
    "aria-label": "Mapa de origen de los ataques",
  });

  // Paises: los que atacan se tinen segun su peso relativo.
  for (const [iso, pais] of Object.entries(m.paises)) {
    const n = porIso.get(iso) || 0;
    const forma = svg("path", { d: pais.d, class: n > 0 ? "pais activo" : "pais" });
    if (n > 0) {
      // Raiz cuadrada para que los paises con poca actividad sigan
      // distinguiendose del fondo en vez de quedarse casi invisibles.
      const peso = Math.sqrt(n / maximo);
      forma.setAttribute("fill-opacity", (0.22 + peso * 0.65).toFixed(3));
    }
    const titulo = svg("title");
    titulo.textContent = n > 0 ? `${pais.n}: ${n} eventos` : pais.n;
    forma.appendChild(titulo);
    lienzo.appendChild(forma);
  }

  // Circulos proporcionales encima, para que un pais pequeno con mucha
  // actividad no pase desapercibido.
  for (const [iso, n] of porIso) {
    const pais = m.paises[iso];
    if (!pais) continue;
    const r = 3 + Math.sqrt(n / maximo) * 17;
    const g = svg("g", { class: "marca-pais" });
    g.appendChild(svg("circle", { cx: pais.c[0], cy: pais.c[1], r: r, class: "halo" }));
    g.appendChild(svg("circle", { cx: pais.c[0], cy: pais.c[1], r: Math.max(2, r * 0.35), class: "nucleo" }));
    const titulo = svg("title");
    titulo.textContent = `${pais.n}: ${n} eventos`;
    g.appendChild(titulo);
    lienzo.appendChild(g);
  }

  const lineas = pintarAtaques(lienzo, m, recientes || [], paisPropio || "ES", propio);
  cont.appendChild(lienzo);

  $("leyenda-mapa").textContent = total === 0
    ? "sin origen geolocalizado todavia"
    : `${porIso.size} pais(es) · ${total} eventos` +
      (lineas > 0 ? ` · ${lineas} ataques recientes` : "");

  if (total === 0) {
    cont.appendChild(nodo("p", "aviso-mapa",
      "Ningun evento tiene pais aun: las IPs privadas no se geolocalizan."));
  }
}

// ─── Grafica temporal ──────────────────────────────────────────────────

function pintarSerie(datos) {
  const cont = $("serie");
  cont.replaceChildren();

  const puntos = datos.puntos || [];
  if (!puntos.length) {
    cont.appendChild(nodo("p", "cargando", "Sin actividad en este periodo."));
    $("leyenda-serie").textContent = "";
    return;
  }

  const maximo = Math.max(...puntos.map((p) => p.total));
  const barras = nodo("div", "barras");

  for (const p of puntos) {
    const col = nodo("div", "columna");
    const pila = nodo("div", "pila");

    // Se apila de mas grave a menos, para que lo notable quede arriba.
    for (const [clase, valor] of [["b-notable", p.notable], ["b-revisar", p.revisar], ["b-ruido", p.ruido]]) {
      if (valor > 0) {
        const seg = nodo("div", `segmento ${clase}`);
        // Por CSSOM, no con setAttribute("style", ...): la CSP lleva
        // style-src 'self', que bloquea los atributos style en linea. El
        // atributo aparecia en el DOM pero el navegador no lo aplicaba, y
        // las barras se quedaban en su min-height de 2px.
        seg.style.height = `${((valor / maximo) * 100).toFixed(2)}%`;
        pila.appendChild(seg);
      }
    }

    const cuando = new Date(p.momento);
    col.title = `${cuando.toLocaleString("es")}\n${p.total} eventos ` +
      `(${p.ruido} ruido, ${p.revisar} revisar, ${p.notable} notables)`;
    col.appendChild(pila);
    barras.appendChild(col);
  }

  cont.appendChild(barras);

  const primero = new Date(puntos[0].momento);
  const ultimo = new Date(puntos[puntos.length - 1].momento);
  const ejes = nodo("div", "ejes");
  ejes.appendChild(nodo("span", null, primero.toLocaleDateString("es")));
  ejes.appendChild(nodo("span", null, `maximo ${maximo}`));
  ejes.appendChild(nodo("span", null, ultimo.toLocaleDateString("es")));
  cont.appendChild(ejes);

  $("leyenda-serie").textContent =
    `por ${datos.granularidad === "hora" ? "horas" : "dias"} · ${puntos.length} intervalos`;
}

// ─── Feed en vivo ──────────────────────────────────────────────────────

const RESUMEN_EVENTO = {
  conexion: (d) => "abrio una conexion",
  huella_cliente: (d) => `cliente: ${d?.cliente || "desconocido"}`,
  login_fallido: (d) => `probo ${d?.usuario || "?"} / ${d?.password || "?"}`,
  login_exitoso: (d) => `entro como ${d?.usuario || "?"}`,
  comando_ejecutado: (d) => `ejecuto: ${d?.comando || "?"}`,
  descarga_fichero: (d) => `descargo ${d?.url || "un fichero"}`,
  peticion_http: (d) => `pidio ${d?.ruta || "/"}`,
};

function pintarVivo(lista) {
  const cont = $("vivo");
  cont.replaceChildren();

  if (!lista.length) {
    cont.appendChild(nodo("p", "cargando", "Sin actividad todavia."));
    return;
  }

  for (const ev of lista) {
    const fila = nodo("div", `linea-viva ${ev.clasificacion}`);
    fila.appendChild(nodo("span", "hora", new Date(ev.timestamp).toLocaleTimeString("es")));
    fila.appendChild(nodo("span", "ip", ev.ip + (ev.pais ? ` ${ev.pais}` : "")));
    const resumen = RESUMEN_EVENTO[ev.tipo];
    fila.appendChild(nodo("span", "que", resumen ? resumen(ev.detalle) : ev.tipo));
    cont.appendChild(fila);
  }
}

// ─── Tablas y resto ────────────────────────────────────────────────────

function pintarTabla(id, filas) {
  const cuerpo = $(id).querySelector("tbody");
  cuerpo.replaceChildren();
  if (!filas || !filas.length) {
    const tr = nodo("tr");
    tr.appendChild(nodo("td", "vacio", "sin datos"));
    cuerpo.appendChild(tr);
    return;
  }
  for (const fila of filas.slice(0, 10)) {
    const tr = nodo("tr");
    for (const c of fila) {
      tr.appendChild(nodo("td", c.clase, c.valor === "" || c.valor == null ? "—" : String(c.valor)));
    }
    cuerpo.appendChild(tr);
  }
}

function contextoIP(ip) {
  const partes = [];
  if (ip.isp) partes.push(ip.isp);
  if (ip.tor) partes.push("TOR");
  if (ip.reputacion > 0) partes.push(`${ip.reputacion}/100`);
  return partes.length ? partes.join(" · ") : "sin datos publicos";
}

function nombrePais(iso) {
  return mundo?.paises?.[iso]?.n || iso;
}

async function cargarEstado(recientes) {
  const e = await traer("/api/estado");

  $("semaforo").className = `semaforo ${e.nivel.toLowerCase()}`;
  $("frase").textContent = e.frase;

  const ruido = e.niveles?.ruido_fondo ?? 0;
  $("m-total").textContent = e.total.toLocaleString("es");
  $("m-ips").textContent = e.ips_unicas.toLocaleString("es");
  $("m-paises").textContent = (e.por_pais || []).length;
  $("m-ruido").textContent = e.total > 0 ? Math.round((ruido / e.total) * 100) : 0;
  $("m-revisar").textContent = e.niveles?.revisar ?? 0;
  $("m-notable").textContent = e.niveles?.notable ?? 0;

  await pintarMapa(e.por_pais || [], recientes, e.pais_propio,
    { lat: e.latitud_propia || 0, lon: e.longitud_propia || 0 });

  pintarTabla("tabla-ips", (e.top_ips || []).map((ip) => [
    { valor: ip.ip }, { valor: ip.eventos, clase: "num" }, { valor: contextoIP(ip), clase: "sub" },
  ]));
  pintarTabla("tabla-paises", (e.por_pais || []).map((p) => [
    { valor: nombrePais(p.Valor) }, { valor: p.N, clase: "num" },
  ]));
  pintarTabla("tabla-usuarios", (e.top_usuarios || []).map((u) => [
    { valor: u.Valor }, { valor: u.N, clase: "num" },
  ]));
  pintarTabla("tabla-passwords", (e.top_passwords || []).map((p) => [
    { valor: p.Valor }, { valor: p.N, clase: "num" },
  ]));
}


// hace convierte un instante en algo legible de un vistazo. Un informe
// fechado sin mas obliga a restar mentalmente para saber si esta al dia.
function hace(iso) {
  const seg = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seg < 90) return "hace un momento";
  const min = Math.round(seg / 60);
  if (min < 60) return `hace ${min} min`;
  const h = Math.round(min / 60);
  if (h < 24) return `hace ${h} h`;
  return `hace ${Math.round(h / 24)} d`;
}

function pintarInforme(inf) {
  const cont = $("informe");
  cont.replaceChildren();
  for (const parrafo of inf.texto.split("\n").filter((l) => l.trim())) {
    cont.appendChild(nodo("p", null, parrafo));
  }
  $("generador").textContent = inf.generador;

  // Se dice quien lo redacto y si los datos han cambiado desde entonces.
  // Un informe con IA fechado hace horas, sin mas, parece un panel colgado;
  // decir que hay actividad nueva convierte eso en una invitacion a pulsar.
  const partes = [];
  partes.push(inf.con_ia ? "redactado con IA" : "resumen automatico");
  if (inf.con_ia && inf.momento) partes.push(hace(inf.momento));
  if (inf.desactualizado) partes.push("hay actividad nueva desde entonces");
  else if (inf.motivo && !inf.con_ia) partes.push(inf.motivo);
  else if (inf.motivo && inf.motivo !== "redactado con IA") partes.push(inf.motivo);
  if (inf.cuota_tope > 0) {
    partes.push(`${inf.cuota_usada}/${inf.cuota_tope} con IA hoy`);
  }
  $("informe-estado").textContent = partes.join(" · ");
}

// ── Ataques ─────────────────────────────────────────────────────────────

const NOMBRE_SEV = {
  roce: "roce",
  tanteo: "tanteo",
  acceso: "acceso",
  intrusion: "intrusion",
};

function horaCorta(iso) {
  const d = new Date(iso);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

// Los destacados desaparecieron del panel: contaban lo mismo que los
// ataques pero evento a evento, y tener las dos listas era la mitad del
// desorden. El endpoint sigue existiendo por si vuelve a hacer falta.
// filtrosDeAtaques recoge lo que hay puesto en la barra.
function filtrosDeAtaques() {
  return {
    q: $("f-texto").value.trim(),
    severidad: $("f-severidad").value,
    protocolo: $("f-protocolo").value,
  };
}

function hayFiltro() {
  const f = filtrosDeAtaques();
  return Boolean(f.q || f.severidad || f.protocolo);
}

async function cargarAtaques() {
  const f = filtrosDeAtaques();
  const params = new URLSearchParams({ dias: rango() });
  for (const [k, v] of Object.entries(f)) if (v) params.set(k, v);

  const resp = await fetch(`/api/episodios?${params}`);
  if (!resp.ok) throw new Error(`/api/episodios respondio ${resp.status}`);
  const lista = await resp.json();

  const cont = $("ataques");
  cont.replaceChildren();
  $("f-limpiar").hidden = !hayFiltro();

  if (!lista.length) {
    cont.appendChild(nodo("p", "vacio", hayFiltro()
      ? "Ningun ataque casa con el filtro."
      : "Todavia no se ha registrado ningun ataque."));
    return;
  }

  // Con filtro puesto hay que decirlo: una lista corta sin explicacion se
  // lee como "no ha pasado nada", que es justo lo contrario.
  if (hayFiltro()) {
    cont.appendChild(nodo("p", "aviso-filtrado",
      `${lista.length} ataque${lista.length > 1 ? "s" : ""} con el filtro puesto`));
  }

  for (const a of lista) {
    // Un boton y no un div: se navega con teclado y lo anuncia el lector
    // de pantalla como lo que es, algo que se puede abrir.
    const fila = nodo("button", "fila-ataque");
    fila.type = "button";

    const sev = nodo("span", `sev sev-${a.severidad}`, NOMBRE_SEV[a.severidad] || a.severidad);
    fila.appendChild(sev);

    const texto = nodo("div", "fila-ataque-texto");
    const donde = [a.ip, a.pais, a.isp].filter(Boolean).join(" · ");
    texto.appendChild(nodo("strong", null, `${a.protocolo} — ${donde}`));
    texto.appendChild(nodo("span", "sub", a.resumen));
    fila.appendChild(texto);

    if (corteNovedades && new Date(a.fin).getTime() > corteNovedades) {
      fila.classList.add("nuevo");
    }
    fila.appendChild(nodo("span", "fila-ataque-cuando", hace(a.fin)));
    fila.addEventListener("click", () => abrirAtaque(a.clave));
    cont.appendChild(fila);
  }
}

// claveAbierta recuerda que ataque se esta mirando, para que el boton de
// explicar sepa sobre cual preguntar.
let claveAbierta = null;

function pintarExplicacion(texto) {
  const caja = $("ataque-explicacion");
  caja.replaceChildren();
  if (!texto) {
    caja.hidden = true;
    return;
  }
  caja.hidden = false;
  for (const parrafo of texto.split("\n").filter((l) => l.trim())) {
    caja.appendChild(nodo("p", null, parrafo));
  }
}

// Va por POST y con su propio boton: es el momento en que alguien quiere
// entender algo, y por eso es donde mejor se gasta una llamada.
async function explicarAtaque() {
  if (!claveAbierta) return;
  const boton = $("explicar-ataque");
  boton.disabled = true;
  boton.textContent = "Explicando…";
  try {
    const r = await pedirJSON(
      `/api/episodio/explicar?clave=${encodeURIComponent(claveAbierta)}`, { method: "POST" });
    pintarExplicacion(r.explicacion);
  } catch (e) {
    pintarExplicacion(`No se pudo explicar: ${e.message}`);
  } finally {
    boton.disabled = false;
    boton.textContent = "Explicar con IA";
  }
}

async function abrirAtaque(clave) {
  const d = await pedirJSON(`/api/episodio?clave=${encodeURIComponent(clave)}`);
  const dlg = $("dialogo-ataque");
  claveAbierta = clave;
  // Si ya se explico una vez, se ensena sin volver a preguntar: la
  // explicacion de un ataque terminado no cambia por reabrir el dialogo.
  pintarExplicacion(d.explicacion);
  $("explicar-ataque").textContent = d.explicacion ? "Volver a explicar" : "Explicar con IA";

  const titulo = $("ataque-titulo");
  titulo.replaceChildren();
  titulo.appendChild(nodo("span", null, `${d.protocolo} desde `));
  const enlaceIP = nodo("button", "enlace-ip", d.ip);
  enlaceIP.type = "button";
  enlaceIP.title = "Ver la ficha de esta IP";
  enlaceIP.addEventListener("click", () => abrirIP(d.ip).catch((e) => {
    $("ataque-sub").textContent = `no se pudo abrir la ficha: ${e.message}`;
  }));
  titulo.appendChild(enlaceIP);
  const donde = [d.pais, d.isp].filter(Boolean).join(" · ");
  const rep = d.reputacion > 0 ? ` · reputacion ${d.reputacion}/100` : "";
  $("ataque-sub").textContent = `${donde}${rep} — ${d.resumen}`;

  const cuerpo = $("ataque-cuerpo");
  cuerpo.replaceChildren();

  // Quien opera la IP va lo primero: un escaner de investigacion y una
  // botnet dejan el mismo rastro, y solo esto los distingue.
  if (d.nota_proveedor) {
    const av = nodo("p", "nota-proveedor");
    av.appendChild(nodo("strong", null, d.nota_proveedor.que));
    if (d.nota_proveedor.por) av.appendChild(nodo("span", null, ` — ${d.nota_proveedor.por}`));
    cuerpo.appendChild(av);
  }
  for (const p of d.pasos || []) {
    const fila = nodo("div", p.destacado ? "paso paso-clave" : "paso");
    fila.appendChild(nodo("span", "paso-hora", horaCorta(p.momento)));

    const texto = nodo("div", "paso-texto");
    texto.appendChild(nodo("span", null, p.texto));
    // La nota explica que significa el paso. Va debajo y en tono menor:
    // acompana a lo observado, no lo sustituye.
    if (p.nota) {
      const nota = nodo("span", "paso-nota");
      nota.appendChild(nodo("strong", null, p.nota.que));
      if (p.nota.por) nota.appendChild(nodo("span", null, ` — ${p.nota.por}`));
      texto.appendChild(nota);
    }
    fila.appendChild(texto);
    cuerpo.appendChild(fila);
  }
  if (!(d.pasos || []).length) {
    cuerpo.appendChild(nodo("p", "vacio", "Sin detalle: los eventos ya se purgaron."));
  }
  dlg.showModal();
}

// ── Situar el honeypot ──────────────────────────────────────────────────

// Un mapa pulsable en vez de una lista de regiones: es mas preciso, no
// depende de tener datos de subdivisiones de cada pais -que son 3.000 y
// cambian- y no hay que explicar como se usa.
async function pintarMapaUbicacion() {
  const m = await cargarMundo();
  const caja = $("mapa-ubicacion");
  caja.replaceChildren();

  const lienzo = svg("svg", {
    viewBox: `0 0 ${m.ancho} ${m.alto}`,
    preserveAspectRatio: "xMidYMid meet",
  });
  for (const [iso, p] of Object.entries(m.paises)) {
    lienzo.appendChild(svg("path", { d: p.d, class: "pais", "data-iso": iso }));
  }
  const marca = svg("g", { class: "marca-propia" });
  lienzo.appendChild(marca);
  caja.appendChild(lienzo);

  const situar = () => {
    marca.replaceChildren();
    const lat = parseFloat($("c-latitud").value);
    const lon = parseFloat($("c-longitud").value);
    let punto;
    if (Number.isFinite(lat) && Number.isFinite(lon) && (lat || lon)) {
      punto = aLienzo(lat, lon, m);
    } else {
      punto = m.paises[$("c-pais").value.toUpperCase()]?.c;
    }
    if (!punto) return;
    marca.appendChild(svg("circle", { cx: punto[0], cy: punto[1], r: 7, class: "diana" }));
    marca.appendChild(svg("circle", { cx: punto[0], cy: punto[1], r: 3, class: "centro" }));
  };

  lienzo.addEventListener("click", (ev) => {
    // Del pixel de pantalla a las coordenadas del SVG: el mapa se escala
    // con el ancho del dialogo, asi que no se puede usar el pixel directo.
    const caja = lienzo.getBoundingClientRect();
    const x = ((ev.clientX - caja.left) / caja.width) * m.ancho;
    const y = ((ev.clientY - caja.top) / caja.height) * m.alto;
    const [lat, lon] = delLienzo(x, y, m);
    $("c-latitud").value = lat.toFixed(4);
    $("c-longitud").value = lon.toFixed(4);
    situar();
  });

  for (const id of ["c-latitud", "c-longitud", "c-pais"]) {
    $(id).addEventListener("input", situar);
  }
  $("quitar-ubicacion").addEventListener("click", () => {
    $("c-latitud").value = 0;
    $("c-longitud").value = 0;
    situar();
  });

  situar();
}

// ── Novedades ───────────────────────────────────────────────────────────

// corteNovedades es el instante desde el que algo cuenta como nuevo. Lo
// comparten el contador y la lista para que no puedan discrepar: un chip
// que dice "2 nuevos" sobre una lista sin nada marcado seria peor que no
// tener chip.
let corteNovedades = null;

async function cargarNovedades() {
  const n = await pedirJSON("/api/novedades");
  corteNovedades = n.desde ? new Date(n.desde).getTime() : null;

  const chip = $("novedades");
  if (!n.total) {
    chip.hidden = true;
    return;
  }
  chip.hidden = false;
  chip.classList.toggle("grave", n.graves > 0);
  chip.textContent = n.graves
    ? `${n.total} nuevos · ${n.graves} grave${n.graves > 1 ? "s" : ""}`
    : `${n.total} nuevos`;
  chip.title = `Desde ${new Date(n.desde).toLocaleString("es")}. Pulsa para marcarlos como vistos.`;
}

// Marcar como visto es explicito: si se hiciera al cargar la pagina, el
// aviso desapareceria antes de que nadie lo leyera.
async function marcarVisto() {
  await pedirJSON("/api/visto", { method: "POST" });
  await refrescar();
}

// ── Avisos ──────────────────────────────────────────────────────────────

// Cada canal pide cosas distintas: ensenar los campos de los tres a la vez
// obliga a adivinar cuales tocan.
function camposDelCanal() {
  const canal = $("c-aviso-canal").value;
  const etiquetas = {
    ntfy: ["Tema de ntfy", "Elige un nombre largo y dificil de adivinar: cualquiera que sepa el tema puede leer tus avisos. Instala la app ntfy y suscribete a ese mismo tema."],
    telegram: ["Chat de Telegram", "El identificador numerico del chat. Escribe a @userinfobot para saber el tuyo."],
    webhook: ["URL del webhook", "Recibira un POST con el aviso en JSON."],
  };
  const [titulo, ayuda] = etiquetas[canal] || etiquetas.ntfy;
  const etiqueta = $("etiqueta-aviso-destino");
  etiqueta.childNodes[0].nodeValue = titulo;
  $("ayuda-aviso-destino").textContent = ayuda;
  $("etiqueta-aviso-clave").hidden = canal !== "telegram";
  $("etiqueta-aviso-servidor").hidden = canal !== "ntfy";
}

async function probarAviso() {
  const boton = $("probar-aviso");
  const estado = $("estado-aviso");
  boton.disabled = true;
  estado.textContent = "Enviando…";
  try {
    // Se guardan los ajustes primero: probar con lo que hay en pantalla y
    // no con lo guardado daria un resultado que no se corresponde con lo
    // que hara el servicio luego.
    await guardarAjustes();
    const r = await pedirJSON("/api/aviso/probar", { method: "POST" });
    estado.textContent = `Enviado por ${r.enviado}. Si no llega, revisa el destino.`;
  } catch (e) {
    estado.textContent = `No se pudo enviar: ${e.message}`;
  } finally {
    boton.disabled = false;
  }
}

// ── Ficha de una IP ─────────────────────────────────────────────────────

function dato(etiqueta, valor, malo) {
  const d = nodo("div", "dato");
  d.appendChild(nodo("span", "etiqueta", etiqueta));
  d.appendChild(nodo("span", malo ? "valor malo" : "valor", valor));
  return d;
}

function cuantoLleva(desde, hasta) {
  const dias = (new Date(hasta) - new Date(desde)) / 86400000;
  if (dias < 1) return "el mismo dia";
  if (dias < 2) return "a lo largo de 1 dia";
  return `a lo largo de ${Math.round(dias)} dias`;
}

async function abrirIP(ip) {
  const p = await pedirJSON(`/api/ip?ip=${encodeURIComponent(ip)}`);
  $("dialogo-ataque").close();

  $("ip-titulo").textContent = p.ip;
  const donde = [p.origen.pais, p.origen.isp, p.origen.tipo_uso].filter(Boolean);
  $("ip-sub").textContent = donde.join(" · ") || "sin datos publicos";

  // El veredicto va arriba y en una frase: es lo que distingue a un
  // escaner de paso de alguien que insiste, que es para lo que se abre
  // una ficha.
  const caja = $("ip-veredicto");
  caja.replaceChildren();
  const frases = [];
  if (p.episodios > 1) {
    frases.push(`Ha vuelto: ${p.episodios} ataques ${cuantoLleva(p.vista, p.ultima_vez)}.`);
  } else {
    frases.push("Primera y unica vez que aparece.");
  }
  if (p.llego_a_entrar) frases.push("Consiguio entrar.");
  if (p.escalo) frases.push("Fue a mas con el tiempo: empezo mas suave de lo que acabo.");
  if (p.nota_proveedor) {
    frases.push(`${p.nota_proveedor.que}: ${p.nota_proveedor.por}.`);
  }
  caja.appendChild(nodo("p", null, frases.join(" ")));
  caja.hidden = false;

  const datos = $("ip-datos");
  datos.replaceChildren();
  datos.appendChild(dato("Primera vez", new Date(p.vista).toLocaleString("es")));
  datos.appendChild(dato("Ultima vez", hace(p.ultima_vez)));
  datos.appendChild(dato("Ataques", String(p.episodios)));
  datos.appendChild(dato("Eventos", String(p.eventos)));
  datos.appendChild(dato("Servicios", (p.servicios || []).join(", ") || "—"));
  datos.appendChild(dato("Lo peor que hizo", NOMBRE_SEV[p.peor_hasta] || p.peor_hasta,
    p.peor_hasta === "intrusion" || p.peor_hasta === "acceso"));
  if (p.origen.reputacion) {
    datos.appendChild(dato("Reputacion", `${p.origen.reputacion}/100`, p.origen.reputacion >= 75));
  }
  if (p.origen.total_reportes) {
    datos.appendChild(dato("Denuncias", String(p.origen.total_reportes)));
  }
  if (p.origen.tor) datos.appendChild(dato("Red", "nodo de salida Tor", true));

  const lista = $("ip-ataques");
  lista.replaceChildren();
  lista.appendChild(nodo("p", "sub", "Sus ataques, del mas reciente al mas antiguo:"));
  for (const a of p.ataques || []) {
    const fila = nodo("button", "fila-ataque");
    fila.type = "button";
    fila.appendChild(nodo("span", `sev sev-${a.severidad}`, NOMBRE_SEV[a.severidad] || a.severidad));
    const texto = nodo("div", "fila-ataque-texto");
    texto.appendChild(nodo("strong", null, `${a.protocolo} — ${new Date(a.inicio).toLocaleString("es")}`));
    texto.appendChild(nodo("span", "sub", a.resumen));
    fila.appendChild(texto);
    fila.appendChild(nodo("span", "fila-ataque-cuando", hace(a.fin)));
    fila.addEventListener("click", () => { $("dialogo-ip").close(); abrirAtaque(a.clave); });
    lista.appendChild(fila);
  }

  $("dialogo-ip").showModal();
}

// ── Campanas y artefactos ───────────────────────────────────────────────

const QUE_COMPARTEN = {
  credenciales: "el mismo diccionario",
  descarga: "el mismo fichero",
  comandos: "la misma secuencia de comandos",
  rutas: "las mismas rutas",
};

async function cargarCampanas() {
  const lista = await traer("/api/campanas");
  const cont = $("campanas");
  cont.replaceChildren();

  if (!lista.length) {
    cont.appendChild(nodo("p", "vacio",
      "Ninguna coincidencia entre ataques todavia. Hacen falta al menos dos IPs compartiendo guion."));
    return;
  }

  for (const c of lista) {
    const fila = nodo("div", "campana");
    fila.appendChild(nodo("span", `sev sev-${c.severidad}`, c.severidad));

    const que = nodo("div", "campana-que");
    que.appendChild(nodo("strong", null, QUE_COMPARTEN[c.tipo] || c.tipo));
    que.appendChild(nodo("code", null, c.muestra));
    fila.appendChild(que);

    const paises = (c.paises || []).length ? ` · ${c.paises.join(" ")}` : "";
    fila.appendChild(nodo("span", "campana-alcance",
      `${c.ips.length} IPs${paises}`));
    cont.appendChild(fila);
  }
}

function tamano(bytes) {
  if (!bytes) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

async function cargarArtefactos() {
  const lista = await traer("/api/artefactos");
  const cont = $("artefactos");
  cont.replaceChildren();

  if (!lista.length) {
    cont.appendChild(nodo("p", "vacio",
      "Nadie ha intentado descargar nada todavia."));
    return;
  }

  for (const a of lista) {
    const caja = nodo("div", "artefacto");
    caja.appendChild(nodo("code", null, a.url || a.fichero));

    const partes = [];
    if (a.ips?.length) partes.push(`${a.ips.length} IP${a.ips.length > 1 ? "s" : ""}`);
    if (a.bytes) partes.push(tamano(a.bytes));
    // Cowrie nombra los ficheros con el SHA-256 de su contenido, asi que
    // el nombre sirve tal cual para consultarlo sin subir la muestra.
    if (a.fichero && !a.url) partes.push("nombre = SHA-256 del contenido");
    if (a.momento) partes.push(hace(a.momento));
    caja.appendChild(nodo("span", "sub", partes.join(" · ")));
    cont.appendChild(caja);
  }
}

async function cargarInforme() {
  pintarInforme(await traer("/api/informe"));
}

// Va por POST porque cuesta dinero: el refresco automatico usa GET, que
// siempre lo redactan las reglas y nunca gasta cuota.
async function regenerarInforme() {
  const boton = $("regenerar");
  boton.disabled = true;
  boton.textContent = "Redactando…";
  try {
    const resp = await fetch(
      `/api/informe?dias=${encodeURIComponent(rango())}`, { method: "POST" });
    if (!resp.ok) throw new Error(`respondio ${resp.status}`);
    pintarInforme(await resp.json());
  } catch (e) {
    $("informe-estado").textContent = `no se pudo redactar con IA: ${e.message}`;
  } finally {
    boton.disabled = false;
    boton.textContent = "Redactar con IA";
  }
}

async function refrescar() {
  const latido = $("latido");
  latido.className = "punto cargando";
  try {
    await cargarMundo();
    // Los recientes se piden primero: el mapa los necesita para trazar las
    // lineas de ataque.
    await cargarNovedades();
    const recientes = await pedirJSON("/api/recientes");
    pintarVivo(recientes);
    await Promise.all([
      cargarEstado(recientes),
      cargarAtaques(),
      cargarCampanas(),
      cargarArtefactos(),
      cargarInforme(),
      traer("/api/serie").then(pintarSerie),
    ]);
    latido.className = "punto conectado";
    $("actualizado").textContent = new Date().toLocaleTimeString("es");
  } catch (err) {
    latido.className = "punto error";
    $("actualizado").textContent = err.message;
  }
}

// Tema: oscuro por defecto, como T-Pot. La eleccion se recuerda.
function aplicarTema(t) {
  document.documentElement.dataset.tema = t;
  try { localStorage.setItem("k0pot-tema", t); } catch (e) { /* modo privado */ }
}
aplicarTema(localStorage.getItem("k0pot-tema") || "oscuro");
$("tema").addEventListener("click", () => {
  aplicarTema(document.documentElement.dataset.tema === "claro" ? "oscuro" : "claro");
});

$("rango").addEventListener("change", refrescar);
$("regenerar").addEventListener("click", regenerarInforme);
$("cerrar-ataque").addEventListener("click", () => $("dialogo-ataque").close());
$("explicar-ataque").addEventListener("click", explicarAtaque);
$("cerrar-ip").addEventListener("click", () => $("dialogo-ip").close());

// Los filtros recargan solo la lista, no el panel entero: cambiar de
// gravedad no tiene por que volver a pedir el mapa ni el informe.
for (const id of ["f-severidad", "f-protocolo"]) {
  $(id).addEventListener("change", () => cargarAtaques().catch(() => {}));
}
let tecleando = null;
$("f-texto").addEventListener("input", () => {
  // Se espera a que pare de escribir: una consulta por tecla llenaria el
  // servidor de peticiones que nadie llega a ver.
  clearTimeout(tecleando);
  tecleando = setTimeout(() => cargarAtaques().catch(() => {}), 250);
});
$("f-limpiar").addEventListener("click", () => {
  $("f-texto").value = "";
  $("f-severidad").value = "";
  $("f-protocolo").value = "";
  cargarAtaques().catch(() => {});
});
$("c-aviso-canal").addEventListener("change", camposDelCanal);
$("probar-aviso").addEventListener("click", probarAviso);
$("novedades").addEventListener("click", marcarVisto);

// ─── Sesion y ajustes ──────────────────────────────────────────────────

const dialogo = $("dialogo-ajustes");

async function pedirJSON(ruta, opciones) {
  const resp = await fetch(ruta, opciones);
  const datos = await resp.json().catch(() => ({}));
  if (resp.status === 401) {
    location.href = "/entrar.html";
    throw new Error("sesion caducada");
  }
  if (!resp.ok) throw new Error(datos.error || `${ruta} respondio ${resp.status}`);
  return datos;
}

const CAMPOS = {
  "c-reputacion": "reputacion_alta",
  "c-denuncias": "denuncias_altas",
  "c-caducidad": "caducidad_ip_dias",
  "c-reserva": "reserva_cuota",
  "c-modelo": "modelo",
  "c-proveedor": "proveedor",
  "c-url-base": "url_base",
  "c-refresco": "refresco_segundos",
  "c-pais": "pais_propio",
  "c-latitud": "latitud_propia",
  "c-longitud": "longitud_propia",
  "c-retencion": "retencion_dias",
  "c-retencion-ataques": "retencion_episodios_dias",
  "c-tls-cert": "tls_cert",
  "c-tls-clave": "tls_clave",
  "c-informe-tope": "informe_tope_diario",
  "c-aviso-canal": "aviso_canal",
  "c-aviso-destino": "aviso_destino",
  "c-aviso-servidor": "aviso_servidor",
  "c-aviso-minima": "aviso_minima",
  "c-aviso-enlace": "aviso_enlace",
};
const INTERRUPTORES = {
  "c-enriquecer": "enriquecer_activo",
  "c-usar-llm": "usar_llm",
  "c-avisos-activos": "avisos_activos",
  "c-panel-https": "panel_https",
};

function volcarAjustes(c) {
  for (const [id, clave] of Object.entries(CAMPOS)) $(id).value = c[clave];
  camposDelCanal();
  for (const [id, clave] of Object.entries(INTERRUPTORES)) $(id).checked = c[clave];

  $("estado-abuse").textContent = c.tiene_abuseipdb
    ? `clave guardada: ${c.clave_abuseipdb}`
    : "sin clave: no se enriqueceran las IPs";
  $("estado-anthropic").textContent = c.tiene_anthropic
    ? `clave guardada: ${c.clave_anthropic}`
    : "sin clave: los informes los redactaran las reglas";
  $("estado-compatible").textContent = c.tiene_compatible
    ? `clave guardada: ${c.clave_compatible}`
    : "sin clave: los informes los redactaran las reglas";
  mostrarCamposDelProveedor();
}

// Solo se ensenan los campos del proveedor elegido: URL base no significa
// nada con Anthropic, y dos casillas de clave a la vez confunden.
function mostrarCamposDelProveedor() {
  const compatible = $("c-proveedor").value === "compatible";
  $("campos-compatible").hidden = !compatible;
  $("campos-anthropic").hidden = compatible;
}

function leerAjustes() {
  const cuerpo = {};
  for (const [id, clave] of Object.entries(CAMPOS)) {
    const el = $(id);
    cuerpo[clave] = el.type === "number" ? Number(el.value) : el.value;
  }
  for (const [id, clave] of Object.entries(INTERRUPTORES)) cuerpo[clave] = $(id).checked;

  // Campo vacio = no tocar la clave guardada. Para borrarla hay que
  // desmarcar el enriquecimiento o el LLM, que es lo que se quiere de
  // verdad al dejar de usar un servicio.
  cuerpo.servicios = leerServicios();
  cuerpo.escucha_panel = $("c-escucha-panel").value;
  cuerpo.escucha_honeypots = $("c-escucha-honeypots").value;

  for (const [id, clave] of [
    ["c-clave-abuse", "clave_abuseipdb"],
    ["c-clave-anthropic", "clave_anthropic"],
    ["c-clave-compatible", "clave_compatible"],
    ["c-aviso-clave", "clave_aviso"],
  ]) {
    const v = $(id).value.trim();
    if (v) cuerpo[clave] = v;
  }
  return cuerpo;
}


// ─── Servicios de honeypot y red ───────────────────────────────────────

let servicios = [];

function pintarServicios(datos) {
  servicios = datos.servicios || [];
  const cont = $("lista-servicios");
  cont.replaceChildren();

  for (const sv of servicios) {
    const fila = nodo("div", "servicio");

    const cab = nodo("label", "servicio-cab");
    const casilla = document.createElement("input");
    casilla.type = "checkbox";
    casilla.checked = sv.activo;
    casilla.dataset.id = sv.id;
    cab.appendChild(casilla);
    cab.appendChild(nodo("span", "servicio-nombre", sv.nombre));
    const estado = nodo("span", sv.activo ? "chip activo" : "chip", sv.activo ? "activo" : "parado");
    cab.appendChild(estado);
    fila.appendChild(cab);

    fila.appendChild(nodo("p", "ayuda", sv.descripcion));

    const puertos = nodo("div", "servicio-puertos");
    const campo = nodo("label", "puerto-campo");
    campo.appendChild(nodo("span", null, "escucha en el puerto"));
    const puerto = document.createElement("input");
    puerto.type = "number";
    puerto.min = 1024;
    puerto.max = 65535;
    puerto.value = sv.puerto;
    puerto.dataset.id = sv.id;
    campo.appendChild(puerto);
    puertos.appendChild(campo);
    puertos.appendChild(nodo("span", "ayuda", "redirige aqui el trafico del puerto real"));
    fila.appendChild(puertos);

    cont.appendChild(fila);
  }

  for (const [id, valor] of [["c-escucha-panel", datos.escucha_panel],
                             ["c-escucha-honeypots", datos.escucha_honeypots]]) {
    const sel = $(id);
    sel.replaceChildren();
    for (const ifa of datos.interfaces || []) {
      const op = document.createElement("option");
      op.value = ifa.ip;
      op.textContent = ifa.nombre === "todas"
        ? "todas las interfaces (0.0.0.0)"
        : `${ifa.nombre} — ${ifa.ip}`;
      sel.appendChild(op);
    }
    sel.value = valor;
  }
  avisarSiMismaRed(datos.interfaces || []);
}

// Si dos interfaces comparten red, separarlas aqui no aisla nada. Vale mas
// decirlo en el panel que dejar creer que hay proteccion donde no la hay.
function avisarSiMismaRed(interfaces) {
  const redes = {};
  for (const ifa of interfaces) {
    if (ifa.nombre === "todas") continue;
    const red = ifa.ip.split(".").slice(0, 3).join(".");
    (redes[red] = redes[red] || []).push(ifa.nombre);
  }
  const compartida = Object.entries(redes).find(([, ifs]) => ifs.length > 1);
  const aviso = $("aviso-red");
  if (compartida) {
    aviso.textContent =
      `Atencion: ${compartida[1].join(" y ")} estan en la misma red (${compartida[0]}.0/24). ` +
      "Elegir interfaces distintas aqui NO aisla nada: la separacion tiene que hacerse " +
      "en el hipervisor y en el router.";
    aviso.className = "ayuda peligro";
  } else {
    aviso.textContent = "El panel y los honeypots pueden escuchar en interfaces distintas.";
    aviso.className = "ayuda";
  }
}

function leerServicios() {
  const out = {};
  for (const sv of servicios) {
    const casilla = document.querySelector(`#lista-servicios input[type=checkbox][data-id="${sv.id}"]`);
    const puerto = document.querySelector(`#lista-servicios input[type=number][data-id="${sv.id}"]`);
    if (casilla && puerto) out[sv.id] = { activo: casilla.checked, puerto: Number(puerto.value) };
  }
  return out;
}


// ─── Direcciones IP de las interfaces ──────────────────────────────────

let interfacesRed = [];

async function cargarRed() {
  const r = await pedirJSON("/api/red");
  interfacesRed = r.interfaces || [];

  $("aviso-ayudante").textContent = r.aviso || "";
  $("aviso-ayudante").className = r.aviso ? "ayuda peligro" : "ayuda";
  // Sin ayudante privilegiado no se puede tocar la red del sistema, pero si
  // generar la configuracion para aplicarla a mano.
  for (const id of ["aplicar-red", "confirmar-red", "revertir-red"]) {
    $(id).disabled = !r.aplicable;
  }

  const cont = $("editor-red");
  cont.replaceChildren();

  for (const ifa of interfacesRed) {
    const caja = nodo("div", "interfaz-red");

    const cab = nodo("div", "interfaz-cab");
    cab.appendChild(nodo("span", "servicio-nombre", ifa.nombre));
    cab.appendChild(nodo("span", "chip" + (ifa.activa ? " activo" : ""), ifa.activa ? "activa" : "caida"));
    caja.appendChild(cab);
    caja.appendChild(nodo("p", "ayuda", `ahora: ${(ifa.ips || []).join(", ") || "sin IP"}`));

    const modo = nodo("label", "fila");
    const dhcp = document.createElement("input");
    dhcp.type = "checkbox";
    dhcp.dataset.campo = "dhcp";
    dhcp.dataset.iface = ifa.nombre;
    modo.appendChild(dhcp);
    modo.appendChild(nodo("span", null, "obtener por DHCP"));
    caja.appendChild(modo);

    for (const [campo, etiqueta, ejemplo] of [
      ["ip", "Direccion con prefijo", "192.168.50.10/24"],
      ["pasarela", "Pasarela", "192.168.50.1"],
      ["dns", "DNS (separados por comas)", "1.1.1.1, 8.8.8.8"],
    ]) {
      const l = nodo("label", null);
      l.appendChild(nodo("span", null, etiqueta));
      const inp = document.createElement("input");
      inp.type = "text";
      inp.placeholder = ejemplo;
      inp.dataset.campo = campo;
      inp.dataset.iface = ifa.nombre;
      if (campo === "ip" && (ifa.ips || []).length) inp.value = ifa.ips[0];
      l.appendChild(inp);
      caja.appendChild(l);
    }

    // Con DHCP los campos manuales sobran.
    dhcp.addEventListener("change", () => {
      caja.querySelectorAll("input[type=text]").forEach((e) => { e.disabled = dhcp.checked; });
    });

    cont.appendChild(caja);
  }
}

function leerRed() {
  return interfacesRed.map((ifa) => {
    const val = (campo) => {
      const e = document.querySelector(`#editor-red [data-iface="${ifa.nombre}"][data-campo="${campo}"]`);
      return e ? (campo === "dhcp" ? e.checked : e.value.trim()) : "";
    };
    const dns = val("dns");
    return {
      nombre: ifa.nombre,
      dhcp: val("dhcp"),
      ip: val("ip"),
      pasarela: val("pasarela"),
      dns: dns ? dns.split(",").map((x) => x.trim()).filter(Boolean) : [],
    };
  });
}

async function accionRed(accion) {
  const estado = $("estado-red");
  estado.textContent = "Procesando…";
  estado.className = "ayuda";
  try {
    const r = await pedirJSON("/api/red", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ accion, interfaces: leerRed() }),
    });
    if (r.yaml) {
      $("yaml-red").textContent = r.yaml; // textContent: nunca como HTML
      $("yaml-red").hidden = false;
    }
    estado.textContent = r.aviso || r.salida || "Hecho.";
    if (r.aviso) estado.className = "ayuda peligro";
  } catch (err) {
    estado.textContent = err.message;
    estado.className = "ayuda peligro";
  }
}

$("generar-red").addEventListener("click", () => accionRed("generar"));
$("aplicar-red").addEventListener("click", () => {
  if (confirm("Vas a cambiar la red del servidor.\n\nSi tocas la IP por la que " +
              "entras al panel, perderas el acceso hasta abrir la nueva. La red se " +
              "revierte sola en 2 minutos si no confirmas.\n\nContinuar?")) {
    accionRed("aplicar");
  }
});
$("confirmar-red").addEventListener("click", () => accionRed("confirmar"));
$("revertir-red").addEventListener("click", () => accionRed("revertir"));


// ─── Pestanas de ajustes ───────────────────────────────────────────────

function irAPestana(nombre) {
  for (const g of document.querySelectorAll("#dialogo-ajustes .grupo")) {
    g.hidden = g.dataset.pestana !== nombre;
  }
  for (const b of document.querySelectorAll(".pestanas [data-ir]")) {
    b.setAttribute("aria-selected", String(b.dataset.ir === nombre));
  }
  // Al cambiar de pestana se vuelve arriba: si no, se entra a mitad de
  // scroll y parece que falta contenido.
  const form = document.querySelector("#dialogo-ajustes form");
  if (form) form.scrollTop = 0;
}

for (const b of document.querySelectorAll(".pestanas [data-ir]")) {
  b.addEventListener("click", () => irAPestana(b.dataset.ir));
}

// Flechas para moverse entre pestanas con el teclado.
document.querySelector(".pestanas")?.addEventListener("keydown", (ev) => {
  if (ev.key !== "ArrowLeft" && ev.key !== "ArrowRight") return;
  const botones = [...document.querySelectorAll(".pestanas [data-ir]")];
  const i = botones.findIndex((b) => b.getAttribute("aria-selected") === "true");
  const siguiente = botones[(i + (ev.key === "ArrowRight" ? 1 : -1) + botones.length) % botones.length];
  siguiente.focus();
  irAPestana(siguiente.dataset.ir);
  ev.preventDefault();
});

async function abrirAjustes() {
  try {
    volcarAjustes(await pedirJSON("/api/ajustes"));
    pintarServicios(await pedirJSON("/api/servicios"));
  } catch (err) {
    $("actualizado").textContent = err.message;
    return;
  }

  // La red va aparte y no bloquea: enumerar interfaces depende del sistema
  // y puede fallar por motivos que nada tienen que ver con el resto de los
  // ajustes. Que un fallo ahi deje sin abrir la ventana entera es una
  // ventana que se pierde por una pestana. Paso: el sandbox de systemd
  // cerro AF_NETLINK y Ajustes dejo de abrirse sin decir por que.
  try {
    await cargarRed();
  } catch (err) {
    $("estado-red").textContent = `No se pudo leer la red: ${err.message}`;
  }

  // Elegir un plazo sin saber cuanto ocupa es elegir a ojo.
  try {
    const u = await pedirJSON("/api/uso");
    $("uso-disco").textContent =
      `Ahora mismo ocupa ${u.legible.total}: base de datos ${u.legible.base_datos}, ` +
      `grabaciones ${u.legible.grabaciones}, descargas ${u.legible.descargas}.`;
  } catch {
    $("uso-disco").textContent = "";
  }

  try {
    await pintarMapaUbicacion();
  } catch {
    // El mapa es una ayuda, no un requisito: si no carga, quedan los
    // campos de latitud y longitud.
  }

  irAPestana("servicios");
  $("estado-ajustes").textContent = "";
  $("estado-contrasena").textContent = "";
  dialogo.showModal();
}

async function guardarAjustes() {
  const estado = $("estado-ajustes");
  estado.textContent = "Guardando…";
  try {
    const c = await pedirJSON("/api/ajustes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(leerAjustes()),
    });
    volcarAjustes(c);
    pintarServicios(await pedirJSON("/api/servicios"));
    for (const id of ["c-clave-abuse", "c-clave-anthropic", "c-clave-compatible"]) {
      $(id).value = "";
    }
    estado.textContent = "Guardado.";
    aplicarRefresco(c.refresco_segundos);
    refrescar();
  } catch (err) {
    estado.textContent = err.message;
  }
}

async function cambiarContrasena() {
  const estado = $("estado-contrasena");
  estado.textContent = "Cambiando…";
  try {
    await pedirJSON("/api/contrasena", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ actual: $("p-actual").value, nueva: $("p-nueva").value }),
    });
    $("p-actual").value = "";
    $("p-nueva").value = "";
    estado.textContent = "Contrasena cambiada. Las demas sesiones se han cerrado.";
  } catch (err) {
    estado.textContent = err.message;
  }
}

let temporizador = null;
function aplicarRefresco(segundos) {
  if (temporizador) clearInterval(temporizador);
  temporizador = setInterval(refrescar, Math.max(5, segundos || 20) * 1000);
}

$("c-proveedor").addEventListener("change", mostrarCamposDelProveedor);
$("abrir-ajustes").addEventListener("click", abrirAjustes);
$("cerrar-ajustes").addEventListener("click", () => dialogo.close());
$("guardar-ajustes").addEventListener("click", guardarAjustes);
$("guardar-contrasena").addEventListener("click", cambiarContrasena);
$("restaurar").addEventListener("click", async () => {
  volcarAjustes(await pedirJSON("/api/ajustes/defecto"));
  $("estado-ajustes").textContent = "Valores por defecto cargados. Pulsa Guardar para aplicarlos.";
});
$("salir").addEventListener("click", async () => {
  await fetch("/api/salir", { method: "POST" });
  location.href = "/entrar.html";
});

async function iniciar() {
  try {
    const q = await pedirJSON("/api/quien");
    if (!q.autenticado) {
      location.href = "/entrar.html";
      return;
    }
    $("quien").textContent = q.usuario;
    const c = await pedirJSON("/api/ajustes");
    aplicarRefresco(c.refresco_segundos);
  } catch (err) {
    return;
  }
  refrescar();
}
iniciar();
