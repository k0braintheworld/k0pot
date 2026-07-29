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
  const resp = await fetch(`${ruta}?dias=${encodeURIComponent(rango())}&idioma=${IDIOMA}`);
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

// dispersar convierte una IP en un desvio pequeno y ESTABLE, para separar
// las lineas que salen del mismo pais sin que salten de sitio en cada
// refresco. El mismo texto da siempre el mismo desvio.
function dispersar(ip) {
  let h = 0;
  for (let i = 0; i < ip.length; i++) {
    h = (h * 31 + ip.charCodeAt(i)) | 0;
  }
  // Un anillo de radio fijo: el angulo lo decide la IP. Radio en unidades
  // del lienzo (~8 sobre un ancho de 1000), suficiente para distinguirlas
  // sin alejarlas del pais.
  const ang = (h >>> 0) % 360 * Math.PI / 180;
  return [Math.cos(ang) * 8, Math.sin(ang) * 8];
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

  // Una linea por IP DISTINTA, no por evento. Una sola sesion SSH genera
  // "conecta", "huella", varios "login"... todos desde la misma IP: pintar
  // uno por evento amontona lineas identicas encima. Y como el origen es el
  // centroide del pais, todas las IP de un mismo pais salen del mismo punto,
  // asi que se les da un pequeno desvio para que se distingan en vez de
  // superponerse. Eso -y no que "siempre sean las mismas"- es lo que hacia
  // que el mapa pareciera congelado.
  const vistas = new Set();
  // La peor clasificacion de cada IP manda el color: si una IP tiene un
  // evento notable, su linea debe salir en rojo aunque el ultimo fuera ruido.
  const peorDe = new Map();
  const rango = { ruido_fondo: 0, revisar: 1, notable: 2 };
  for (const ev of recientes) {
    const actual = peorDe.get(ev.ip);
    if (actual === undefined || rango[ev.clasificacion] > rango[actual]) {
      peorDe.set(ev.ip, ev.clasificacion);
    }
  }

  for (const ev of recientes) {
    if (ev.pais === paisPropio || vistas.has(ev.ip)) continue;
    if (dibujados >= 18) break; // mas lineas solo ensucian

    // Si la IP esta situada por ciudad, la linea sale de sus coordenadas
    // exactas. Si no, del centroide del pais con un desvio por IP para no
    // amontonar todas las de un mismo pais en el mismo punto.
    let salida;
    if (ev.latitud || ev.longitud) {
      salida = aLienzo(ev.latitud, ev.longitud, m);
    } else {
      const origen = m.paises[ev.pais]?.c;
      if (!origen) continue;
      const desvio = dispersar(ev.ip);
      salida = [origen[0] + desvio[0], origen[1] + desvio[1]];
    }
    vistas.add(ev.ip);

    const clase = peorDe.get(ev.ip);
    const linea = svg("path", {
      d: arco(salida, destino),
      class: `ataque ${clase === "notable" ? "notable" : clase === "revisar" ? "revisar" : ""}`,
    });
    // El retardo va por CSSOM: la CSP bloquea los atributos style en linea.
    linea.style.animationDelay = `${(dibujados * 0.14).toFixed(2)}s`;
    // Cada linea es ya un atacante concreto: al pasar el raton dice quien es.
    const quien = svg("title");
    const donde = ev.ciudad
      ? `${ev.ciudad}, ${nombrePais(ev.pais)}`
      : ev.pais ? nombrePais(ev.pais) : t("origen.desconocido");
    quien.textContent = `${ev.ip} — ${donde}`;
    linea.appendChild(quien);
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
    "aria-label": t("mapa.aria"),
  });

  // Paises: los que atacan se tinen segun su peso relativo.
  for (const [iso, pais] of Object.entries(m.paises)) {
    const n = porIso.get(iso) || 0;
    const forma = svg("path", { d: pais.d, class: n > 0 ? "pais activo" : "pais" });
    if (n > 0) {
      // Raiz cuadrada para que los paises con poca actividad sigan
      // distinguiendose del fondo en vez de quedarse casi invisibles.
      const peso = Math.sqrt(n / maximo);
      forma.setAttribute("fill-opacity", (0.10 + peso * 0.40).toFixed(3));
    }
    const titulo = svg("title");
    titulo.textContent = n > 0 ? t("mapa.eventospais", { pais: pais.n, n }) : pais.n;
    forma.appendChild(titulo);
    lienzo.appendChild(forma);
  }

  // Circulos proporcionales encima, para que un pais pequeno con mucha
  // actividad no pase desapercibido.
  for (const [iso, n] of porIso) {
    const pais = m.paises[iso];
    if (!pais) continue;
    const r = 2 + Math.sqrt(n / maximo) * 9;
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
    ? t("mapa.sinorigen")
    : `${porIso.size} pais(es) · ${total} eventos` +
      (lineas > 0 ? ` · ${lineas} ataques recientes` : "");

  if (total === 0) {
    cont.appendChild(nodo("p", "aviso-mapa",
      t("mapa.sinpais")));
  }
}

// ─── Grafica temporal ──────────────────────────────────────────────────

function pintarSerie(datos) {
  const cont = $("serie");
  cont.replaceChildren();

  const puntos = datos.puntos || [];
  if (!puntos.length) {
    cont.appendChild(nodo("p", "cargando", t("vivo.vacio")));
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
    col.title = `${cuando.toLocaleString(IDIOMA)}\n${p.total} eventos ` +
      t("serie.reparto", { ruido: p.ruido, revisar: p.revisar, notable: p.notable });
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

// visibleJS hace legible un texto con bytes de control o basura binaria.
// Es el gemelo en el navegador de visible() en Go: un escaner no siempre
// habla el protocolo del puerto -un "cliente SSH" puede ser un saludo RDP-
// y volcar esos bytes rompe el render (los cuadraditos que se veian). Se
// escapan a \xNN, que ademas deja ver que HABIA bytes no imprimibles.
function visibleJS(s) {
  if (!s) return "";
  let out = "";
  for (const ch of s) {
    const c = ch.codePointAt(0);
    if (ch === "\t") out += "\\t";
    else if (c < 0x20 || c === 0x7f) out += "\\x" + c.toString(16).padStart(2, "0");
    else if (c === 0xfffd) out += "\\x??";
    // Rango de control C1 (0x80-0x9f): invisible y sospechoso, se escapa.
    else if (c >= 0x80 && c <= 0x9f) out += "\\x" + c.toString(16).padStart(2, "0");
    else out += ch;
  }
  return out;
}

// terminalDe traduce un evento a como se veria en la consola del atacante.
// No inventa nada: es lo mismo que capturamos, con la gramatica del
// protocolo real -redis-cli muestra "127.0.0.1:6379>", ftp usa comandos en
// mayusculas, una shell un "$"-, para que se lea como lo que de verdad fue.
function terminalDe(ev) {
  const d = ev.detalle || {};
  switch (ev.tipo) {
    case "conexion": {
      const p = d.puerto ? `:${d.puerto}` : "";
      return { sigilo: "•", cuerpo: `connect${p}`, tecleado: false };
    }
    case "huella_cliente":
      return { sigilo: "→", cuerpo: `client: ${visibleJS(d.cliente)}`, tecleado: false };
    case "login_fallido":
      return { sigilo: "✗", cuerpo: `login ${visibleJS(d.usuario)}:${visibleJS(d.password)} denied`, tecleado: true };
    case "login_exitoso":
      return { sigilo: "✓", cuerpo: `login ${visibleJS(d.usuario)}:${visibleJS(d.password)} OK`, tecleado: true };
    case "comando_ejecutado": {
      // Un verbo de Redis/FTP no es una shell: se muestra con su prompt real.
      const prompt = ev.protocolo === "redis" ? "redis>" : ev.protocolo === "ftp" ? "ftp>" : "$";
      return { sigilo: prompt, cuerpo: visibleJS(d.comando), tecleado: true };
    }
    case "tunel_solicitado":
      return { sigilo: "⇄", cuerpo: `forward → ${visibleJS(d.destino)}`, tecleado: true };
    case "descarga_fichero":
      return { sigilo: "↓", cuerpo: `fetch ${visibleJS(d.url || d.fichero)}`, tecleado: true };
    case "peticion_http": {
      const linea = `${d.metodo || "GET"} ${visibleJS(d.ruta) || "/"}`;
      return { sigilo: "»", cuerpo: linea, tecleado: true };
    }
    default:
      return { sigilo: "·", cuerpo: ev.tipo, tecleado: false };
  }
}

// vistos guarda las lineas ya pintadas -por id de evento aproximado- para
// teclear SOLO las nuevas: reteclear todo en cada refresco marearia.
const vistosVivo = new Set();

function pintarVivo(lista) {
  const cont = $("vivo");
  cont.replaceChildren();

  if (!lista.length) {
    cont.appendChild(nodo("p", "cargando", t("vivo.esperando")));
    return;
  }

  // Se pintan del mas antiguo al mas nuevo, como una consola que crece
  // hacia abajo; la lista llega al reves.
  const orden = [...lista].reverse();
  for (const ev of orden) {
    const t = terminalDe(ev);
    const clave = `${ev.timestamp}|${ev.ip}|${t.cuerpo}`;
    const esNuevo = !vistosVivo.has(clave);
    vistosVivo.add(clave);

    const fila = nodo("div", `tl ${ev.clasificacion}`);
    fila.appendChild(nodo("span", "tl-hora", horaCorta(ev.timestamp)));
    // El prompt lleva la IP del atacante, como en una sesion real.
    const prompt = nodo("span", "tl-prompt");
    prompt.appendChild(nodo("span", "tl-ip", ev.ip));
    if (ev.pais) prompt.appendChild(nodo("span", "tl-pais", ev.pais.toLowerCase()));
    prompt.appendChild(nodo("span", "tl-sigilo", t.sigilo));
    fila.appendChild(prompt);

    const cuerpo = nodo("span", "tl-cuerpo");
    if (esNuevo && t.tecleado && t.cuerpo.length <= 80) {
      teclear(cuerpo, t.cuerpo);
    } else {
      cuerpo.textContent = t.cuerpo;
    }
    fila.appendChild(cuerpo);
    cont.appendChild(fila);
  }

  // Cursor parpadeante al final: la senal de que la consola esta viva.
  const cursor = nodo("div", "tl-cursor");
  cursor.appendChild(nodo("span", "tl-sigilo", "▸"));
  cursor.appendChild(nodo("span", "tl-caret", "█"));
  cont.appendChild(cursor);

  // Se mantiene el scroll abajo, donde esta lo ultimo.
  cont.scrollTop = cont.scrollHeight;

  // No dejar crecer el set sin fin.
  if (vistosVivo.size > 500) {
    const sobran = [...vistosVivo].slice(0, vistosVivo.size - 300);
    for (const k of sobran) vistosVivo.delete(k);
  }
}

// teclear revela el texto caracter a caracter, rapido: la sensacion de
// estar viendo a alguien escribir en directo. Se cancela si la fila se
// reemplaza, para no dejar temporizadores colgando.
function teclear(nodo, texto) {
  let i = 0;
  const paso = () => {
    if (!nodo.isConnected) return;
    nodo.textContent = texto.slice(0, i);
    if (i++ < texto.length) setTimeout(paso, 18);
  };
  paso();
}

// ─── Tablas y resto ────────────────────────────────────────────────────

function pintarTabla(id, filas) {
  const cuerpo = $(id).querySelector("tbody");
  cuerpo.replaceChildren();
  if (!filas || !filas.length) {
    const tr = nodo("tr");
    tr.appendChild(nodo("td", "vacio", t("tabla.vacio")));
    cuerpo.appendChild(tr);
    return;
  }
  for (const fila of filas.slice(0, 50)) {
    const tr = nodo("tr");
    for (const c of fila) {
      const td = nodo("td", c.clase);
      if (c.ip) {
        // La IP abre su ficha: es la forma mas corta de pasar de "quien
        // aparece mucho" a "que ha hecho y si ya habia venido".
        const enlace = nodo("button", "enlace-ip", c.ip);
        enlace.type = "button";
        enlace.title = "Ver la ficha de esta IP";
        enlace.addEventListener("click", () => abrirIP(c.ip).catch(() => {}));
        td.appendChild(enlace);
      } else {
        td.textContent = c.valor === "" || c.valor == null ? "—" : String(c.valor);
      }
      tr.appendChild(td);
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

// Nombres bonitos de los servicios para el panel; los internos van en
// minusculas (ssh, http, mysql...).
const NOMBRE_SERVICIO = {
  ssh: "SSH", telnet: "Telnet", http: "HTTP", redis: "Redis", ftp: "FTP",
  mysql: "MySQL", postgres: "PostgreSQL", smtp: "SMTP", rdp: "RDP",
  vnc: "VNC", docker: "Docker",
};
function nombreServicio(id) {
  return NOMBRE_SERVICIO[id] || (id ? id[0].toUpperCase() + id.slice(1) : "?");
}

// pintarSemaforo escribe la linea del semaforo: la palabra del nivel -el
// color ya lo refuerza- y a que servicio le estan dando, de mas a menos.
function pintarSemaforo(nivel, servicios) {
  const cont = $("frase");
  cont.replaceChildren();
  cont.appendChild(nodo("strong", "sem-nivel", t("nivel." + nivel.toLowerCase())));

  servicios = servicios || [];
  if (!servicios.length) {
    cont.appendChild(nodo("span", "sem-vacio", t("sem.vacio")));
    return;
  }
  cont.appendChild(nodo("span", "sep", "—"));
  servicios.forEach((sv, i) => {
    if (i > 0) cont.appendChild(nodo("span", "sep", "·"));
    const chip = nodo("span", "serv");
    chip.appendChild(nodo("span", "serv-nombre", nombreServicio(sv.Valor)));
    chip.appendChild(nodo("span", "serv-n", String(sv.N)));
    cont.appendChild(chip);
  });
}

async function cargarEstado(recientes) {
  const e = await traer("/api/estado");

  const sem = $("semaforo");
  sem.className = `semaforo ${e.nivel.toLowerCase()}`;
  // El veredicto en una frase pasa a ser el tooltip: sigue ahi para quien lo
  // quiera, pero la linea la ocupa algo mas util, el reparto por servicio.
  // Se arma en el cliente para que siga el idioma elegido.
  const sv2 = e.severidades || {};
  const nInt = sv2.intrusion || 0, nAcc = sv2.acceso || 0;
  const atq = (n) => t(n === 1 ? "sem.ataque1" : "sem.ataqueN", { n });
  sem.title = nInt > 0 ? t("sem.rojo", { n: atq(nInt) })
    : nAcc > 0 ? t("sem.ambar", { n: atq(nAcc) })
    : t("sem.verde");
  pintarSemaforo(e.nivel, e.ataques_por_servicio);

  // Las metricas cuentan ATAQUES (episodios), no eventos, para hablar el
  // mismo idioma que la grafica de gravedad: un intruso genera decenas de
  // eventos pero es un solo ataque. "Eventos" queda como dato bruto de
  // volumen; ruido/a revisar/notables salen del baremo de gravedad.
  const sv = e.severidades || {};
  const nRoce = sv.roce || 0, nTanteo = sv.tanteo || 0;
  const nAcceso = sv.acceso || 0, nIntrusion = sv.intrusion || 0;
  const ataques = nRoce + nTanteo + nAcceso + nIntrusion;
  const ruido = nRoce + nTanteo;
  $("m-total").textContent = e.total.toLocaleString(IDIOMA);
  $("m-ips").textContent = e.ips_unicas.toLocaleString(IDIOMA);
  $("m-paises").textContent = (e.por_pais || []).length;
  $("m-ruido").textContent = ataques > 0 ? Math.round((ruido / ataques) * 100) : 0;
  $("m-revisar").textContent = nAcceso;
  $("m-notable").textContent = nIntrusion;

  await pintarMapa(e.por_pais || [], recientes, e.pais_propio,
    { lat: e.latitud_propia || 0, lon: e.longitud_propia || 0 });

  pintarTabla("tabla-ips", (e.top_ips || []).map((ip) => [
    { ip: ip.ip, clase: "celda-ip" },
    { valor: ip.eventos, clase: "num" },
    { valor: contextoIP(ip), clase: "sub" },
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

  pintarGravedad(e.severidades);
}


// hace convierte un instante en algo legible de un vistazo. Un informe
// fechado sin mas obliga a restar mentalmente para saber si esta al dia.
function hace(iso) {
  const seg = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seg < 90) return t("hace.momento");
  const min = Math.round(seg / 60);
  if (min < 60) return t("hace.min", { n: min });
  const h = Math.round(min / 60);
  if (h < 24) return t("hace.h", { n: h });
  return t("hace.d", { n: Math.round(h / 24) });
}

// ── Ataques ─────────────────────────────────────────────────────────────

function nombreSev(sev) {
  return t("sev." + sev);
}

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
    automatismo: $("f-automatismo").value,
  };
}

function hayFiltro() {
  const f = filtrosDeAtaques();
  return Boolean(f.q || f.severidad || f.protocolo || f.automatismo || $("f-ruido").checked);
}

async function cargarAtaques() {
  const f = filtrosDeAtaques();
  const params = new URLSearchParams({ dias: rango(), idioma: IDIOMA });
  for (const [k, v] of Object.entries(f)) if (v) params.set(k, v);

  const resp = await fetch(`/api/episodios?${params}`);
  if (!resp.ok) throw new Error(`/api/episodios respondio ${resp.status}`);
  let lista = await resp.json();
  // "Ocultar ruido de fondo": fuera lo que no llego a entrar -escaneos,
  // tanteos y fuerza bruta fallida-, que es la mayoria y no cuenta ninguna
  // historia. Se queda lo que consiguio acceso o actuo dentro.
  if ($("f-ruido").checked) {
    lista = lista.filter((a) => a.severidad === "acceso" || a.severidad === "intrusion");
  }

  const cont = $("ataques");
  cont.replaceChildren();
  $("f-limpiar").hidden = !hayFiltro();

  if (!lista.length) {
    cont.appendChild(nodo("p", "vacio", hayFiltro()
      ? t("ataques.nofiltro")
      : t("ataques.ninguno")));
    return;
  }

  // Con filtro puesto hay que decirlo: una lista corta sin explicacion se
  // lee como "no ha pasado nada", que es justo lo contrario.
  if (hayFiltro()) {
    cont.appendChild(nodo("p", "aviso-filtrado",
      t("ataques.filtro", { n: lista.length })));
  }

  for (const a of lista) {
    // Un boton y no un div: se navega con teclado y lo anuncia el lector
    // de pantalla como lo que es, algo que se puede abrir.
    const fila = nodo("button", "fila-ataque");
    fila.type = "button";

    const sev = nodo("span", `sev sev-${a.severidad}`, nombreSev(a.severidad));
    fila.appendChild(sev);

    const texto = nodo("div", "fila-ataque-texto");
    const donde = [a.ip, a.pais, a.isp].filter(Boolean).join(" · ");
    // La etiqueta bot/manual va inline, delante del servicio: asi ocupa solo
    // su texto y no rompe la rejilla de tres columnas de la fila.
    if (a.automatismo) {
      const chip = nodo("span", `chip-origen origen-${a.automatismo}`, t("auto." + a.automatismo));
      if (a.automatismo === "manual") chip.title = t("auto.manual.tip");
      texto.appendChild(chip);
    }
    texto.appendChild(nodo("strong", null, `${a.protocolo} — ${donde}`));
    texto.appendChild(nodo("span", "sub", a.resumen));
    fila.appendChild(texto);

    const esNuevo = corteNovedades && new Date(a.fin).getTime() > corteNovedades;
    if (esNuevo) fila.classList.add("nuevo");
    const cuando = nodo("span", "fila-ataque-cuando", hace(a.fin));
    if (esNuevo) {
      cuando.appendChild(document.createTextNode(" · "));
      cuando.appendChild(nodo("span", "insignia-nuevo", t("ataque.nuevo")));
    }
    fila.appendChild(cuando);
    fila.addEventListener("click", () => abrirAtaque(a.clave));
    cont.appendChild(fila);
  }
}

// claveAbierta recuerda que ataque se esta mirando, para que el boton de
// explicar sepa sobre cual preguntar.
let claveAbierta = null;

// esperarExplicacion muestra "generando..." y sondea hasta que la explicacion
// que se cocina en segundo plano esta lista, para pintarla en el sitio sin que
// haya que reabrir. Se detiene si cierras el dialogo o si tarda demasiado.
function esperarExplicacion(idCaja, tipo, clave, idDialogo, mensaje) {
  const dlg = $(idDialogo);
  pintarExplicacion(idCaja, mensaje || t("expl.pendiente"));
  // Se sigue esperando mientras el dialogo este abierto: en cuanto el barredor
  // la genera, aparece sola. Se corta al cerrar.
  const iv = setInterval(async () => {
    if (!dlg.open) { clearInterval(iv); return; }
    try {
      const r = await pedirJSON(
        `/api/explicacion?tipo=${encodeURIComponent(tipo)}&clave=${encodeURIComponent(clave)}&idioma=${IDIOMA}`);
      if (r.explicacion) {
        clearInterval(iv);
        pintarExplicacion(idCaja, r.explicacion);
      }
    } catch (e) { /* reintenta en el siguiente tick */ }
  }, 5000);
}

function pintarExplicacion(idCaja, texto) {
  const caja = $(idCaja);
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


let ataqueAbierto = null;
async function abrirAtaque(clave) {
  const d = await pedirJSON(`/api/episodio?clave=${encodeURIComponent(clave)}&idioma=${IDIOMA}`);
  const dlg = $("dialogo-ataque");
  claveAbierta = clave;
  // Si ya se explico una vez, se ensena sin volver a preguntar: la
  // explicacion de un ataque terminado no cambia por reabrir el dialogo.
  pintarExplicacion("ataque-explicacion", d.explicacion);
  if (!d.explicacion && d.pendiente) {
    // El detalle paso a paso ya esta debajo (narracion + glosas de memoria);
    // solo falta el resumen global de la IA. Que el aviso lo diga.
    const hayPasos = (d.pasos || []).length > 0;
    esperarExplicacion("ataque-explicacion", "ataque", clave, "dialogo-ataque",
      hayPasos ? t("expl.pendiente.pasos") : t("expl.pendiente"));
  }

  const titulo = $("ataque-titulo");
  titulo.replaceChildren();
  titulo.appendChild(nodo("span", null, `${d.protocolo} desde `));
  const enlaceIP = nodo("button", "enlace-ip", d.ip);
  enlaceIP.type = "button";
  enlaceIP.title = "Ver la ficha de esta IP";
  enlaceIP.addEventListener("click", () => abrirIP(d.ip).catch((e) => {
    $("ataque-sub").textContent = t("ip.nofichar", { msg: e.message });
  }));
  titulo.appendChild(enlaceIP);
  const donde = [d.pais, d.isp].filter(Boolean).join(" · ");
  const rep = d.reputacion > 0 ? ` · reputacion ${d.reputacion}/100` : "";
  $("ataque-sub").textContent = `${donde}${rep} — ${d.resumen}`;

  ataqueAbierto = d;
  const cuerpo = $("ataque-cuerpo");
  pintarPasos(cuerpo, d);
  dlg.showModal();
}

// pintarPasos dibuja la secuencia narrada del ataque (la vista estatica).
function pintarPasos(cuerpo, d) {
  cuerpo.replaceChildren();
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
    if (p.glosa) {
      const g = nodo("span", "paso-glosa");
      g.appendChild(nodo("span", "paso-glosa-icono", "\ud83d\udca1"));
      g.appendChild(nodo("span", null, p.glosa));
      texto.appendChild(g);
    } else if (p.nota) {
      const nota = nodo("span", "paso-nota");
      nota.appendChild(nodo("strong", null, p.nota.que));
      if (p.nota.por) nota.appendChild(nodo("span", null, ` — ${p.nota.por}`));
      texto.appendChild(nota);
    }
    if (p.crudo && !p.texto.includes(p.crudo)) {
      const pre = nodo("pre", "paso-crudo");
      pre.textContent = p.crudo;
      texto.appendChild(pre);
    }
    fila.appendChild(texto);
    cuerpo.appendChild(fila);
  }
  if (!(d.pasos || []).length) {
    cuerpo.appendChild(nodo("p", "vacio", t("det.purgado")));
  }
}


// ── Subir la base GeoIP ─────────────────────────────────────────────────

// El fichero .mmdb ronda los 60 MB. Se envia como cuerpo crudo del POST -no
// multipart- para no duplicarlo en memoria montando un formulario: el
// servidor lo copia a disco segun llega.
async function subirGeoIP(fichero) {
  const estado = $("estado-geoip");
  const boton = $("subir-geoip");
  boton.disabled = true;
  estado.textContent = t("subiendo", { mb: (fichero.size / 1048576).toFixed(0) });
  try {
    const resp = await fetch("/api/geoip", { method: "POST", body: fichero });
    const r = await resp.json();
    if (!resp.ok) throw new Error(r.error || `respondio ${resp.status}`);
    $("c-ruta-geoip").value = r.ruta;
    estado.textContent = t("geoip.cargada", { tipo: r.tipo, aviso: r.aviso });
  } catch (e) {
    estado.textContent = t("geoip.nosubir", { msg: e.message });
  } finally {
    boton.disabled = false;
  }
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

  // El zoom es MOVER el viewBox, no escalar la imagen: el dibujo sigue
  // siendo vectorial -no se pixela- y las coordenadas del SVG no cambian,
  // asi que el clic sigue convirtiendose igual sin tocar nada mas. La vista
  // es la parte del mapa que se ve; empieza en el mapa entero.
  const vista = { x: 0, y: 0, w: m.ancho, h: m.alto };
  const ZOOM_MAX = 40;     // cuanto se puede acercar respecto al mapa entero
  const aplicarVista = () => {
    lienzo.setAttribute("viewBox", `${vista.x} ${vista.y} ${vista.w} ${vista.h}`);
    // El radio de la marca se encoge al acercar: un circulo de 7 unidades
    // sobre una vista de medio pais taparia media region.
    const escala = vista.w / m.ancho;
    marca.querySelectorAll("circle").forEach((c, i) => {
      c.setAttribute("r", (i === 0 ? 7 : 3) * Math.max(escala, 0.05));
    });
  };

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
    aplicarVista();
  };

  // pixelAMapa convierte la posicion del raton a coordenadas del SVG
  // teniendo en cuenta el zoom: se parte de la VISTA, no del mapa entero.
  const pixelAMapa = (ev) => {
    const c = lienzo.getBoundingClientRect();
    return [
      vista.x + ((ev.clientX - c.left) / c.width) * vista.w,
      vista.y + ((ev.clientY - c.top) / c.height) * vista.h,
    ];
  };

  // arrastrar distingue un clic de situar de un arrastre para desplazar: si
  // el raton se movio mas de unos pocos pixeles entre pulsar y soltar, era
  // un desplazamiento y no hay que mover la marca.
  let inicio = null;
  lienzo.addEventListener("pointerdown", (ev) => {
    inicio = { px: ev.clientX, py: ev.clientY, vx: vista.x, vy: vista.y, movido: false };
    lienzo.setPointerCapture(ev.pointerId);
  });
  lienzo.addEventListener("pointermove", (ev) => {
    if (!inicio) return;
    const c = lienzo.getBoundingClientRect();
    const dx = (ev.clientX - inicio.px) / c.width * vista.w;
    const dy = (ev.clientY - inicio.py) / c.height * vista.h;
    if (Math.abs(ev.clientX - inicio.px) + Math.abs(ev.clientY - inicio.py) > 4) {
      inicio.movido = true;
    }
    vista.x = acotar(inicio.vx - dx, 0, m.ancho - vista.w);
    vista.y = acotar(inicio.vy - dy, 0, m.alto - vista.h);
    aplicarVista();
  });
  lienzo.addEventListener("pointerup", (ev) => {
    const fue = inicio;
    inicio = null;
    if (!fue || fue.movido) return; // era un arrastre, no un clic
    const [x, y] = pixelAMapa(ev);
    const [lat, lon] = delLienzo(x, y, m);
    $("c-latitud").value = lat.toFixed(4);
    $("c-longitud").value = lon.toFixed(4);
    situar();
  });

  // La rueda hace zoom sobre el punto donde esta el raton, que es lo que uno
  // espera: acercarse a lo que se esta mirando, no al centro.
  lienzo.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const [fx, fy] = pixelAMapa(ev);
    const factor = ev.deltaY < 0 ? 0.8 : 1.25;
    const nuevoW = acotar(vista.w * factor, m.ancho / ZOOM_MAX, m.ancho);
    const nuevoH = nuevoW * (m.alto / m.ancho);
    // Se mantiene el punto bajo el raton fijo mientras cambia el zoom.
    vista.x = acotar(fx - (fx - vista.x) * (nuevoW / vista.w), 0, m.ancho - nuevoW);
    vista.y = acotar(fy - (fy - vista.y) * (nuevoH / vista.h), 0, m.alto - nuevoH);
    vista.w = nuevoW;
    vista.h = nuevoH;
    aplicarVista();
  }, { passive: false });

  // Botones de zoom, para quien no tenga rueda o este en tactil.
  const zoom = (factor) => {
    const cx = vista.x + vista.w / 2;
    const cy = vista.y + vista.h / 2;
    const nuevoW = acotar(vista.w * factor, m.ancho / ZOOM_MAX, m.ancho);
    const nuevoH = nuevoW * (m.alto / m.ancho);
    vista.x = acotar(cx - nuevoW / 2, 0, m.ancho - nuevoW);
    vista.y = acotar(cy - nuevoH / 2, 0, m.alto - nuevoH);
    vista.w = nuevoW;
    vista.h = nuevoH;
    aplicarVista();
  };
  $("zoom-mas").addEventListener("click", () => zoom(0.6));
  $("zoom-menos").addEventListener("click", () => zoom(1 / 0.6));
  $("zoom-reset").addEventListener("click", () => {
    Object.assign(vista, { x: 0, y: 0, w: m.ancho, h: m.alto });
    aplicarVista();
  });

  for (const id of ["c-latitud", "c-longitud", "c-pais"]) {
    $(id).addEventListener("input", situar);
  }
  $("subir-geoip").addEventListener("click", () => $("f-geoip").click());
$("f-geoip").addEventListener("change", (ev) => {
  const f = ev.target.files[0];
  if (f) subirGeoIP(f);
  ev.target.value = ""; // permite volver a subir el mismo fichero
});
$("quitar-ubicacion").addEventListener("click", () => {
    $("c-latitud").value = 0;
    $("c-longitud").value = 0;
    situar();
  });

  situar();
}

// acotar limita un valor a un rango. Se usa para no dejar que la vista del
// mapa se salga de sus bordes.
function acotar(v, min, max) {
  return Math.min(Math.max(v, min), max);
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
    ? t("pill.con", { n: n.total, g: n.graves, sev: t(n.graves > 1 ? "pill.graveN" : "pill.grave1") })
    : t("pill.solo", { n: n.total });
  chip.title = t("pill.title", { fecha: new Date(n.desde).toLocaleString(IDIOMA) });
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
  const cual = ["ntfy", "telegram", "webhook"].includes(canal) ? canal : "ntfy";
  const titulo = t("cfg.av.dst." + cual);
  const ayuda = t("cfg.av.dst." + cual + ".ayuda");
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
  estado.textContent = t("aviso.enviando");
  try {
    // Se guardan los ajustes primero: probar con lo que hay en pantalla y
    // no con lo guardado daria un resultado que no se corresponde con lo
    // que hara el servicio luego.
    await guardarAjustes();
    const r = await pedirJSON("/api/aviso/probar", { method: "POST" });
    estado.textContent = t("aviso.enviado", { canal: r.enviado });
  } catch (e) {
    estado.textContent = t("aviso.noenviado", { msg: e.message });
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
  if (dias < 1) return t("lleva.mismodia");
  if (dias < 2) return t("lleva.undia");
  return t("lleva.dias", { n: Math.round(dias) });
}

// pintarLineaVida traza cuando estuvo activa la IP: un ataque por marca en
// una barra que va de su primera a su ultima aparicion, coloreado por
// gravedad. Con un solo ataque no hay linea que trazar, asi que se oculta.
function pintarLineaVida(p) {
  const cont = $("ip-linea");
  cont.replaceChildren();
  const ataques = (p.ataques || []).filter((a) => a.inicio);
  if (ataques.length < 2) {
    cont.hidden = true;
    return;
  }
  cont.hidden = false;
  const ini = new Date(p.vista).getTime();
  const fin = new Date(p.ultima_vez).getTime();
  const span = Math.max(fin - ini, 1);
  cont.appendChild(nodo("p", "sub",
    t("ip.vida.intro", { dias: Math.max(1, Math.round(span / 86400000)) })));
  const track = nodo("div", "vida-track");
  for (const a of ataques) {
    const pct = ((new Date(a.inicio).getTime() - ini) / span) * 100;
    const marca = nodo("span", `vida-marca sev-${a.severidad}`);
    // Posicion por CSSOM: la CSP bloquea el atributo style en linea.
    marca.style.left = `${Math.min(100, Math.max(0, pct))}%`;
    marca.title = `${nombreSev(a.severidad)} · ${new Date(a.inicio).toLocaleString(IDIOMA)}`;
    track.appendChild(marca);
  }
  cont.appendChild(track);
  const ejes = nodo("div", "vida-ejes");
  ejes.appendChild(nodo("span", null, new Date(ini).toLocaleDateString(IDIOMA)));
  ejes.appendChild(nodo("span", null, new Date(fin).toLocaleDateString(IDIOMA)));
  cont.appendChild(ejes);
}

async function abrirIP(ip) {
  const p = await pedirJSON(`/api/ip?ip=${encodeURIComponent(ip)}&idioma=${IDIOMA}`);
  $("dialogo-ataque").close();

  $("ip-titulo").textContent = p.ip;
  const donde = [p.origen.pais, p.origen.isp, p.origen.tipo_uso].filter(Boolean);
  $("ip-sub").textContent = donde.join(" · ") || t("ip.sindatos");

  // El veredicto va arriba y en una frase: es lo que distingue a un
  // escaner de paso de alguien que insiste, que es para lo que se abre
  // una ficha.
  const caja = $("ip-veredicto");
  caja.replaceChildren();
  const frases = [];
  if (p.episodios > 1) {
    frases.push(t("ip.volvio", { n: p.episodios, cuando: cuantoLleva(p.vista, p.ultima_vez) }));
  } else {
    frases.push(t("ip.unica"));
  }
  if (p.llego_a_entrar) frases.push(t("ip.entro"));
  if (p.escalo) frases.push(t("ip.escalo"));
  if (p.nota_proveedor) {
    frases.push(`${p.nota_proveedor.que}: ${p.nota_proveedor.por}.`);
  }
  caja.appendChild(nodo("p", null, frases.join(" ")));
  caja.hidden = false;

  const datos = $("ip-datos");
  datos.replaceChildren();
  datos.appendChild(dato(t("dato.primera"), new Date(p.vista).toLocaleString(IDIOMA)));
  datos.appendChild(dato(t("dato.ultima"), hace(p.ultima_vez)));
  datos.appendChild(dato(t("dato.ataquescount"), String(p.episodios)));
  datos.appendChild(dato(t("dato.eventos"), String(p.eventos)));
  datos.appendChild(dato(t("dato.servicios"), (p.servicios || []).join(", ") || "—"));
  datos.appendChild(dato(t("dato.peor"), nombreSev(p.peor_hasta),
    p.peor_hasta === "intrusion" || p.peor_hasta === "acceso"));
  if (p.origen.reputacion) {
    datos.appendChild(dato(t("dato.reputacion"), `${p.origen.reputacion}/100`, p.origen.reputacion >= 75));
  }
  if (p.origen.total_reportes) {
    datos.appendChild(dato(t("dato.denuncias"), String(p.origen.total_reportes)));
  }
  if (p.origen.tor) datos.appendChild(dato(t("dato.red"), t("dato.tor"), true));

  pintarLineaVida(p);

  const lista = $("ip-ataques");
  lista.replaceChildren();
  lista.appendChild(nodo("p", "sub", t("ip.ataques.intro")));
  for (const a of p.ataques || []) {
    const fila = nodo("button", "fila-ataque");
    fila.type = "button";
    fila.appendChild(nodo("span", `sev sev-${a.severidad}`, nombreSev(a.severidad)));
    const texto = nodo("div", "fila-ataque-texto");
    texto.appendChild(nodo("strong", null, `${a.protocolo} — ${new Date(a.inicio).toLocaleString(IDIOMA)}`));
    texto.appendChild(nodo("span", "sub", a.resumen));
    fila.appendChild(texto);
    fila.appendChild(nodo("span", "fila-ataque-cuando", hace(a.fin)));
    fila.addEventListener("click", () => { $("dialogo-ip").close(); abrirAtaque(a.clave); });
    lista.appendChild(fila);
  }

  $("dialogo-ip").showModal();
}

// ── Campanas y artefactos ───────────────────────────────────────────────

function queCompartenTxt(tipo) {
  return t("comparten." + tipo);
}

let campanasCargadas = [];
async function cargarCampanas() {
  const lista = await traer("/api/campanas");
  campanasCargadas = lista;
  const cont = $("campanas");
  cont.replaceChildren();

  // El bloque entero se oculta cuando no hay nada: una campana solo aparece
  // si de verdad delata una operacion coordinada. A bajo trafico eso es
  // raro, y un cuadro vacio permanente ocupa sitio sin decir nada.
  const seccion = document.querySelector(".bloque-campanas");
  if (!lista.length) {
    if (seccion) seccion.hidden = true;
    return;
  }
  if (seccion) seccion.hidden = false;

  for (const c of lista) {
    const fila = nodo("div", "campana");
    fila.appendChild(nodo("span", `sev sev-${c.severidad}`, c.severidad));

    const que = nodo("div", "campana-que");
    que.appendChild(nodo("strong", null, queCompartenTxt(c.tipo)));
    que.appendChild(nodo("code", null, c.muestra));
    fila.appendChild(que);

    const paises = (c.paises || []).length ? ` · ${c.paises.join(" ")}` : "";
    fila.appendChild(nodo("span", "campana-alcance",
      t("camp.alcance", { ips: c.ips.length, paises })));
    // Pulsable: abre el detalle con los ataques que la componen.
    fila.classList.add("pulsable");
    fila.addEventListener("click", () => abrirCampana(c));
    cont.appendChild(fila);
  }
}

// abrirCampana muestra el guion compartido y LOS ATAQUES que forman la
// campana; cada uno abre su detalle -evento a evento- reaprovechando el
// dialogo de ataque. Asi el "proceso" de la operacion sale de encadenar lo
// que ya existe, sin duplicar nada.
// pintarSecuenciaCampana ensena lo que DE VERDAD comparten los ataques de
// una campana: la secuencia entera de comandos, el diccionario, las rutas o
// el fichero. Es el paso de "estas IPs" a "esto es lo que hacen".
function pintarSecuenciaCampana(cont, tipo, rep, fichero) {
  cont.replaceChildren();
  cont.hidden = false;
  cont.appendChild(nodo("p", "sub", t("camp.secuencia." + tipo)));
  if (tipo === "comandos") {
    const pre = nodo("pre", "secuencia");
    pre.textContent = (rep.comandos || []).map((c) => "$ " + c).join("\n") || "—";
    cont.appendChild(pre);
  } else if (tipo === "rutas") {
    const pre = nodo("pre", "secuencia");
    pre.textContent = (rep.rutas || []).join("\n") || "—";
    cont.appendChild(pre);
  } else if (tipo === "credenciales") {
    cont.appendChild(dato(t("camp.usuarios"), (rep.usuarios || []).join(", ") || "—"));
    cont.appendChild(dato(t("camp.contrasenas"), (rep.passwords || []).join(", ") || "—"));
  } else if (tipo === "descarga") {
    for (const u of rep.descargas || []) cont.appendChild(nodo("code", "url-descarga", u));
  }
  if (fichero) {
    // Enlaza la campana de descarga con el binario capturado: un clic para
    // pasar de "se traen esto de aqui" a ver que era en realidad.
    const link = nodo("button", "enlace-fichero");
    link.type = "button";
    link.textContent = t("camp.verfichero");
    link.addEventListener("click", () => { $("dialogo-campana").close(); abrirArtefacto(fichero); });
    cont.appendChild(link);
  }
}

let campanaAbierta = null;

async function abrirCampana(c) {
  campanaAbierta = { tipo: c.tipo, huella: c.huella };
  pintarExplicacion("campana-explicacion", "");
  const paises = (c.paises || []).length ? ` · ${c.paises.join(" ")}` : "";
  $("campana-titulo").textContent = queCompartenTxt(c.tipo);
  $("campana-sub").textContent = t("camp.sub", { ips: c.ips.length, paises, eps: c.episodios });

  const muestra = $("campana-muestra");
  muestra.replaceChildren();
  if (c.muestra) {
    muestra.hidden = false;
    muestra.appendChild(nodo("code", null, c.muestra));
  } else {
    muestra.hidden = true;
  }

  const datos = $("campana-datos");
  datos.replaceChildren();
  datos.appendChild(dato(t("dato.gravedad"), c.severidad));
  datos.appendChild(dato(t("dato.primera"), new Date(c.desde).toLocaleString(IDIOMA)));
  datos.appendChild(dato(t("dato.ultima"), new Date(c.hasta).toLocaleString(IDIOMA)));
  if ((c.paises || []).length) datos.appendChild(dato(t("dato.paises"), c.paises.join(" ")));
  datos.appendChild(dato(t("dato.direcciones"), c.ips.join(", ")));

  const lista = $("campana-ataques");
  lista.replaceChildren();
  lista.appendChild(nodo("p", "sub", t("dlg.cargando.ataques")));
  $("dialogo-campana").showModal();

  let resp = { episodios: [] };
  try {
    resp = await pedirJSON(
      `/api/campana?tipo=${encodeURIComponent(c.tipo)}` +
      `&huella=${encodeURIComponent(c.huella)}&dias=${encodeURIComponent(rango())}&idioma=${IDIOMA}`);
  } catch (e) {
    lista.replaceChildren(nodo("p", "sub", t("dlg.nocargar", { msg: e.message })));
    return;
  }
  pintarExplicacion("campana-explicacion", resp.explicacion);
  if (!resp.explicacion && resp.pendiente) esperarExplicacion("campana-explicacion", "campana", `${c.tipo}|${c.huella}`, "dialogo-campana");
  // La muestra recortada se sustituye por la secuencia COMPLETA compartida.
  pintarSecuenciaCampana($("campana-muestra"), c.tipo, (resp.episodios || [])[0] || {}, resp.fichero);

  lista.replaceChildren();
  lista.appendChild(nodo("p", "sub",
    t("camp.ataques.intro")));
  for (const a of resp.episodios || []) {
    const fila = nodo("button", "fila-ataque");
    fila.type = "button";
    fila.appendChild(nodo("span", `sev sev-${a.severidad}`, nombreSev(a.severidad)));
    const texto = nodo("div", "fila-ataque-texto");
    texto.appendChild(nodo("strong", null, `${a.ip} · ${a.protocolo}`));
    texto.appendChild(nodo("span", "sub", a.resumen));
    fila.appendChild(texto);
    fila.appendChild(nodo("span", "fila-ataque-cuando", hace(a.fin)));
    fila.addEventListener("click", () => { $("dialogo-campana").close(); abrirAtaque(a.clave); });
    lista.appendChild(fila);
  }
}

function tamano(bytes) {
  if (!bytes) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function deltaTendencia(actual, previo) {
  if (previo === 0) return actual > 0 ? { texto: t("tend.nuevo"), clase: "sube" } : { texto: "—", clase: "" };
  const pct = Math.round(((actual - previo) / previo) * 100);
  if (pct > 0) return { texto: `▲ ${pct}%`, clase: "sube" };
  if (pct < 0) return { texto: `▼ ${Math.abs(pct)}%`, clase: "baja" };
  return { texto: t("tend.igual"), clase: "" };
}
function pintarTendencia(id, etiqueta, m) {
  const cont = $(id);
  cont.replaceChildren();
  cont.appendChild(nodo("span", "tend-cifra", (m.actual || 0).toLocaleString(IDIOMA)));
  cont.appendChild(nodo("span", "tend-etiqueta", etiqueta));
  const d = deltaTendencia(m.actual || 0, m.previo || 0);
  const delta = nodo("span", `tend-delta ${d.clase}`, d.texto);
  delta.title = t("tend.previo", { n: (m.previo || 0).toLocaleString(IDIOMA) });
  cont.appendChild(delta);
}
async function cargarTendencias() {
  const d = await traer("/api/tendencias");
  const seccion = document.querySelector(".bloque-tendencias");
  if (seccion) seccion.hidden = false;
  pintarTendencia("tend-ataques", t("tend.ataques"), d.ataques || {});
  pintarTendencia("tend-intrusiones", t("tend.intrusiones"), d.intrusiones || {});
  pintarTendencia("tend-malware", t("tend.malware"), d.malware || {});
}

// cargarRadar pinta el radar: ficheros nunca vistos y sesiones a revisar.
// Es el bloque que corta el ruido -si esta vacio, no molesta-.
async function cargarRadar() {
  const r = await traer("/api/radar");
  const cont = $("radar");
  cont.replaceChildren();
  const seccion = document.querySelector(".bloque-radar");
  const malware = r.malware || [], manual = r.manual || [];
  if (!malware.length && !manual.length) {
    if (seccion) seccion.hidden = true;
    return;
  }
  if (seccion) seccion.hidden = false;

  if (malware.length) {
    cont.appendChild(nodo("p", "novedades-titulo", t("novedades.malware", { n: malware.length })));
    for (const m of malware) {
      const caja = nodo("button", "novedad pulsable");
      caja.type = "button";
      caja.appendChild(nodo("span", "novedad-icono", "🧬"));
      const txt = nodo("div", "novedad-texto");
      txt.appendChild(nodo("code", null, m.sha256.slice(0, 24) + "…"));
      const sub = [];
      if (m.ips) sub.push(`${m.ips} IP${m.ips > 1 ? "s" : ""}`);
      if (m.primera) sub.push(hace(m.primera));
      txt.appendChild(nodo("span", "sub", sub.join(" · ")));
      caja.appendChild(txt);
      caja.addEventListener("click", () => abrirArtefacto(m.sha256));
      cont.appendChild(caja);
    }
  }
  if (manual.length) {
    cont.appendChild(nodo("p", "novedades-titulo", t("novedades.manual", { n: manual.length })));
    for (const s of manual) {
      const caja = nodo("button", "novedad pulsable");
      caja.type = "button";
      caja.appendChild(nodo("span", "novedad-icono", "👁"));
      const txt = nodo("div", "novedad-texto");
      txt.appendChild(nodo("strong", null, `${s.protocolo} — ${s.ip}`));
      txt.appendChild(nodo("span", "sub", s.resumen));
      caja.appendChild(txt);
      caja.addEventListener("click", () => abrirAtaque(s.clave));
      cont.appendChild(caja);
    }
  }
}

async function cargarArtefactos() {
  const lista = await traer("/api/artefactos");
  const cont = $("artefactos");
  cont.replaceChildren();

  // Se oculta el bloque entero mientras nadie descargue nada: es lo normal
  // durante mucho tiempo, y un cuadro vacio permanente descuadra la fila.
  const seccion = document.querySelector(".bloque-artefactos");
  if (!lista.length) {
    if (seccion) seccion.hidden = true;
    return;
  }
  if (seccion) seccion.hidden = false;

  for (const a of lista) {
    const caja = nodo("div", "artefacto");
    caja.appendChild(nodo("code", null, a.url || a.fichero));

    const partes = [];
    if (a.ips?.length) partes.push(`${a.ips.length} IP${a.ips.length > 1 ? "s" : ""}`);
    if (a.bytes) partes.push(tamano(a.bytes));
    // Cowrie nombra los ficheros con el SHA-256 de su contenido, asi que
    // el nombre sirve tal cual para consultarlo sin subir la muestra.
    if (a.fichero && !a.url) partes.push(t("artef.sha"));
    if (a.momento) partes.push(hace(a.momento));
    // Etiqueta clara: un fichero capturado se abre; una URL es un intento
    // -del que a veces sí salió fichero-. Asi se entiende por que unos se
    // pueden abrir y otros no.
    const esFichero = a.fichero && RE_HASH_ARTEFACTO.test(a.fichero);
    if (esFichero) partes.push(t("artef.abrible"));
    else if (a.url) partes.push(a.fichero_de ? t("artef.capturo") : t("artef.intento"));
    caja.appendChild(nodo("span", "sub", partes.join(" · ")));
    if (esFichero) {
      caja.classList.add("pulsable");
      caja.addEventListener("click", () => abrirArtefacto(a.fichero));
    } else if (a.url) {
      caja.classList.add("pulsable");
      caja.addEventListener("click", () => abrirArtefactoURL(a));
    }
    cont.appendChild(caja);
  }
}


const RE_HASH_ARTEFACTO = /^[a-f0-9]{64}$/;
let hashArtefactoAbierto = null;
let urlArtefactoAbierta = null;

// abrirArtefactoURL abre la ficha de un INTENTO de descarga sin fichero: no
// hay bytes que revisar, pero si de donde venia, quien la pidio y -si la
// tenemos- el fichero que dejo. La IA explica que suele ser esa direccion.
async function abrirArtefactoURL(a) {
  urlArtefactoAbierta = { url: a.url, ips: (a.ips || []).length };
  hashArtefactoAbierto = null;
  $("artefacto-titulo").textContent = t("artef.url.titulo");
  $("artefacto-sub").textContent = a.url;
  $("artefacto-aviso").replaceChildren(nodo("p", null, t("artef.url.aviso")));
  $("descargar-artefacto").hidden = true;
  if (!a.explicacion) {
    // Dispara la explicacion en segundo plano y la espera en el sitio.
    pedirJSON(`/api/artefacto/url-fondo?url=${encodeURIComponent(a.url)}&ips=${(a.ips || []).length}&idioma=${IDIOMA}`,
      { method: "POST" })
      .then((r) => { if (r && r.pendiente) esperarExplicacion("artefacto-explicacion", "url", a.url, "dialogo-artefacto"); })
      .catch(() => {});
  }

  const datos = $("artefacto-datos");
  datos.replaceChildren();
  if (a.ips?.length) datos.appendChild(dato(t("dato.trajeron"), a.ips.join(", ")));
  if (a.momento) datos.appendChild(dato(t("dato.ultima"), new Date(a.momento).toLocaleString(IDIOMA)));
  if (a.fichero_de) {
    const link = nodo("button", "enlace-fichero", t("artef.url.verfichero"));
    link.type = "button";
    link.addEventListener("click", () => abrirArtefacto(a.fichero_de));
    datos.appendChild(link);
  }
  $("artefacto-cadenas").replaceChildren();
  pintarExplicacion("artefacto-explicacion", a.explicacion || "");
  $("dialogo-artefacto").showModal();
}

// abrirArtefacto muestra la ficha de una muestra capturada: que es, sus
// cadenas de texto internas y quien la trajo, y permite descargarla como
// fichero inerte para analizarla aparte. Nunca la ejecuta.
async function abrirArtefacto(hash) {
  urlArtefactoAbierta = null;
  $("descargar-artefacto").hidden = false;
  $("artefacto-titulo").textContent = t("artef.titulo");
  $("artefacto-sub").textContent = hash;

  const aviso = $("artefacto-aviso");
  aviso.replaceChildren(nodo("p", null,
t("artef.aviso")));

  hashArtefactoAbierto = hash;
  // Abrirlo lo convierte en "visto": deja de ser novedad y se refresca el radar.
  pedirJSON(`/api/artefacto/visto?hash=${encodeURIComponent(hash)}`, { method: "POST" })
    .then(() => cargarRadar())
    .catch(() => {});
  pintarExplicacion("artefacto-explicacion", "");

  const datos = $("artefacto-datos");
  datos.replaceChildren(nodo("p", "sub", t("cargando")));
  const cadenas = $("artefacto-cadenas");
  cadenas.replaceChildren();

  // La descarga va por un enlace con la cookie de sesion; el servidor la
  // entrega como adjunto inerte (nunca se ejecuta ni se interpreta).
  $("descargar-artefacto").onclick = () => {
    const a = document.createElement("a");
    a.href = `/api/artefacto/contenido?hash=${encodeURIComponent(hash)}`;
    a.rel = "noopener";
    a.click();
  };

  $("dialogo-artefacto").showModal();

  let d;
  try {
    d = await pedirJSON(`/api/artefacto?hash=${encodeURIComponent(hash)}`);
  } catch (e) {
    datos.replaceChildren(nodo("p", "sub", t("dlg.nocargar", { msg: e.message })));
    return;
  }

  datos.replaceChildren();
  datos.appendChild(dato(t("dato.tipo"), d.tipo));
  datos.appendChild(dato(t("dato.tamano"), tamano(d.bytes)));
  datos.appendChild(dato("SHA-256", d.sha256));
  // VirusTotal: veredicto por hash si hay clave, y enlace siempre.
  let vtTexto = "";
  if (d.vt && d.vt.conocido) {
    vtTexto = t(d.vt.maliciosos > 0 ? "artef.vt.detectado" : "artef.vt.limpio",
      { n: d.vt.maliciosos, total: d.vt.total });
    if (d.vt.etiqueta) vtTexto += ` · ${d.vt.etiqueta}`;
  } else if (d.vt) {
    vtTexto = t("artef.vt.desconocido");
  }
  const vtFila = dato("VirusTotal", vtTexto);
  const vtLink = nodo("a", "vt-link", t("artef.vt.ver"));
  vtLink.href = `https://www.virustotal.com/gui/file/${encodeURIComponent(d.sha256)}`;
  vtLink.target = "_blank";
  vtLink.rel = "noopener";
  vtFila.appendChild(vtLink);
  datos.appendChild(vtFila);
  if (d.urls?.length) datos.appendChild(dato(t("dato.origen"), d.urls.join("  ")));
  if (d.ips?.length) datos.appendChild(dato(t("dato.trajeron"), d.ips.join(", ")));
  if (d.primera) datos.appendChild(dato(t("dato.primera"), new Date(d.primera).toLocaleString(IDIOMA)));

  cadenas.replaceChildren();
  if (d.vista) {
    // Es texto (un script): se lee tal cual, que ensena mucho mas que unas
    // cadenas sueltas. textContent, nunca innerHTML: no se interpreta nada.
    cadenas.appendChild(nodo("p", "sub", t("artef.contenido.intro")));
    const pre = nodo("pre", "cadenas-artefacto");
    pre.textContent = d.vista;
    cadenas.appendChild(pre);
  } else if (d.cadenas?.length) {
    cadenas.appendChild(nodo("p", "sub", t("artef.cadenas.intro")));
    const pre = nodo("pre", "cadenas-artefacto");
    pre.textContent = d.cadenas.join("\n");
    cadenas.appendChild(pre);
  } else {
    cadenas.appendChild(nodo("p", "sub", t("artef.cadenas.vacio")));
  }

  pintarExplicacion("artefacto-explicacion", d.explicacion);
  if (!d.explicacion && d.pendiente) esperarExplicacion("artefacto-explicacion", "artefacto", hash, "dialogo-artefacto");
}

// Explica con IA que es y que hace la muestra. Igual que en ataques: POST,
// gasta cuota, y el resultado se guarda por el hash.

// pintarGravedad dibuja las barras de ataques por gravedad. Es el reparto
// que resume el negocio de k0Pot: mucho ruido, y estrechandose hasta la
// intrusion. El maximo escala las barras; sin datos, no se pinta nada.
function pintarGravedad(severidades) {
  const cont = $("grafica-gravedad");
  cont.replaceChildren();

  const orden = [
    ["intrusion", t("grav.intrusion")],
    ["acceso", t("grav.acceso")],
    ["tanteo", t("grav.tanteo")],
    ["roce", t("grav.roce")],
  ];
  const cuenta = (k) => severidades?.[k] || 0;
  const total = orden.reduce((s, [k]) => s + cuenta(k), 0);
  if (!total) {
    cont.appendChild(nodo("p", "vacio", t("grav.vacio")));
    return;
  }
  const max = Math.max(...orden.map(([k]) => cuenta(k)), 1);

  const barras = nodo("div", "barras-sev");
  for (const [clave, etiqueta] of orden) {
    const n = cuenta(clave);
    const barra = nodo("div", `barra-sev ${clave}`);
    const fila = nodo("div", "fila");
    fila.appendChild(nodo("span", "nombre", etiqueta));
    fila.appendChild(nodo("span", "cuenta", String(n)));
    barra.appendChild(fila);
    const canal = nodo("div", "canal");
    const relleno = nodo("div", "relleno");
    // El ancho por CSSOM: la CSP bloquea el atributo style en linea.
    relleno.style.width = `${(n / max) * 100}%`;
    canal.appendChild(relleno);
    barra.appendChild(canal);
    barras.appendChild(barra);
  }
  cont.appendChild(barras);

  // Cierre: el embudo de las cuatro gravedades en dos bloques, ruido contra
  // lo que de verdad importa. Es lo que separa a k0Pot de mirar un log crudo:
  // casi todo rebota solo, y lo poco que entra queda a la vista.
  const ruido = cuenta("roce") + cuenta("tanteo");
  const serio = cuenta("acceso") + cuenta("intrusion");
  const pctRuido = Math.round((ruido / total) * 100);

  const embudo = nodo("div", "embudo");
  const split = nodo("div", "split");
  const segRuido = nodo("div", "seg ruido");
  segRuido.style.width = `${(ruido / total) * 100}%`;
  const segSerio = nodo("div", "seg serio");
  segSerio.style.width = `${(serio / total) * 100}%`;
  split.appendChild(segRuido);
  split.appendChild(segSerio);
  embudo.appendChild(split);

  const leyenda = nodo("div", "leyenda-split");
  const marca = (clase, texto, n) => {
    const it = nodo("div", `marca ${clase}`);
    it.appendChild(nodo("span", "punto"));
    it.appendChild(nodo("span", "txt", texto));
    it.appendChild(nodo("span", "n", String(n)));
    return it;
  };
  leyenda.appendChild(marca("ruido", t("grav.ruidofondo"), ruido));
  leyenda.appendChild(marca("serio", t("grav.serio"), serio));
  embudo.appendChild(leyenda);

  const frase = serio === 0
    ? t("grav.todoruido", { n: total })
    : t("grav.mixto", { total, pct: pctRuido, serio });
  embudo.appendChild(nodo("p", "nota", frase));
  cont.appendChild(embudo);
}

// cargarAprendizaje pinta el pulso del conocimiento en la cabecera: cuantos
// comandos lleva k0pot aprendidos y, en el titulo, como va la cuota de hoy.
let aprendidasPrevias = null;
async function cargarAprendizaje() {
  try {
    const a = await pedirJSON("/api/aprendizaje");
    const chip = $("aprendizaje-chip");
    if (!a.activo && !a.total) { chip.hidden = true; return; }
    chip.hidden = false;
    // La cuenta SIEMPRE visible; el estado va como sufijo aparte con su color,
    // sin tapar el numero de comandos aprendidos.
    chip.replaceChildren();
    chip.appendChild(nodo("span", "apr-cuenta", t("apr.chip", { n: a.total })));
    let estadoTxt = "", estadoCls = "", titulo = t("apr.chip.activo", { hoy: a.hoy, tope: a.tope });
    if (a.sin_tokens) {
      estadoTxt = t("apr.estado.sintokens"); estadoCls = "sin-tokens";
      titulo = t("apr.chip.sintokens.t");
    } else if (a.generando) {
      estadoTxt = t("apr.estado.generando"); estadoCls = "trabajando";
    } else if (!a.activo) {
      estadoTxt = t("apr.estado.inactivo"); estadoCls = "en-pausa";
      titulo = t("apr.chip.inactivo");
    } else if (a.pausado) {
      estadoTxt = t("apr.estado.pausa"); estadoCls = "en-pausa";
      titulo = t("apr.chip.pausa", { hoy: a.hoy, tope: a.tope });
    }
    if (estadoTxt) {
      chip.appendChild(nodo("span", "apr-estado " + estadoCls, estadoTxt));
    }
    // Tokens del dia en el tooltip (se refresca en cada sondeo). El limite
    // solo se conoce cuando el proveedor lo revela en un 429.
    if (a.tokens_hoy) {
      const fmt = (n) => (n || 0).toLocaleString(IDIOMA);
      titulo += "\n" + (a.tokens_limite
        ? t("apr.tokens", { usados: fmt(a.tokens_hoy), limite: fmt(a.tokens_limite) })
        : t("apr.tokens.solo", { usados: fmt(a.tokens_hoy) }));
    }
    chip.title = titulo;
    // Pulso cuando aprende algo nuevo, para que se vea vivo.
    if (aprendidasPrevias !== null && a.total > aprendidasPrevias) {
      chip.classList.remove("recien");
      void chip.offsetWidth; // reinicia la animacion
      chip.classList.add("recien");
    }
    aprendidasPrevias = a.total;
  } catch (e) { /* silencioso: el indicador no debe romper el refresco */ }
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
      cargarRadar(),
      cargarTendencias(),
      cargarAprendizaje(),
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

// Idioma: traducir la interfaz estatica y cablear el selector. traducirDOM e
// IDIOMA vienen de idiomas.js, que se carga antes que este fichero.
traducirDOM();
$("idioma").value = IDIOMA;
$("idioma").addEventListener("change", (e) => cambiarIdioma(e.target.value));
$("tema").addEventListener("click", () => {
  aplicarTema(document.documentElement.dataset.tema === "claro" ? "oscuro" : "claro");
});

$("rango").addEventListener("change", refrescar);
// El informe se abre en otra pestana: es un documento para revisar e
// imprimir, no algo que sustituya al panel. Lleva el periodo seleccionado.
$("descargar-blocklist").addEventListener("click", () => {
  window.open(`/api/blocklist?dias=${encodeURIComponent(rango())}`, "_blank", "noopener");
});
$("generar-informe").addEventListener("click", () => {
  window.open(`/api/reporte?dias=${encodeURIComponent(rango())}&idioma=${IDIOMA}`, "_blank", "noopener");
});
$("cerrar-ataque").addEventListener("click", () => $("dialogo-ataque").close());

// ── Asistente: preguntar a la IA sobre el honeypot ──────────────────────
const historialAsistente = [];
function mensajeAsistente(rol, texto) {
  const hilo = $("asistente-hilo");
  const msg = nodo("div", `asis-msg asis-${rol}`);
  msg.textContent = texto;
  hilo.appendChild(msg);
  hilo.scrollTop = hilo.scrollHeight;
  return msg;
}
async function preguntarAsistente(ev) {
  ev.preventDefault();
  const input = $("asistente-pregunta");
  const q = input.value.trim();
  if (!q) return;
  input.value = "";
  mensajeAsistente("tu", q);
  const resp = mensajeAsistente("k0pot", t("asis.pensando"));
  resp.classList.add("pensando");
  $("asistente-enviar").disabled = true;
  try {
    // Se manda un poco de hilo para que las repreguntas tengan contexto.
    const hist = historialAsistente.slice(-3)
      .map((h) => `P: ${h.p}\nR: ${h.r}`).join("\n\n");
    const r = await pedirJSON("/api/asistente", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ pregunta: q, historial: hist }),
    });
    resp.classList.remove("pensando");
    resp.textContent = r.respuesta;
    historialAsistente.push({ p: q, r: r.respuesta });
  } catch (e) {
    resp.classList.remove("pensando");
    resp.textContent = t("asis.error", { msg: e.message });
  } finally {
    $("asistente-enviar").disabled = false;
    input.focus();
  }
}
$("abrir-asistente").addEventListener("click", () => {
  $("dialogo-asistente").showModal();
  $("asistente-pregunta").focus();
});
$("cerrar-asistente").addEventListener("click", () => $("dialogo-asistente").close());
$("asistente-form").addEventListener("submit", preguntarAsistente);

// ── Modo aprende: cada concepto, con un caso REAL de esta maquina ────────
// La lista es fija (el temario), pero el "ver un caso real" solo aparece si
// el honeypot ha capturado algo que lo ejemplifica. Asi se aprende sobre lo
// que de verdad ha pasado aqui, no sobre un ejemplo de manual.
const CONCEPTOS_APRENDE = [
  { k: "honeypot", icono: "\ud83c\udf6f" },
  { k: "escaneo", icono: "\ud83d\udd0d", ej: "escaneo" },
  { k: "fuerzabruta", icono: "\ud83d\udd11", ej: "fuerzabruta" },
  { k: "credenciales", icono: "\ud83d\udeaa", ej: "credenciales" },
  { k: "servicios", icono: "\ud83d\udd13", ej: "servicios" },
  { k: "exploit", icono: "\ud83d\udca5", ej: "exploit" },
  { k: "botnet", icono: "\ud83e\udd16", ej: "botnet" },
  { k: "dropper", icono: "\u2b07\ufe0f", ej: "dropper" },
  { k: "cripto", icono: "\u26cf\ufe0f", ej: "cripto" },
  { k: "proxy", icono: "\ud83d\udd00", ej: "proxy" },
  { k: "persistencia", icono: "\ud83d\udd73\ufe0f", ej: "persistencia" },
  { k: "huellas", icono: "\ud83e\uddf9", ej: "huellas" },
  { k: "c2", icono: "\ud83d\udce1" },
]

function casoRealAprende(ej, datos) {
  const v = datos[ej];
  if (!v) return null;
  if (ej === "botnet") {
    const c = campanasCargadas.find((x) => x.huella === v.huella);
    return c ? () => { $("dialogo-aprende").close(); abrirCampana(c); } : null;
  }
  if (ej === "dropper") {
    return () => { $("dialogo-aprende").close(); abrirArtefacto(v); };
  }
  // El resto de conceptos ejemplifican con una IP: se abre su ficha.
  return () => { $("dialogo-aprende").close(); abrirIP(v); };
}

async function abrirAprende() {
  const cont = $("aprende-lista");
  cont.replaceChildren(nodo("p", "sub", t("cargando")));
  $("dialogo-aprende").showModal();
  let datos = {};
  try {
    datos = await pedirJSON("/api/aprende");
  } catch (e) {
    // Sin ejemplos vivos igual se muestra el temario; el fallo no rompe nada.
  }
  cont.replaceChildren();
  for (const c of CONCEPTOS_APRENDE) {
    const tarjeta = nodo("div", "apr-tarjeta");
    const cab = nodo("div", "apr-cab");
    cab.appendChild(nodo("span", "apr-icono", c.icono));
    cab.appendChild(nodo("strong", "apr-titulo", t("apr." + c.k + ".t")));
    tarjeta.appendChild(cab);
    tarjeta.appendChild(nodo("p", "apr-texto", t("apr." + c.k + ".d")));
    const abrir = c.ej ? casoRealAprende(c.ej, datos) : null;
    if (abrir) {
      const enlace = nodo("button", "apr-caso", t("apr.vercaso"));
      enlace.addEventListener("click", abrir);
      tarjeta.appendChild(enlace);
    } else if (c.ej) {
      // Admite ejemplo pero aun no hay: se dice, para que no parezca un fallo
      // -y de paso es buena noticia: ese ataque no te ha tocado todavia-.
      tarjeta.appendChild(nodo("span", "apr-sinvisto", t("apr.sinvisto")));
    }
    cont.appendChild(tarjeta);
  }
}
$("abrir-aprende").addEventListener("click", () => abrirAprende().catch(() => {}));
$("cerrar-aprende").addEventListener("click", () => $("dialogo-aprende").close());

// ── Exportar IOCs: convertir lo capturado en algo defendible fuera ──────
function descargarIOCs(formato) {
  window.open(`/api/iocs?formato=${formato}&dias=${encodeURIComponent(rango())}`, "_blank", "noopener");
}
$("abrir-iocs").addEventListener("click", () => $("dialogo-iocs").showModal());
$("cerrar-iocs").addEventListener("click", () => $("dialogo-iocs").close());
$("ioc-csv").addEventListener("click", () => descargarIOCs("csv"));
$("ioc-stix").addEventListener("click", () => descargarIOCs("stix"));

// ── Menu de acciones: agrupa los botones para no saturar la cabecera ────
const menuBoton = $("menu-boton");
const menuLista = $("menu-lista");
function cerrarMenu() {
  menuLista.hidden = true;
  menuBoton.setAttribute("aria-expanded", "false");
}
menuBoton.addEventListener("click", (e) => {
  e.stopPropagation();
  const abrir = menuLista.hidden;
  menuLista.hidden = !abrir;
  menuBoton.setAttribute("aria-expanded", String(abrir));
});
// Al elegir una accion, el menu se cierra (la accion ya tiene su listener).
menuLista.addEventListener("click", () => cerrarMenu());
// Pulsar fuera o Escape lo cierra.
document.addEventListener("click", (e) => {
  if (!$("menu-acciones").contains(e.target)) cerrarMenu();
});
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && !menuLista.hidden) cerrarMenu();
});
$("cerrar-ip").addEventListener("click", () => $("dialogo-ip").close());
$("cerrar-campana").addEventListener("click", () => $("dialogo-campana").close());
$("cerrar-artefacto").addEventListener("click", () => $("dialogo-artefacto").close());

// El desplegable de servicios se llena desde el mismo mapa que usa el resto
// del panel: asi una trampa nueva aparece en el filtro sola, sin que haya que
// acordarse de tocar el HTML (que era justo lo que se quedaba desfasado).
for (const [id, nombre] of Object.entries(NOMBRE_SERVICIO)) {
  $("f-protocolo").appendChild(nodo("option", null, nombre)).value = id;
}

// Los filtros recargan solo la lista, no el panel entero: cambiar de
// gravedad no tiene por que volver a pedir el mapa ni el informe.
for (const id of ["f-severidad", "f-protocolo", "f-automatismo", "f-ruido"]) {
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
  $("f-automatismo").value = "";
  $("f-ruido").checked = false;
  cargarAtaques().catch(() => {});
});
$("c-aviso-canal").addEventListener("change", camposDelCanal);
$("reportar-abuse").addEventListener("click", async () => {
  if (!confirm(t("aj.reportar.confirm"))) return;
  const btn = $("reportar-abuse"), est = $("estado-reportar");
  btn.disabled = true;
  est.textContent = t("aj.reportar.enviando");
  try {
    const r = await pedirJSON("/api/reportar-abuse", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    est.textContent = r.reportadas
      ? t("aj.reportar.hecho", { n: r.reportadas, total: r.total })
      : t("aj.reportar.nada");
  } catch (e) {
    est.textContent = t("aj.reportar.error", { msg: e.message });
  } finally {
    btn.disabled = false;
  }
});
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
  "c-resumen-cadencia": "resumen_cadencia",
};
const INTERRUPTORES = {
  "c-enriquecer": "enriquecer_activo",
  "c-usar-llm": "usar_llm",
  "c-avisos-activos": "avisos_activos",
  "c-panel-https": "panel_https",
  "c-resumen-activo": "resumen_activo",
  "c-asistente-activo": "asistente_activo",
  "c-aprendizaje-auto": "aprendizaje_automatico",
};

function volcarAjustes(c) {
  for (const [id, clave] of Object.entries(CAMPOS)) $(id).value = c[clave];
  camposDelCanal();
  for (const [id, clave] of Object.entries(INTERRUPTORES)) $(id).checked = c[clave];

  $("estado-abuse").textContent = c.tiene_abuseipdb
    ? `clave guardada: ${c.clave_abuseipdb}`
    : "sin clave: no se enriqueceran las IPs";
  cargarModelos(c);
  $("abrir-asistente").hidden = !c.asistente_activo;
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
    ["c-clave-virustotal", "clave_virustotal"],
    ["c-aviso-clave", "clave_aviso"],
  ]) {
    const v = $(id).value.trim();
    if (v) cuerpo[clave] = v;
  }
  cuerpo.modelos = modelosConfig.map((m) => ({
    proveedor: m.proveedor, modelo: m.modelo || "", clave: m.claveNueva || "",
  }));
  return cuerpo;
}

// ─── Modelos de IA: lista con failover, "elige proveedor y pega clave" ───
let catalogoProveedores = [];
let modelosConfig = [];

async function cargarCatalogoProveedores() {
  try {
    catalogoProveedores = await pedirJSON("/api/proveedores");
  } catch (e) {
    catalogoProveedores = [];
  }
  const sel = $("nuevo-proveedor");
  sel.replaceChildren();
  for (const p of catalogoProveedores) {
    const o = document.createElement("option");
    o.value = p.id;
    o.textContent = p.nombre;
    sel.appendChild(o);
  }
}

function nombreProveedor(id) {
  const p = catalogoProveedores.find((x) => x.id === id);
  return p ? p.nombre : (id || "compatible");
}

function cargarModelos(c) {
  modelosConfig = (c.modelos || []).map((m) => ({
    proveedor: m.proveedor || "", modelo: m.modelo || "",
    claveMasked: m.clave || "", claveNueva: "",
  }));
  pintarModelos();
}

function pintarModelos() {
  const cont = $("lista-modelos");
  cont.replaceChildren();
  if (!modelosConfig.length) {
    cont.appendChild(nodo("p", "sub", t("cfg.modelos.vacio")));
    return;
  }
  modelosConfig.forEach((m, i) => {
    const fila = nodo("div", "modelo-fila");
    fila.appendChild(nodo("span", "modelo-nombre", nombreProveedor(m.proveedor)));
    const clave = nodo("input", "modelo-clave");
    clave.type = "password";
    clave.autocomplete = "off";
    clave.placeholder = m.claveMasked
      ? t("cfg.modelos.configurada", { c: m.claveMasked })
      : t("cfg.modelos.clave");
    clave.value = m.claveNueva;
    clave.addEventListener("input", () => { m.claveNueva = clave.value; });
    fila.appendChild(clave);
    const acc = nodo("div", "modelo-acciones");
    const boton = (txt, fn, dis) => {
      const b = nodo("button", "boton-menor", txt);
      b.type = "button";
      b.disabled = !!dis;
      b.addEventListener("click", fn);
      return b;
    };
    acc.appendChild(boton("↑", () => {
      [modelosConfig[i - 1], modelosConfig[i]] = [modelosConfig[i], modelosConfig[i - 1]];
      pintarModelos();
    }, i === 0));
    acc.appendChild(boton("↓", () => {
      [modelosConfig[i + 1], modelosConfig[i]] = [modelosConfig[i], modelosConfig[i + 1]];
      pintarModelos();
    }, i === modelosConfig.length - 1));
    acc.appendChild(boton("✕", () => { modelosConfig.splice(i, 1); pintarModelos(); }));
    fila.appendChild(acc);
    cont.appendChild(fila);
  });
}

$("anadir-modelo").addEventListener("click", () => {
  const prov = $("nuevo-proveedor").value;
  if (!prov) return;
  modelosConfig.push({ proveedor: prov, modelo: "", claveMasked: "", claveNueva: $("nueva-clave").value.trim() });
  $("nueva-clave").value = "";
  pintarModelos();
});
cargarCatalogoProveedores();


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
    puertos.appendChild(nodo("span", "ayuda", t("serv.redirige")));
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
    aviso.textContent = t("red.distintas");
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
    cab.appendChild(nodo("span", "chip" + (ifa.activa ? " activo" : ""), ifa.activa ? t("aj.red.activa") : t("aj.red.caida")));
    caja.appendChild(cab);
    caja.appendChild(nodo("p", "ayuda", t("aj.red.ahora", { ips: (ifa.ips || []).join(", ") || t("aj.red.sinip") })));

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
  estado.textContent = t("red.procesando");
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

// ── Actualizaciones ─────────────────────────────────────────────────────

async function cargarActualizaciones() {
  try {
    const a = await pedirJSON("/api/actualizacion");
    $("version-actual").value = a.version || "?";
    const pend = $("pendiente-deb");
    const cancelar = $("cancelar-deb");
    pend.replaceChildren();
    if (a.pendiente) {
      pend.hidden = false;
      cancelar.hidden = false;
      pend.appendChild(nodo("span", null,
        `Hay una actualizacion preparada (${tamano(a.pendiente.bytes)}). Aplicala en el servidor con `));
      pend.appendChild(nodo("code", null, a.comando));
      pend.appendChild(nodo("span", null, "."));
    } else {
      pend.hidden = true;
      cancelar.hidden = true;
    }
  } catch {
    // El menu es opcional; si no carga, el resto de ajustes sigue.
  }
}

// La subida va como cuerpo crudo del POST, igual que la base GeoIP: un .deb
// puede pesar varios MB y no hace falta montar un formulario en memoria.
async function subirActualizacion(fichero) {
  const estado = $("estado-deb");
  const boton = $("subir-deb");
  boton.disabled = true;
  estado.textContent = t("subiendo", { mb: (fichero.size / 1048576).toFixed(1) });
  try {
    const resp = await fetch("/api/actualizacion", { method: "POST", body: fichero });
    const r = await resp.json();
    if (!resp.ok) throw new Error(r.error || `respondio ${resp.status}`);
    estado.textContent = t("act.subida");
    cargarActualizaciones();
  } catch (e) {
    estado.textContent = t("geoip.nosubir", { msg: e.message });
  } finally {
    boton.disabled = false;
  }
}

async function descartarActualizacion() {
  try {
    await pedirJSON("/api/actualizacion", { method: "DELETE" });
    $("estado-deb").textContent = t("act.descartada");
    cargarActualizaciones();
  } catch (e) {
    $("estado-deb").textContent = t("act.nodescartar", { msg: e.message });
  }
}

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
    $("estado-red").textContent = t("red.noleer", { msg: err.message });
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

  await cargarActualizaciones();

  irAPestana("servicios");
  $("estado-ajustes").textContent = "";
  $("estado-contrasena").textContent = "";
  dialogo.showModal();
}

async function guardarAjustes() {
  const estado = $("estado-ajustes");
  estado.textContent = t("aj.guardando");
  try {
    const c = await pedirJSON("/api/ajustes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(leerAjustes()),
    });
    volcarAjustes(c);
    pintarServicios(await pedirJSON("/api/servicios"));
    for (const id of ["c-clave-abuse", "c-clave-virustotal"]) {
      $(id).value = "";
    }
    estado.textContent = t("aj.guardado");
    aplicarRefresco(c.refresco_segundos);
    refrescar();
  } catch (err) {
    estado.textContent = err.message;
  }
}

async function cambiarContrasena() {
  const estado = $("estado-contrasena");
  estado.textContent = t("pass.cambiando");
  try {
    await pedirJSON("/api/contrasena", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ actual: $("p-actual").value, nueva: $("p-nueva").value }),
    });
    $("p-actual").value = "";
    $("p-nueva").value = "";
    estado.textContent = t("pass.cambiada");
  } catch (err) {
    estado.textContent = err.message;
  }
}

let temporizador = null;
let temporizadorAprendizaje = null;
function aplicarRefresco(segundos) {
  if (temporizador) clearInterval(temporizador);
  temporizador = setInterval(refrescar, Math.max(5, segundos || 20) * 1000);
  clearInterval(temporizadorAprendizaje);
  temporizadorAprendizaje = setInterval(() => cargarAprendizaje().catch(() => {}), 15000);
}

$("abrir-ajustes").addEventListener("click", abrirAjustes);
$("cerrar-ajustes").addEventListener("click", () => dialogo.close());
$("guardar-ajustes").addEventListener("click", guardarAjustes);
$("subir-deb").addEventListener("click", () => $("f-deb").click());
$("f-deb").addEventListener("change", (ev) => {
  const f = ev.target.files[0];
  if (f) subirActualizacion(f);
  ev.target.value = "";
});
$("cancelar-deb").addEventListener("click", descartarActualizacion);
$("guardar-contrasena").addEventListener("click", cambiarContrasena);
$("restaurar").addEventListener("click", async () => {
  volcarAjustes(await pedirJSON("/api/ajustes/defecto"));
  $("estado-ajustes").textContent = t("aj.restaurado");
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
    $("abrir-asistente").hidden = !c.asistente_activo;
  } catch (err) {
    return;
  }
  refrescar();
}
iniciar();
