// idiomas.js — internacionalizacion del panel.
//
// Los textos de cara al usuario viven aqui, en espanol e ingles, con la
// ortografia correcta (acentos y ñ): son datos, no codigo, asi que no siguen
// la convencion de comentarios sin tildes del resto del proyecto.
//
// Uso: en el HTML, data-i18n="clave" (y data-i18n-title / -placeholder / -aria
// para atributos). En el JS, t("clave") o t("clave", {var: valor}).

const IDIOMAS = {
  es: {
    "hdr.sub": "panel de actividad del honeypot",
    "rango.24h": "24 horas",
    "rango.7d": "7 días",
    "rango.30d": "30 días",
    "rango.90d": "90 días",
    "hdr.informe": "Generar informe",
    "hdr.informe.t": "Abrir un informe completo del periodo seleccionado, listo para imprimir o guardar como PDF",
    "hdr.tema": "Cambiar tema",
    "hdr.ajustes": "Ajustes",
    "hdr.salir": "salir",
    "hdr.conectando": "conectando…",
    "hdr.idioma": "Idioma",
    "dlg.cerrar": "Cerrar",
    "dlg.explicar": "Explicar con IA",
    "dlg.explicar.t": "Pedir al modelo que explique esto. Consume cuota.",
    "dlg.descargar": "Descargar",
    "sec.mapa": "Origen de los ataques",
    "sec.vivo": "En vivo",
    "sec.vivo.sub": "últimos eventos",
    "sec.ataques": "Ataques",
    "sec.ataques.sub": "Los más graves primero, no los más ruidosos",
    "sec.grafica": "Ataques por gravedad",
    "sec.grafica.sub": "Cuánto es ruido de fondo y cuánto va en serio",
    "sec.serie": "Actividad en el tiempo",
    "sec.campanas": "Campañas",
    "sec.campanas.sub": "Ataques que comparten guion: varias IPs, una sola operación",
    "sec.artefactos": "Artefactos",
    "sec.artefactos.sub": "Lo que intentaron traerse al sistema",
    "sec.ips": "IPs más activas",
    "sec.paises": "Países",
    "sec.cred": "Credenciales probadas",
    "sec.usuarios": "usuarios",
    "sec.passwords": "contraseñas",
    "m.eventos": "eventos",
    "m.ips": "IPs únicas",
    "m.paises": "países",
    "m.ruido": "% ruido de fondo",
    "m.revisar": "a revisar",
    "m.notable": "notables",
    "f.buscar": "Buscar IP, país, proveedor…",
    "f.toda": "Toda gravedad",
    "f.tanteo": "Tanteo o más",
    "f.acceso": "Acceso o más",
    "f.intrusion": "Solo intrusiones",
    "f.servicios": "Todos los servicios",
    "f.limpiar": "Quitar filtros",
    "cargando": "Cargando…",
    "cargando.mapa": "Cargando mapa…",
    "pie": "Los datos de esta página los escriben atacantes. Se muestran siempre como texto plano, nunca como HTML."
  },
  en: {
    "hdr.sub": "honeypot activity dashboard",
    "rango.24h": "24 hours",
    "rango.7d": "7 days",
    "rango.30d": "30 days",
    "rango.90d": "90 days",
    "hdr.informe": "Generate report",
    "hdr.informe.t": "Open a full report for the selected period, ready to print or save as PDF",
    "hdr.tema": "Toggle theme",
    "hdr.ajustes": "Settings",
    "hdr.salir": "log out",
    "hdr.conectando": "connecting…",
    "hdr.idioma": "Language",
    "dlg.cerrar": "Close",
    "dlg.explicar": "Explain with AI",
    "dlg.explicar.t": "Ask the model to explain this. Uses quota.",
    "dlg.descargar": "Download",
    "sec.mapa": "Where attacks come from",
    "sec.vivo": "Live",
    "sec.vivo.sub": "latest events",
    "sec.ataques": "Attacks",
    "sec.ataques.sub": "Most severe first, not the noisiest",
    "sec.grafica": "Attacks by severity",
    "sec.grafica.sub": "How much is background noise and how much is serious",
    "sec.serie": "Activity over time",
    "sec.campanas": "Campaigns",
    "sec.campanas.sub": "Attacks sharing a script: many IPs, one operation",
    "sec.artefactos": "Artifacts",
    "sec.artefactos.sub": "What they tried to pull into the system",
    "sec.ips": "Most active IPs",
    "sec.paises": "Countries",
    "sec.cred": "Credentials tried",
    "sec.usuarios": "usernames",
    "sec.passwords": "passwords",
    "m.eventos": "events",
    "m.ips": "unique IPs",
    "m.paises": "countries",
    "m.ruido": "% background noise",
    "m.revisar": "to review",
    "m.notable": "notable",
    "f.buscar": "Search IP, country, provider…",
    "f.toda": "Any severity",
    "f.tanteo": "Probe or worse",
    "f.acceso": "Access or worse",
    "f.intrusion": "Intrusions only",
    "f.servicios": "All services",
    "f.limpiar": "Clear filters",
    "cargando": "Loading…",
    "cargando.mapa": "Loading map…",
    "pie": "The data on this page is written by attackers. It is always shown as plain text, never as HTML."
  },
};

const IDIOMA_POR_DEFECTO = "es";

// idiomaActual: el guardado, o el del navegador si lo tenemos, o el defecto.
function idiomaActual() {
  const guardado = localStorage.getItem("k0pot-idioma");
  if (guardado && IDIOMAS[guardado]) return guardado;
  const nav = (navigator.language || "es").slice(0, 2).toLowerCase();
  return IDIOMAS[nav] ? nav : IDIOMA_POR_DEFECTO;
}

let IDIOMA = idiomaActual();

// t devuelve el texto en el idioma actual, sustituyendo {var} por su valor.
// Si falta la clave, cae al espanol y, en ultimo caso, a la propia clave.
function t(clave, vars) {
  let s = (IDIOMAS[IDIOMA] && IDIOMAS[IDIOMA][clave]);
  if (s === undefined) s = IDIOMAS.es[clave];
  if (s === undefined) s = clave;
  if (vars) {
    for (const k in vars) s = s.split("{" + k + "}").join(vars[k]);
  }
  return s;
}

// traducirDOM aplica las traducciones a un arbol: textContent para [data-i18n]
// y atributos para las variantes.
function traducirDOM(raiz) {
  raiz = raiz || document;
  raiz.querySelectorAll("[data-i18n]").forEach((el) => {
    el.textContent = t(el.getAttribute("data-i18n"));
  });
  // data-i18n-html: para textos con markup de confianza (negritas, <code>).
  // Son cadenas del propio catalogo, nunca entrada de usuario.
  raiz.querySelectorAll("[data-i18n-html]").forEach((el) => {
    el.innerHTML = t(el.getAttribute("data-i18n-html"));
  });
  const attrs = [
    ["data-i18n-title", "title"],
    ["data-i18n-placeholder", "placeholder"],
    ["data-i18n-aria", "aria-label"],
  ];
  for (const [marca, prop] of attrs) {
    raiz.querySelectorAll("[" + marca + "]").forEach((el) => {
      el.setAttribute(prop, t(el.getAttribute(marca)));
    });
  }
  document.documentElement.lang = IDIOMA;
}

// cambiarIdioma persiste la eleccion y recarga: un re-render limpio en el
// idioma nuevo es mas fiable que repintar a mano cada trozo dinamico.
function cambiarIdioma(nuevo) {
  if (!IDIOMAS[nuevo] || nuevo === IDIOMA) return;
  localStorage.setItem("k0pot-idioma", nuevo);
  location.reload();
}
