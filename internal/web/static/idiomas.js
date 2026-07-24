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


// ── Grupo 3a: semaforo, gravedad, tiempo, severidades (textos dinamicos) ──
Object.assign(IDIOMAS.es, {
  "hace.momento": "hace un momento",
  "hace.min": "hace {n} min", "hace.h": "hace {n} h", "hace.d": "hace {n} d",
  "sev.roce": "roce", "sev.tanteo": "tanteo", "sev.acceso": "acceso", "sev.intrusion": "intrusión",
  "nivel.rojo": "ROJO", "nivel.ambar": "ÁMBAR", "nivel.verde": "VERDE",
  "sem.vacio": "sin ataques en este periodo",
  "grav.intrusion": "Intrusión — entraron y actuaron",
  "grav.acceso": "Acceso — consiguieron entrar",
  "grav.tanteo": "Tanteo — probaron credenciales o rutas",
  "grav.roce": "Roce — solo tocaron el puerto",
  "grav.vacio": "Sin ataques en este periodo.",
  "grav.ruidofondo": "Ruido de fondo", "grav.serio": "Llegaron a algo",
  "grav.todoruido": "Los {n} son ruido: escaneos y pruebas que rebotan solas.",
  "grav.mixto": "De {total} ataques, el {pct}% es ruido. {serio} llegaron a entrar o actuar: esos son los que miras.",
});
Object.assign(IDIOMAS.en, {
  "hace.momento": "just now",
  "hace.min": "{n} min ago", "hace.h": "{n}h ago", "hace.d": "{n}d ago",
  "sev.roce": "knock", "sev.tanteo": "probe", "sev.acceso": "access", "sev.intrusion": "intrusion",
  "nivel.rojo": "RED", "nivel.ambar": "AMBER", "nivel.verde": "GREEN",
  "sem.vacio": "no attacks in this period",
  "grav.intrusion": "Intrusion — they got in and acted",
  "grav.acceso": "Access — they got in",
  "grav.tanteo": "Probe — they tried credentials or paths",
  "grav.roce": "Knock — they only touched the port",
  "grav.vacio": "No attacks in this period.",
  "grav.ruidofondo": "Background noise", "grav.serio": "Got somewhere",
  "grav.todoruido": "All {n} are noise: scans and probes that bounce off on their own.",
  "grav.mixto": "Of {total} attacks, {pct}% is noise. {serio} got in or acted: those are the ones to watch.",
});

// ── Grupo 3b: botones y estados dinamicos ──
Object.assign(IDIOMAS.es, {
  "dlg.explicando": "Explicando…", "dlg.reexplicar": "Volver a explicar",
  "dlg.noexplicar": "No se pudo explicar: {msg}",
  "dlg.cargando.ataques": "Cargando ataques…",
  "vivo.vacio": "Sin actividad en este periodo.", "vivo.esperando": "esperando actividad…",
  "tabla.vacio": "sin datos",
  "ataques.nofiltro": "Ningún ataque casa con el filtro.",
  "ataques.ninguno": "Todavía no se ha registrado ningún ataque.",
  "ataques.filtro": "{n} ataques con el filtro puesto",
  "aviso.enviando": "Enviando…", "aviso.enviado": "Enviado por {canal}. Si no llega, revisa el destino.",
  "aviso.noenviado": "No se pudo enviar: {msg}",
  "red.procesando": "Procesando…", "red.noleer": "No se pudo leer la red: {msg}",
  "red.distintas": "El panel y los honeypots pueden escuchar en interfaces distintas.",
  "subiendo": "Subiendo {mb} MB…",
  "geoip.cargada": "Base {tipo} cargada. {aviso}", "geoip.nosubir": "No se pudo subir: {msg}",
  "act.subida": "Subida y verificada. Aplícala en el servidor.",
  "act.descartada": "Actualización descartada.", "act.nodescartar": "No se pudo descartar: {msg}",
  "act.nosubir": "No se pudo subir: {msg}",
  "aj.guardando": "Guardando…", "aj.guardado": "Guardado.",
  "aj.restaurado": "Valores por defecto cargados. Pulsa Guardar para aplicarlos.",
  "pass.cambiando": "Cambiando…", "pass.cambiada": "Contraseña cambiada. Las demás sesiones se han cerrado.",
  "ip.nofichar": "no se pudo abrir la ficha: {msg}",
});
Object.assign(IDIOMAS.en, {
  "dlg.explicando": "Explaining…", "dlg.reexplicar": "Explain again",
  "dlg.noexplicar": "Could not explain: {msg}",
  "dlg.cargando.ataques": "Loading attacks…",
  "vivo.vacio": "No activity in this period.", "vivo.esperando": "waiting for activity…",
  "tabla.vacio": "no data",
  "ataques.nofiltro": "No attack matches the filter.",
  "ataques.ninguno": "No attacks recorded yet.",
  "ataques.filtro": "{n} attacks matching the filter",
  "aviso.enviando": "Sending…", "aviso.enviado": "Sent via {canal}. If it does not arrive, check the target.",
  "aviso.noenviado": "Could not send: {msg}",
  "red.procesando": "Processing…", "red.noleer": "Could not read the network: {msg}",
  "red.distintas": "The panel and the honeypots can listen on different interfaces.",
  "subiendo": "Uploading {mb} MB…",
  "geoip.cargada": "{tipo} database loaded. {aviso}", "geoip.nosubir": "Could not upload: {msg}",
  "act.subida": "Uploaded and verified. Apply it on the server.",
  "act.descartada": "Update discarded.", "act.nodescartar": "Could not discard: {msg}",
  "act.nosubir": "Could not upload: {msg}",
  "aj.guardando": "Saving…", "aj.guardado": "Saved.",
  "aj.restaurado": "Default values loaded. Press Save to apply them.",
  "pass.cambiando": "Changing…", "pass.cambiada": "Password changed. Other sessions have been closed.",
  "ip.nofichar": "could not open the profile: {msg}",
});

// ── Grupo 3c: fichas, veredicto de IP, campanas, artefactos ──
Object.assign(IDIOMAS.es, {
  "dato.primera": "Primera vez", "dato.ultima": "Última vez", "dato.ataquescount": "Ataques",
  "dato.eventos": "Eventos", "dato.servicios": "Servicios", "dato.peor": "Lo peor que hizo",
  "dato.reputacion": "Reputación", "dato.denuncias": "Denuncias", "dato.red": "Red",
  "dato.tor": "nodo de salida Tor", "dato.gravedad": "Gravedad", "dato.paises": "Países",
  "dato.direcciones": "Direcciones", "dato.tipo": "Tipo", "dato.tamano": "Tamaño",
  "dato.origen": "Origen", "dato.trajeron": "Lo trajeron",
  "ip.unica": "Primera y única vez que aparece.", "ip.entro": "Consiguió entrar.",
  "ip.escalo": "Fue a más con el tiempo: empezó más suave de lo que acabó.",
  "ip.volvio": "Ha vuelto: {n} ataques {cuando}.",
  "ip.ataques.intro": "Sus ataques, del más reciente al más antiguo:",
  "lleva.mismodia": "el mismo día", "lleva.undia": "a lo largo de 1 día", "lleva.dias": "a lo largo de {n} días",
  "comparten.credenciales": "el mismo diccionario", "comparten.descarga": "el mismo fichero",
  "comparten.comandos": "la misma secuencia de comandos", "comparten.rutas": "las mismas rutas",
  "camp.sub": "{ips} IPs{paises} · {eps} ataques", "camp.alcance": "{ips} IPs{paises}",
  "camp.ataques.intro": "Los ataques de esta campaña — pulsa uno para ver su proceso paso a paso:",
  "artef.titulo": "Artefacto capturado",
  "artef.aviso": "Muestra sin procesar, posible malware. Se descarga como fichero inerte para analizarla en un entorno aislado; no la ejecutes en tu equipo.",
  "artef.cadenas.intro": "Cadenas de texto dentro del fichero (URLs, comandos, direcciones incrustadas):",
  "artef.cadenas.vacio": "Sin cadenas de texto legibles en la cabecera.",
  "dlg.nocargar": "No se pudo cargar: {msg}",
  "origen.desconocido": "origen desconocido", "mapa.aria": "Mapa de origen de los ataques",
  "mapa.sinorigen": "sin origen geolocalizado todavía",
  "mapa.sinpais": "Ningún evento tiene país aún: las IPs privadas no se geolocalizan.",
  "serie.reparto": "({ruido} ruido, {revisar} revisar, {notable} notables)",
  "mapa.eventospais": "{pais}: {n} eventos",
  "serv.redirige": "redirige aquí el tráfico del puerto real",
  "det.purgado": "Sin detalle: los eventos ya se purgaron.",
});
Object.assign(IDIOMAS.en, {
  "dato.primera": "First seen", "dato.ultima": "Last seen", "dato.ataquescount": "Attacks",
  "dato.eventos": "Events", "dato.servicios": "Services", "dato.peor": "Worst it did",
  "dato.reputacion": "Reputation", "dato.denuncias": "Reports", "dato.red": "Network",
  "dato.tor": "Tor exit node", "dato.gravedad": "Severity", "dato.paises": "Countries",
  "dato.direcciones": "Addresses", "dato.tipo": "Type", "dato.tamano": "Size",
  "dato.origen": "Source", "dato.trajeron": "Brought by",
  "ip.unica": "First and only time it appears.", "ip.entro": "It got in.",
  "ip.escalo": "It escalated over time: it started milder than it ended.",
  "ip.volvio": "It is back: {n} attacks {cuando}.",
  "ip.ataques.intro": "Its attacks, newest to oldest:",
  "lleva.mismodia": "the same day", "lleva.undia": "over 1 day", "lleva.dias": "over {n} days",
  "comparten.credenciales": "the same dictionary", "comparten.descarga": "the same file",
  "comparten.comandos": "the same command sequence", "comparten.rutas": "the same paths",
  "camp.sub": "{ips} IPs{paises} · {eps} attacks", "camp.alcance": "{ips} IPs{paises}",
  "camp.ataques.intro": "The attacks in this campaign — click one to see its step-by-step process:",
  "artef.titulo": "Captured artifact",
  "artef.aviso": "Raw sample, possibly malware. It downloads as an inert file to analyze in an isolated environment; do not run it on your machine.",
  "artef.cadenas.intro": "Text strings inside the file (URLs, commands, embedded addresses):",
  "artef.cadenas.vacio": "No readable text strings in the header.",
  "dlg.nocargar": "Could not load: {msg}",
  "origen.desconocido": "unknown source", "mapa.aria": "Map of where attacks come from",
  "mapa.sinorigen": "no geolocated source yet",
  "mapa.sinpais": "No event has a country yet: private IPs are not geolocated.",
  "serie.reparto": "({ruido} noise, {revisar} to review, {notable} notable)",
  "mapa.eventospais": "{pais}: {n} events",
  "serv.redirige": "redirect the real port traffic here",
  "det.purgado": "No detail: the events were already purged.",
});
