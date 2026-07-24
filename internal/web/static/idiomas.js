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
  // data-i18n-first: traduce SOLO el primer nodo de texto de un elemento,
  // dejando intactos los campos que contenga (para <label>Texto<input></label>).
  raiz.querySelectorAll("[data-i18n-first]").forEach((el) => {
    const clave = el.getAttribute("data-i18n-first");
    for (const n of el.childNodes) {
      if (n.nodeType === 3 && n.textContent.trim()) {
        const pre = /^\s/.test(n.textContent) ? " " : "";
        const post = /\s$/.test(n.textContent) ? " " : "";
        n.textContent = pre + t(clave) + post;
        break;
      }
    }
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

// -- Grupo 2: dialogo de Ajustes --
Object.assign(IDIOMAS.es, {
  "cfg.titulo": "Ajustes",
  "cfg.tab.servicios": "Servicios",
  "cfg.tab.red": "Red",
  "cfg.tab.deteccion": "Detección",
  "cfg.tab.informes": "Informes",
  "cfg.tab.avisos": "Avisos",
  "cfg.tab.general": "General",
  "cfg.tab.actualizaciones": "Actualizaciones",
  "cfg.serv.h3": "Servicios de honeypot",
  "cfg.serv.ayuda": "Cada servicio activo escucha en el puerto indicado. Para capturar ataques reales hay que <strong>redirigir</strong> hacia él el tráfico del puerto de verdad (el 80 hacia el de HTTP, etc.).",
  "cfg.serv.cowrie": "Cowrie (SSH en el 2222 y Telnet en el 2223) va en su propio contenedor y se gestiona desde <code>docker-compose.yml</code>.",
  "cfg.red.h3": "Red",
  "cfg.red.ifpanel": "Interfaz del panel",
  "cfg.red.ifhp": "Interfaz de los honeypots",
  "cfg.red.h3ip": "Direcciones IP de las interfaces",
  "cfg.red.peligro": "Cambiar la IP por la que entras al panel te dejará fuera hasta que abras la nueva. La red se revierte sola en 2 minutos si no confirmas, así que un error no deja el servidor inaccesible.",
  "cfg.red.ver": "Ver configuración",
  "cfg.red.aplicar": "Aplicar",
  "cfg.red.confirmar": "Confirmar",
  "cfg.red.revertir": "Revertir",
  "cfg.clas.h3": "Clasificador",
  "cfg.clas.ayuda": "A partir de qué punto una IP deja de ser ruido de fondo. Subirlos hace a k0Pot más callado.",
  "cfg.clas.rep": "Reputación alta (0-100)",
  "cfg.clas.den": "Denuncias altas",
  "cfg.enr.h3": "Enriquecimiento de IPs",
  "cfg.enr.abuse": "Consultar AbuseIPDB",
  "cfg.enr.caducidad": "Caducidad del dato (días)",
  "cfg.enr.geoip": "Base GeoIP (opcional)",
  "cfg.enr.geoip.ph": "(ninguna: el mapa usa el país)",
  "cfg.enr.geoip.small": "Sitúa cada IP en su ciudad, no solo en su país. Descarga gratis GeoLite2-City de MaxMind (cuenta gratuita) y súbela con el botón.",
  "cfg.enr.subir": "Subir base GeoIP…",
  "cfg.enr.reserva": "Reserva de cuota diaria",
  "cfg.enr.clave": "Clave de AbuseIPDB",
  "cfg.sincambios": "sin cambios",
  "cfg.inf.h3": "Informes",
  "cfg.inf.llm": "Redactar con LLM",
  "cfg.inf.proveedor": "Proveedor",
  "cfg.inf.compat": "Compatible con OpenAI (Groq, OpenRouter, Mistral, Ollama…)",
  "cfg.inf.modelo": "Modelo",
  "cfg.inf.tope": "Tope de informes con IA al día (pedidos a mano)",
  "cfg.inf.tope.small": "Los informes automáticos no cuentan: los redactan las reglas, que no cuestan nada. 0 = sin límite.",
  "cfg.inf.url": "URL base",
  "cfg.inf.claveprov": "Clave del proveedor",
  "cfg.inf.claveanth": "Clave de Anthropic",
  "cfg.av.nota": "Un panel solo avisa a quien lo tiene abierto. Con esto, k0Pot te escribe cuando alguien <strong>consigue entrar</strong> en el honeypot o <strong>se sirve de él</strong>. El ruido de fondo —escaneos y contraseñas por defecto, cientos al día— no genera ningún aviso.",
  "cfg.av.activo": "Avisar cuando pase algo grave",
  "cfg.av.pordonde": "Por dónde",
  "cfg.av.ntfy": "ntfy (sin cuenta, con app móvil)",
  "cfg.av.webhook": "Webhook propio",
  "cfg.av.gravedad": "A partir de qué gravedad",
  "cfg.av.acceso": "Acceso — consiguieron entrar",
  "cfg.av.intrusion": "Intrusión — entraron y además actuaron",
  "cfg.av.tema": "Tema de ntfy",
  "cfg.av.tema.small": "Elige un nombre largo y difícil de adivinar: cualquiera que sepa el tema puede leer tus avisos. Instala la app ntfy y suscríbete a ese mismo tema.",
  "cfg.av.token": "Token del bot",
  "cfg.av.token.small": "Lo da @BotFather al crear el bot.",
  "cfg.av.servidor": "Servidor de ntfy",
  "cfg.av.servidor.small": "Déjalo vacío salvo que tengas uno propio.",
  "cfg.av.enlace": "Enlace al panel",
  "cfg.av.enlace.small": "Se incluye en el aviso para poder abrir el panel desde la notificación.",
  "cfg.av.probar": "Enviar un aviso de prueba",
  "cfg.gen.h3": "Panel y datos",
  "cfg.gen.refresco": "Refresco del panel (segundos)",
  "cfg.gen.pais": "País del honeypot (ISO, p.ej. ES)",
  "cfg.gen.pais.ayuda": "Destino de las líneas de ataque en el mapa.",
  "cfg.gen.ubic": "Sitúalo con precisión: <strong>pincha en el mapa</strong>. Sin coordenadas la marca va al centro del país, que en uno grande queda a cientos de kilómetros de donde está la máquina.",
  "cfg.zoom.mas": "Acercar",
  "cfg.zoom.menos": "Alejar",
  "cfg.zoom.reset": "Ver todo",
  "cfg.gen.lat": "Latitud",
  "cfg.gen.lon": "Longitud",
  "cfg.gen.solopais": "Usar solo el país",
  "cfg.gen.https": "Servir el panel por HTTPS",
  "cfg.gen.https.nota": "El panel pide una contraseña y devuelve todo lo capturado. Sin cifrar, eso viaja en claro por tu red. Si no indicas certificado propio, k0Pot genera uno autofirmado: el navegador avisará la primera vez —no hay autoridad que lo verifique— pero el tráfico ya va cifrado. <strong>Requiere reiniciar el panel.</strong>",
  "cfg.gen.cert": "Certificado (opcional)",
  "cfg.gen.cert.ph": "ruta al fichero .crt",
  "cfg.gen.cert.small": "Déjalo vacío para que se genere uno solo.",
  "cfg.gen.certkey": "Clave del certificado (opcional)",
  "cfg.gen.certkey.ph": "ruta al fichero .key",
  "cfg.gen.reteventos": "Conservar eventos (días)",
  "cfg.gen.reteventos.small": "El detalle: cada línea capturada, con sus grabaciones de sesión y los binarios descargados. Es lo que más ocupa. 0 = para siempre.",
  "cfg.gen.retataques": "Conservar ataques (días)",
  "cfg.gen.retataques.small": "El resumen agrupado. Ocupa una fracción y es lo que responde \"¿esta IP ya había venido?\" meses después, así que conviene un plazo más largo que el de los eventos. 0 = para siempre.",
  "cfg.pass.h3": "Cambiar contraseña",
  "cfg.pass.actual": "Actual",
  "cfg.pass.nueva": "Nueva",
  "cfg.pass.boton": "Cambiar contraseña",
  "cfg.act.h3": "Actualizaciones",
  "cfg.act.version": "Versión instalada",
  "cfg.act.ayuda": "Sube el paquete <code>.deb</code> de una versión nueva. El panel lo valida y lo deja preparado, pero <strong>no lo instala</strong>: corre sin privilegios a propósito, para que un acceso al panel no pueda volverse root del servidor. Para aplicarlo, ejecuta en el servidor <code>sudo k0pot-actualizar</code> (te pedirá confirmación).",
  "cfg.restaurar": "Restaurar valores",
  "cfg.guardar": "Guardar"
});
Object.assign(IDIOMAS.en, {
  "cfg.titulo": "Settings",
  "cfg.tab.servicios": "Services",
  "cfg.tab.red": "Network",
  "cfg.tab.deteccion": "Detection",
  "cfg.tab.informes": "Reports",
  "cfg.tab.avisos": "Alerts",
  "cfg.tab.general": "General",
  "cfg.tab.actualizaciones": "Updates",
  "cfg.serv.h3": "Honeypot services",
  "cfg.serv.ayuda": "Each active service listens on the given port. To capture real attacks you must <strong>redirect</strong> the real port traffic to it (port 80 to the HTTP one, etc.).",
  "cfg.serv.cowrie": "Cowrie (SSH on 2222 and Telnet on 2223) runs in its own container and is managed from <code>docker-compose.yml</code>.",
  "cfg.red.h3": "Network",
  "cfg.red.ifpanel": "Panel interface",
  "cfg.red.ifhp": "Honeypots interface",
  "cfg.red.h3ip": "Interface IP addresses",
  "cfg.red.peligro": "Changing the IP you use to reach the panel will lock you out until you open the new one. The network reverts on its own after 2 minutes if you do not confirm, so a mistake won't leave the server unreachable.",
  "cfg.red.ver": "Show configuration",
  "cfg.red.aplicar": "Apply",
  "cfg.red.confirmar": "Confirm",
  "cfg.red.revertir": "Revert",
  "cfg.clas.h3": "Classifier",
  "cfg.clas.ayuda": "The point at which an IP stops being background noise. Raising these makes k0Pot quieter.",
  "cfg.clas.rep": "High reputation (0-100)",
  "cfg.clas.den": "High report count",
  "cfg.enr.h3": "IP enrichment",
  "cfg.enr.abuse": "Query AbuseIPDB",
  "cfg.enr.caducidad": "Data expiry (days)",
  "cfg.enr.geoip": "GeoIP database (optional)",
  "cfg.enr.geoip.ph": "(none: the map uses the country)",
  "cfg.enr.geoip.small": "Places each IP in its city, not just its country. Download GeoLite2-City from MaxMind for free (free account) and upload it with the button.",
  "cfg.enr.subir": "Upload GeoIP database…",
  "cfg.enr.reserva": "Daily quota reserve",
  "cfg.enr.clave": "AbuseIPDB key",
  "cfg.sincambios": "unchanged",
  "cfg.inf.h3": "Reports",
  "cfg.inf.llm": "Write with an LLM",
  "cfg.inf.proveedor": "Provider",
  "cfg.inf.compat": "OpenAI-compatible (Groq, OpenRouter, Mistral, Ollama…)",
  "cfg.inf.modelo": "Model",
  "cfg.inf.tope": "Daily AI report cap (manual requests)",
  "cfg.inf.tope.small": "Automatic reports do not count: they are written by rules, which cost nothing. 0 = no limit.",
  "cfg.inf.url": "Base URL",
  "cfg.inf.claveprov": "Provider key",
  "cfg.inf.claveanth": "Anthropic key",
  "cfg.av.nota": "A panel only alerts whoever has it open. With this, k0Pot writes to you when someone <strong>gets into</strong> the honeypot or <strong>uses it</strong>. Background noise —scans and default passwords, hundreds a day— triggers no alert.",
  "cfg.av.activo": "Alert when something serious happens",
  "cfg.av.pordonde": "Channel",
  "cfg.av.ntfy": "ntfy (no account, with a mobile app)",
  "cfg.av.webhook": "Your own webhook",
  "cfg.av.gravedad": "From which severity",
  "cfg.av.acceso": "Access — they got in",
  "cfg.av.intrusion": "Intrusion — they got in and acted",
  "cfg.av.tema": "ntfy topic",
  "cfg.av.tema.small": "Pick a long, hard-to-guess name: anyone who knows the topic can read your alerts. Install the ntfy app and subscribe to that same topic.",
  "cfg.av.token": "Bot token",
  "cfg.av.token.small": "@BotFather gives it to you when you create the bot.",
  "cfg.av.servidor": "ntfy server",
  "cfg.av.servidor.small": "Leave it empty unless you have your own.",
  "cfg.av.enlace": "Panel link",
  "cfg.av.enlace.small": "It is included in the alert so you can open the panel from the notification.",
  "cfg.av.probar": "Send a test alert",
  "cfg.gen.h3": "Panel and data",
  "cfg.gen.refresco": "Panel refresh (seconds)",
  "cfg.gen.pais": "Honeypot country (ISO, e.g. ES)",
  "cfg.gen.pais.ayuda": "Where the attack lines point to on the map.",
  "cfg.gen.ubic": "Place it precisely: <strong>click on the map</strong>. Without coordinates the marker goes to the country's center, which in a large country is hundreds of kilometers from the machine.",
  "cfg.zoom.mas": "Zoom in",
  "cfg.zoom.menos": "Zoom out",
  "cfg.zoom.reset": "See all",
  "cfg.gen.lat": "Latitude",
  "cfg.gen.lon": "Longitude",
  "cfg.gen.solopais": "Use only the country",
  "cfg.gen.https": "Serve the panel over HTTPS",
  "cfg.gen.https.nota": "The panel asks for a password and returns everything captured. Unencrypted, that travels in the clear across your network. If you do not provide your own certificate, k0Pot generates a self-signed one: the browser will warn the first time —no authority can verify it— but the traffic is already encrypted. <strong>Requires restarting the panel.</strong>",
  "cfg.gen.cert": "Certificate (optional)",
  "cfg.gen.cert.ph": "path to the .crt file",
  "cfg.gen.cert.small": "Leave it empty to generate one automatically.",
  "cfg.gen.certkey": "Certificate key (optional)",
  "cfg.gen.certkey.ph": "path to the .key file",
  "cfg.gen.reteventos": "Keep events (days)",
  "cfg.gen.reteventos.small": "The detail: every captured line, with its session recordings and downloaded binaries. It takes the most space. 0 = forever.",
  "cfg.gen.retataques": "Keep attacks (days)",
  "cfg.gen.retataques.small": "The grouped summary. It takes a fraction and is what answers \"has this IP been here before?\" months later, so a longer period than events is worth it. 0 = forever.",
  "cfg.pass.h3": "Change password",
  "cfg.pass.actual": "Current",
  "cfg.pass.nueva": "New",
  "cfg.pass.boton": "Change password",
  "cfg.act.h3": "Updates",
  "cfg.act.version": "Installed version",
  "cfg.act.ayuda": "Upload the <code>.deb</code> package of a new version. The panel validates it and stages it, but <strong>does not install it</strong>: it runs unprivileged on purpose, so that access to the panel cannot become root on the server. To apply it, run on the server <code>sudo k0pot-actualizar</code> (it will ask for confirmation).",
  "cfg.restaurar": "Restore defaults",
  "cfg.guardar": "Save"
});
Object.assign(IDIOMAS.es, { "cfg.act.subir": "Subir .deb…", "cfg.act.descartar": "Descartar" });
Object.assign(IDIOMAS.en, { "cfg.act.subir": "Upload .deb…", "cfg.act.descartar": "Discard" });
Object.assign(IDIOMAS.es, {
  "cfg.av.dst.ntfy": "Tema de ntfy",
  "cfg.av.dst.ntfy.ayuda": "Elige un nombre largo y difícil de adivinar: cualquiera que sepa el tema puede leer tus avisos. Instala la app ntfy y suscríbete a ese mismo tema.",
  "cfg.av.dst.telegram": "Chat de Telegram",
  "cfg.av.dst.telegram.ayuda": "El identificador numérico del chat. Escribe a @userinfobot para saber el tuyo.",
  "cfg.av.dst.webhook": "URL del webhook",
  "cfg.av.dst.webhook.ayuda": "Recibirá un POST con el aviso en JSON."
});
Object.assign(IDIOMAS.en, {
  "cfg.av.dst.ntfy": "ntfy topic",
  "cfg.av.dst.ntfy.ayuda": "Pick a long, hard-to-guess name: anyone who knows the topic can read your alerts. Install the ntfy app and subscribe to that same topic.",
  "cfg.av.dst.telegram": "Telegram chat",
  "cfg.av.dst.telegram.ayuda": "The chat's numeric ID. Message @userinfobot to find yours.",
  "cfg.av.dst.webhook": "Webhook URL",
  "cfg.av.dst.webhook.ayuda": "It will receive a POST with the alert as JSON."
});
