# k0Pot

Honeypot ligero que **explica** lo que pasa en lugar de limitarse a
registrarlo. Captura los ataques, separa el ruido de lo que importa y **te
cuenta en lenguaje llano** que es cada uno, como funciona y que buscaban, sin
que tengas que ser analista de seguridad. Lo que no sabe **lo aprende solo**,
en segundo plano, y lo va guardando: cuando abres un ataque, la explicacion ya
esta puesta.

Ligero a proposito: un unico binario en Go y Cowrie en un contenedor, sin
stacks de gigabytes ni bases de datos que administrar. Reutiliza honeypots que
ya funcionan bien y aporta la capa que suele faltar: **la interpretacion**.

## Por que

Un honeypot genera miles de lineas al dia. La inmensa mayoria es ruido: bots
probando `admin/admin`, escaneres inventariando internet. El problema no es
capturar, es **encontrar el unico episodio que importaba** entre diez mil que
no importaban.

k0Pot responde a tres preguntas, en este orden:

1. **¿Tengo que preocuparme?** Un semaforo verde, ambar o rojo.
2. **¿Que ha pasado?** Los ataques agrupados y ordenados por lo que
   consiguieron, no por cuanto insistieron.
3. **¿Que significa?** `GET /SDK/webLanguage` es un hecho; *"buscan camaras IP
   Hikvision expuestas para reclutarlas en una botnet"* es lo que necesitas
   saber. Un catalogo propio traduce lo rutinario al instante, y **lo que no
   sabe lo aprende solo**: la IA explica en segundo plano cada comando o
   ataque nuevo y lo guarda, de modo que cuando abres algo la explicacion ya
   esta puesta, sin botones ni esperas.

## Como funciona

```
   internet
      |
      v
 [ Cowrie ]  SSH y Telnet, en contenedor
 [ trampas ] HTTP, Redis, FTP, MySQL, PostgreSQL,
             SMTP, RDP, VNC, Docker; nativas en Go
      |
      v
  collector --> enrich --> classify --> SQLite
                                          |
                              +-----------+-----------+
                              v                       v
                         episodios                informes
                      (ataques agrupados)    (reglas + IA opcional)
                              |                       |
                              +----------> panel <----+
```

**Un evento aislado casi nunca dice nada.** Lo que una persona llama "un
ataque" es una secuencia: esta IP conecto, probo doce contrasenas, entro y
ejecuto `wget`. k0Pot agrupa los eventos en **episodios** y los punta por lo
que el atacante *consiguio*:

| Severidad | Significa |
|---|---|
| `roce` | toco el puerto y se fue |
| `tanteo` | probo credenciales o rutas |
| `acceso` | entro |
| `intrusion` | entro y ademas actuo dentro |

Mil conexiones de un escaner valen menos que una sola sesion donde alguien
tecleo `cat /etc/passwd`. Ordenar por volumen es justo lo que entierra el
unico episodio que habia que mirar.

## Explicaciones que se generan solas

Es lo que mas distingue a k0Pot, y funciona en dos capas, **sin botones**:

- **Comando a comando.** Cada orden que teclea un atacante lleva al lado, en
  llano, que hace y para que: `chmod +x` prepara el fichero recien descargado
  para lanzarlo; `chroot /host` es un escape del contenedor hacia la maquina
  real. Un catalogo propio cubre al instante lo habitual; **lo que no conoce
  lo aprende**: pregunta a la IA una vez, guarda la respuesta y a partir de
  ahi la sirve gratis, aqui y en cualquier ataque futuro con ese mismo
  comando. El conocimiento crece con lo que ve.
- **El ataque entero, la campana o el artefacto.** Una narrativa en prosa:
  que buscaban, como funciona la tecnica, hasta donde llegaron y que
  significaria en un servidor de verdad. Y **tambien se reutiliza**: como los
  bots repiten el mismo guion desde miles de IPs, cada ataque tiene una *firma*
  —su forma normalizada, sin IPs ni hashes—; dos ataques con la misma firma
  comparten narrativa, asi que el primero la genera y el resto la sirven gratis
  y al instante. En la practica, miles de ataques se reducen a unas decenas de
  formas. Un artefacto capturado se explica a partir de su tipo y de las cadenas
  que lleva dentro, **sin ejecutarlo**.

**Abrir algo NUNCA llama al modelo.** Todo sale de memoria. La IA solo trabaja
en segundo plano y **solo para los ataques que abres** —no malgasta la cuota en
un backlog de miles que nadie mira—: al abrir uno, si su forma ya se explico se
reutiliza al momento; si es nueva, se genera y se guarda por firma. Mientras
tanto, el detalle paso a paso ya esta debajo (narracion + glosas de memoria) y
el panel avisa de que prepara el resumen del ataque entero. Un indicador en la
cabecera muestra cuanto lleva aprendido, si esta aprendiendo, los tokens de hoy
y si algun modelo se quedo sin cuota.

**Nace sabiendo.** k0Pot trae de fabrica lo ya aprendido —un catalogo de
comandos Y las narrativas de las formas de ataque mas comunes: Mirai, droppers,
reconocimiento, fuerza bruta, escapes de contenedor...—, asi que una instalacion
nueva reconoce y explica lo de siempre desde el primer minuto sin gastar IA.

**Configurar la IA es elegir y pegar la clave.** En Ajustes hay un catalogo de
proveedores integrado —Groq, Google Gemini, OpenAI, Anthropic, OpenRouter,
Mistral, DeepSeek—; eliges uno y pegas tu clave, sin URLs que recordar (cada proveedor trae un
modelo por defecto, que puedes cambiar por fila si te hace falta). Y puedes **configurar varios**: k0Pot usa el primero de la lista
con tokens y, si se agota, **salta solo al siguiente** (failover automatico);
cuando el primero se recupera, vuelve a el. El orden es la prioridad.

**Los limites son de cada modelo y automaticos.** No configuras cuotas: cada
proveedor avisa con su error de "sin tokens" y k0Pot lo aprende, pausa ese
modelo por separado y sigue con otro. Un indicador en la cabecera muestra
cuantos comandos lleva aprendidos, si esta aprendiendo en ese momento, los
tokens gastados hoy y si algun modelo se quedo sin cuota.

**Sin clave, k0Pot funciona igual**: se apagan solo las explicaciones con IA, y
todo lo demas —semaforo, agrupacion, catalogo de fabrica, informe— sigue gratis
y por reglas. El encuadre es defensivo: al modelo se le dice que esto es un
senuelo y que NO recomiende cerrar la trampa (ver *"Los textos hablan de un
senuelo"* mas abajo).

## Mas en el panel

- **Modo aprende.** Un aula corta —honeypot, escaneo, fuerza bruta, botnet,
  dropper, C2...— en lenguaje llano, donde cada concepto enlaza a un caso
  **real** capturado en tu maquina.
- **Tendencias.** El periodo actual frente al anterior: si la cosa va a mas o
  a menos, y que ha aparecido de nuevo.
- **Novedades.** Ficheros que no habias visto nunca y sesiones que no encajan
  con la automatizacion conocida; dejan de salir en cuanto los miras.
- **Ficha de una IP** con su linea de vida: cuando estuvo activa y como
  evoluciono, un ataque por marca coloreado por gravedad.
- **Asistente** (opcional, se activa en Ajustes): chatear con la IA sobre lo
  que ha visto el honeypot esta semana.
- **Exportar IOCs** (CSV y STIX 2.1): las IPs, hashes, URLs de malware y los
  **C2 que los atacantes filtran** al lanzar un exploit (el `ldap://` de un
  Log4Shell, el `http://` de la segunda fase), listos para importar en tu
  firewall, tu SIEM o en MISP.
- **Blocklist descargable.** Un fichero con las IPs que *de verdad* atacaron
  —por defecto las que consiguieron entrar—, en texto plano o como set de
  `nftables`, listo para bloquearlas en tus servidores reales. Atacaron un
  senuelo, asi que bloquearlas es seguro.
- **Trampas con cebo.** La web falsa sirve un `.env`, un panel de login o la
  config de git creibles, y captura las credenciales o el payload que envian:
  nadie legitimo teclea su usuario en la maquina trampa.
- **Captura de infraestructura del atacante.** Cuando un escaneo intenta un
  exploit conocido (Log4Shell, Shellshock, Struts, Spring4Shell, Solr,
  ThinkPHP...), k0Pot lo reconoce en toda la peticion —tambien en las
  cabeceras, y deshaciendo la ofuscacion de Log4j— y **extrae el destino de
  retrollamada**: su C2 o el servidor desde el que sirve la segunda fase. Es
  la inteligencia mas valiosa que deja un escaneo, y se saca leyendo texto,
  sin ejecutar nada.

## Servicios

| Servicio | Puerto por defecto | Motor |
|---|---|---|
| SSH | 2222 | Cowrie (shell emulada completa) |
| Telnet | 2223 | Cowrie |
| HTTP | 8081 | nativo |
| Redis | 6379 | nativo |
| FTP | 2121 | nativo |
| MySQL | 3306 | nativo |
| PostgreSQL | 5432 | nativo |
| SMTP | 2525 | nativo |
| RDP | 3389 | nativo |
| VNC | 5900 | nativo |
| Docker API | 2375 | nativo |
| Elasticsearch | 9200 | nativo |
| Jenkins | 8000 | nativo |
| Grafana | 3000 | nativo |
| MongoDB | 27017 | nativo |

Se activan y desactivan desde el panel. Los puertos son configurables; el
panel indica a cuales hay que redirigir el trafico.

El senuelo de Elasticsearch va mas alla de responder: sirve indices con
nombres jugosos (`users`, `payments`, `customers`...) y documentos con
**credenciales senuelo** dentro, asi que vaciar esa "base de datos" es a la
vez el gancho y una trampa: si el atacante reutiliza una, salta la alarma.

En la misma linea, **Jenkins**, **Grafana** y **MongoDB** imitan servicios
que se rastrean sin descanso: paneles de login que capturan las credenciales
que prueban (tambien en JSON), la consola de scripts Groovy de Jenkins, el
path traversal de Grafana (CVE-2021-43798) respondido con un `/etc/passwd`
de pega, y el apreton de manos binario de MongoDB con bases de nombres
jugosos. Cada uno se activa desde el panel; recuerda abrir su puerto en el
aislamiento (ya listados) y redirigirlo en tu router.

Y las trampas de **MySQL** y **PostgreSQL** ya no solo capturan el login: lo
aceptan y dejan "entrar", sirven tablas con datos falsos (`users`, `payments`,
`customers`...) donde se cuelan credenciales senuelo, y anotan **cada consulta
SQL** que lanza el atacante. Asi se ve como intenta exfiltrar, y robar esas
filas y reutilizarlas mas tarde salta la alarma.

## Botin y cebos que avisan (canary tokens)

Un honeypot ensena mas cuanto mas se queda el atacante. Por eso el sistema
de ficheros falso de Cowrie viene con **botin** creible: quien entra por SSH
encuentra un `/root/.env` con credenciales de "produccion", un
`.bash_history` con los comandos del "administrador", claves SSH y AWS, un
`.mysql_history`, un `crontab` y un volcado de base de datos. Y comandos como
`mysql`, `docker`, `aws` o `sshpass` responden de forma creible, en vez de
delatar la trampa con un "command not found".

Todo es **falso e inerte**: ninguna credencial abre nada real, la clave
privada no autentica en ningun sitio y nada se ejecuta (Cowrie simula). Pero
cada credencial es unica y de alta entropia: es un **canary**. Si una
reaparece mas tarde —el atacante prueba esa contrasena en un login, la teclea
en un comando o la envia al panel falso— k0Pot lo detecta con **certeza
total**: nadie escribe esas cadenas por casualidad, asi que su reaparicion
confirma que leyo el cebo y volvio. El ataque salta a **intrusion**, el
resumen lo encabeza con "mordio el cebo" y la narrativa lo explica lo primero.
Todo dentro de la maquina, sin avisar a ningun servicio externo.

El botin se planta parcheando el filesystem de Cowrie con contenido embebido
(`deploy/plantar-botin.py` inyecta `deploy/loot/` en el pickle); las
credenciales senuelo viven en `internal/cebo` y se detectan en
`internal/classify`.

## Instalacion

### Con paquete (recomendado)

`./empaquetar.sh` deja en `dist/` el `.deb`, un instalador de un paso y una
guia `LEEME.txt` para no entendidos. Copia la carpeta `dist/` al servidor y:

```sh
sudo ./instalar.sh
```

Instala el paquete con sus dependencias y lanza el asistente de un tiron. A
mano seria:

```sh
sudo apt install ./k0pot_*.deb
sudo k0pot-configurar
```

`apt install` —no `dpkg -i`— porque asi resuelve e instala las dependencias:
Docker, el plugin de compose y nftables. En un Ubuntu de serie coge los de
la distribucion (`docker.io`, `docker-compose-v2`); si ya tienes anadido el
repositorio de Docker, sirven igual los suyos (`docker-ce`,
`docker-compose-plugin`). **No hace falta Go**: el binario viene compilado y
enlazado estaticamente.

El asistente detecta las interfaces reales y **propone las IP que ya tiene
la maquina** —basta con pulsar Enter para mantenerlas—, crea tu cuenta,
**deja el cortafuegos generado con esas IP** (listo para `k0pot-nft aplicar`)
y arranca los servicios. Al terminar indica la URL del panel.

La diferencia importante frente a instalarlo a mano es **quien ejecuta el
servicio**: el paquete crea un usuario propio del sistema, sin shell y **sin
pertenecer a `sudo` ni a `docker`**. Como el grupo `docker` equivale a root
—basta un contenedor con el disco montado—, un fallo en una trampa expuesta
a internet dejaria de ser un camino a root en la maquina. Cowrie lo arranca
un servicio aparte que si habla con Docker, de modo que el proceso expuesto
nunca necesita ese acceso.

Para construir el paquete desde el codigo:

```sh
./empaquetar.sh          # deja el .deb en dist/
```

### Desde el codigo, sin paquete

```sh
git clone https://github.com/k0braintheworld/k0pot.git
cd k0pot
./instalar.sh
```

Instala en tu directorio de usuario con servicios de systemd de usuario.
Mas rapido para desarrollar, pero el servicio hereda los grupos de tu
cuenta: si estas en `docker`, el sandbox de systemd es lo unico que separa
una trampa expuesta de tener root.

### Requisitos

- **Go 1.24 o superior** para compilar. Sin CGO: no hace falta gcc.
- **Docker y Docker Compose**, con tu usuario en el grupo `docker`.
- **Dos interfaces de red**, en redes distintas. Con una sola no hay
  aislamiento posible: el honeypot quedaria escuchando en tu propia red.
- Opcional: clave de [AbuseIPDB](https://www.abuseipdb.com) y de algun
  proveedor de IA. k0Pot funciona sin ninguna de las dos.

### A mano, si lo prefieres

```sh
cp .env.ejemplo .env
$EDITOR .env                 # K0POT_IP_EXPUESTA es OBLIGATORIA
mkdir -p data/cowrie/lib/{downloads,tty,snapshots} data/cowrie/log
go build -o k0pot ./cmd/k0pot
docker compose up -d
./k0pot -crear-usuario tunombre
cp deploy/k0pot-*.service ~/.config/systemd/user/
systemctl --user daemon-reload && systemctl --user enable --now k0pot-collector k0pot-panel
sudo loginctl enable-linger $USER    # si no, mueren al cerrar la sesion
```

Los volumenes tienen que existir **antes** de `docker compose up`: si los
crea Docker seran de root, Cowrie no podra escribir sus claves de host y ni
SSH ni Telnet arrancaran —con el contenedor apareciendo como `Up`.

### Ordenes utiles

```sh
./k0pot -resumen -dias 7      # resumen por consola
./k0pot -informe              # informe redactado
./k0pot -reclasificar         # revisa el historico con el criterio de hoy
./k0pot -usuarios             # cuentas del panel
```

## Actualizar

Desde el panel, en **Ajustes → Actualizaciones**: ves la version instalada y
puedes **subir el `.deb`** de una version nueva. El panel lo valida (que es un
paquete de verdad) y lo deja preparado, pero **no lo instala**.

Instalar un `.deb` es ejecutar codigo como root; el panel corre sin
privilegios a proposito, asi que un acceso al panel -expuesto a internet- no
puede volverse root del host. Por eso el ultimo paso lo das tu, en el
servidor:

```sh
sudo k0pot-actualizar
```

El ayudante comprueba con `dpkg` que el paquete subido es de verdad `k0pot`,
te ensena la version vieja y la nueva, **pide confirmacion**, instala con
`apt` y reinicia los servicios. El panel nunca invoca `sudo`: el unico que
instala eres tu, con tu contrasena.

La subida esta protegida por sesion y por comprobacion de origen (CSRF), con
tope de tamano y escritura atomica. En **Ajustes** puedes descartar un `.deb`
pendiente si te equivocaste.

Cuando el proyecto sea publico, lo correcto sera **releases firmados** y que
`k0pot-actualizar` verifique la firma antes de instalar; eso permitiria la
auto-actualizacion con seguridad. De momento el gate es tu `sudo`.

## Aislamiento de red: leelo antes de exponerlo

**Un honeypot es una maquina que invitas a que ataquen.** Si esta en la misma
red que tus equipos, le estas dando a un atacante un pie dentro de casa.

k0Pot separa la interfaz de gestion -por donde entras al panel- de la
interfaz expuesta -donde escuchan los honeypots-, pero eso **no es
aislamiento por si solo**: solo decide por donde escucha cada cosa. El
aislamiento de verdad son tres capas, y las tres hacen falta:

1. **Hipervisor o switch**: la interfaz expuesta en su propia VLAN.
2. **Router**: esa VLAN sin ruta hacia tu red interna.
3. **La propia maquina**: `deploy/aislamiento.nft`. Cubre lo que las otras
   dos no pueden — con `ip_forward` activo, que lo enciende Docker, el
   servidor actua de router entre ambas redes y un atacante puede usarlo de
   pasarela para saltarse el bloqueo del router.

Aplicalo siempre con el ayudante, que valida las IP antes de cargar y
revierte solo a los 120 segundos si no confirmas:

```sh
# symlink, NO copia: el script se busca sus .nft junto a si mismo, y copiado
# a /usr/local/sbin no los encontraria.
sudo ln -sf "$PWD/deploy/k0pot-nft.sh" /usr/local/sbin/k0pot-nft
sudo k0pot-nft aplicar
sudo k0pot-nft confirmar      # desde OTRA sesion, antes de 2 minutos
```

Con el paquete esto es automatico: `k0pot-nft` ya queda instalado (como
symlink) y el asistente genera el fichero de reglas con tus IP.

Un `nft -f` a pelo con `policy drop` es la forma mas rapida de quedarse fuera
de un servidor remoto.

Para comprobarlo desde fuera: `deploy/comprobar-aislamiento.sh <IP-expuesta>
<IP-gestion>`, ejecutado **desde otra maquina**. Desde el propio servidor no
demuestra nada.

## Ficha de una IP

Un ataque suelto no puede responder la pregunta que mas importa cuando una
direccion reaparece: **¿esta ya habia venido?** Sin ficha, una IP que vuelve
manana produce dos ataques sin relacion aparente.

Pulsando la IP en cualquier ataque se abre su ficha: primera y ultima vez,
cuantos ataques, cuantos eventos, que servicios ha tocado, lo peor que
llego a hacer, y su contexto en AbuseIPDB.

Arriba, en una frase, el veredicto que distingue insistir de progresar:

> Ha vuelto: 3 ataques a lo largo de 3 dias. Consiguio entrar.
> **Fue a mas con el tiempo: empezo mas suave de lo que acabo.**

Esa ultima linea sale de comparar su primer ataque con el peor. Un escaner
de paso repite lo mismo; alguien que progresa empieza tanteando y acaba
entrando, y eso solo se ve mirando su historia entera.

La ficha **no se recorta por el periodo en pantalla**: la gracia es ver todo
lo que ha hecho esa direccion, no solo lo de los ultimos siete dias.

## Consultar: filtrar y buscar

Un honeypot expuesto acumula cientos de ataques. Sin poder acotar, la lista
deja de servir para consultar y solo sirve para mirar lo ultimo.

Sobre la lista hay una barra con tres cosas:

- **Buscar** por IP -entera o a trozos-, pais, proveedor, servicio o por lo
  que hicieron. Se busca en todos esos campos a la vez, porque quien
  consulta recuerda un dato, no en que columna esta guardado.
- **Gravedad minima**: de "toda" a "solo intrusiones".
- **Servicio**: cualquiera de los activos (SSH, Telnet, HTTP, Redis, FTP,
  MySQL, PostgreSQL, SMTP, RDP, VNC, Docker). La lista se genera sola.

Con filtro puesto la lista **lo dice**: una lista corta sin explicacion se
lee como "no ha pasado nada", que es justo lo contrario.

Y al abrir un ataque, **la IP es pulsable**: filtra por ella y ensena todo
lo que ha hecho esa direccion. Es la forma mas corta de responder "¿esta
IP ya habia venido antes?" sin construir una pantalla aparte.

## Exportar un informe

El boton **Generar informe** de la cabecera abre un documento HTML completo y
autocontenido: el veredicto, las cifras, y **cada ataque con su secuencia
entera** -conexiones, credenciales probadas, comandos tal y como se tecleron,
peticiones, tuneles- mas las IPs mas activas y las credenciales.

Para PDF: desde ese documento, **Imprimir → Guardar como PDF** del navegador.
Se hace asi -y no con un generador de PDF propio- porque el HTML impreso queda
mejor y no arrastra dependencias.

El informe se arma con `html/template`, que auto-escapa: un comando de
atacante con `<script>` sale como texto, nunca como HTML. Es la misma garantia
del panel, en un fichero que puede compartirse o guardarse como evidencia.

## Retencion

Dos plazos, no uno, porque no cuestan lo mismo:

- **Eventos** (Ajustes → General): el detalle de cada linea capturada, con
  las grabaciones de sesion y los binarios que descargue Cowrie. Es lo que
  ocupa de verdad —un evento son cientos de bytes, una grabacion puede ser
  megas— y caduca pronto: nadie consulta la linea exacta de un escaneo de
  hace tres meses.
- **Ataques**: el resumen agrupado. Ocupa una fraccion y es lo que responde
  *"¿esta IP ya habia venido?"* meses despues, asi que conviene un plazo
  bastante mas largo.

Tirar los dos con el mismo plazo es lo intuitivo y lo peor: se pierde la
memoria larga para ahorrar lo que no ocupaba. `0` conserva para siempre.

El panel ensena **cuanto ocupa cada cosa** al abrir los ajustes, porque
elegir un plazo sin ese dato es elegir a ojo. Y cuenta el fichero `-wal` de
SQLite, que puede ser mayor que la propia base.

## Como gasta la IA (con cabeza)

El principio: **mirar el panel jamas cuesta dinero, y la IA trabaja sola pero
con freno**.

- **El panel es gratis y siempre al dia.** Semaforo, reparto por gravedad y
  por servicio, metricas y el informe completo se calculan con reglas
  deterministas. Ningun refresco llama a un modelo.
- **La IA trabaja en segundo plano, no al abrir.** Aprende los comandos y
  redacta las narrativas por su cuenta, a ritmo lento. Abrir un ataque no
  dispara ninguna llamada: todo sale de lo ya aprendido.
- **Respeta los limites del proveedor.** Si el modelo corta por cuota de
  tokens —habitual en los tiers gratuitos—, k0Pot hace pausa, lo avisa en la
  cabecera y se reactiva solo en cuanto vuelve a haber.
- **Nace con conocimiento de fabrica**, asi que el gasto de arranque es minimo:
  solo aprende lo que tu honeypot ve por primera vez.

### Cuando se acaban los tokens

Los proveedores gratuitos (Groq, Gemini...) no cobran, pero limitan —por tokens
al dia, o por minuto—. Cuando un modelo se agota, k0Pot **no insiste con el**:
lo pausa y, si tienes otro configurado, **sigue con ese** sin que te enteres. Si
se agotan TODOS, lo dice en la cabecera con un indicador ambar (*"tokens
agotados"*) y **se reactiva solo** en cuanto alguno libera cuota (por minuto en
segundos, por dia al reiniciarse la ventana). Por eso configurar dos proveedores
—p. ej. Groq y Gemini— hace que casi nunca te quedes sin explicaciones.

Mientras tanto **no se rompe nada**: el panel, el semaforo, la agrupacion, el
catalogo de fabrica y **todo lo ya aprendido** siguen igual, porque salen de
memoria y de reglas, no del modelo. Lo unico que espera es la explicacion de lo
que k0Pot ve *por primera vez*; y como reserva el 30% de la cuota para lo que
abras tu, casi siempre queda margen para lo que de verdad estas mirando. Si te
quedas corto a menudo, sube el tope diario en *Ajustes -> Informes*, cambia a
un proveedor con mas cuota, o deja que se ponga al dia solo en unos dias.

## Los textos hablan de un senuelo, no de un servidor comprometido

Un modelo de lenguaje al que le cuentas que alguien entro como root por SSH
escribe lo que escribiria cualquier analista: aisla la maquina, bloquea esa
IP, cambia las contrasenas, contiene el incidente.

Es buen consejo para otro sistema y **exactamente lo contrario** de lo que
hay que hacer con este. En un honeypot que alguien consiga entrar no es un
incidente: es la trampa haciendo su trabajo. Cerrarlo es apagarlo.

Asi que el modelo recibe ese encuadre por delante de todo lo demas, con la
lista de acciones que no debe proponer. En su lugar se le pide lo que si
aporta: que buscaban, que habria significado en un servidor de verdad, y que
credenciales o ficheros estan circulando.

Con una excepcion, que si es un problema real: **si el senuelo se esta
usando para danar a terceros** -reenviar trafico, servir de rele, atacar
hacia fuera-, eso hay que decirlo con claridad y actuar.

## Desde tu ultima visita

El panel ensena siempre la misma lista, asi que sin ayuda no hay forma de
saber que es nuevo: se relee lo mismo cada vez y se acaba dejando de leer.

En la cabecera aparece un contador -*"2 nuevos · 1 grave"*- y las filas
posteriores a tu ultima revision quedan marcadas. Pulsar el contador las da
por vistas.

Tres detalles pensados:

- **Es por usuario**, no global: lo que ha visto uno no dice nada de lo que
  ha visto otro.
- **Marcar como visto es explicito.** Si se hiciera al cargar la pagina, el
  aviso desapareceria antes de que nadie lo leyera.
- **Estrenar el panel no anuncia todo el historico.** Sin revision previa el
  corte es el momento de la primera consulta: "247 ataques nuevos" el primer
  dia no informa de nada.

Si un ataque **continua** despues de darlo por visto, vuelve a contar como
nuevo. No es lo mismo un ataque terminado que uno que sigue pasando.

## Ubicar los ataques por ciudad

De serie, las lineas de ataque salen del centro del pais del atacante: cientos
de kilometros de imprecision, y todas las IP de un mismo pais amontonadas en el
mismo punto. AbuseIPDB solo da el pais, asi que para afinar hace falta otra
fuente.

Con una base **GeoLite2-City de MaxMind** -un fichero local, sin llamadas a
terceros ni limites de consultas- cada IP se situa en su ciudad exacta:

1. Crea una cuenta gratuita en [maxmind.com](https://www.maxmind.com) y descarga
   `GeoLite2-City.mmdb`.
2. En Ajustes → General → *Base GeoIP*, pulsa **Subir base GeoIP** y elige el
   fichero. k0Pot lo valida -que sea de ciudad y no otra cosa-, lo deja en su
   sitio y lo activa. No hay que tocar el servidor ni teclear rutas.

Al subir una base, las IP que ya se conocian de ataques anteriores se situan
en el acto -es una consulta al fichero local, no gasta cuota de AbuseIPDB-,
asi que el mapa se ilumina enseguida en vez de dentro de una semana.

Es **opcional**: sin fichero, k0Pot funciona igual y el mapa se conforma con el
pais. La ubicacion de ciudad no gasta cuota de AbuseIPDB —es una consulta a un
fichero local— y no envia la IP a nadie mas.

El lector de la base es Go puro: no rompe la compilacion sin CGO.

## Situar el honeypot en el mapa

El mapa traza las lineas de ataque hacia donde esta la maquina. Con solo el
pais, la marca va al **centroide**, que en un pais grande queda a cientos de
kilometros de donde esta de verdad.

En Ajustes → General hay un mapa pequeno: **pincha donde estas** y se
guardan latitud y longitud. Tambien se pueden escribir a mano, y "Usar solo
el pais" vuelve al centroide.

Se eligio un mapa pulsable en vez de una lista de comunidades o regiones
porque es mas preciso —dentro de una region tambien hay cientos de
kilometros—, no depende de mantener datos de subdivisiones de doscientos
paises, y no hay que explicar como se usa.

La conversion entre coordenadas y el lienzo usa la misma proyeccion
equirectangular con la que se genera el mapa en `tools/genmapa.py`. Un test
comprueba que las dos formulas siguen coincidiendo: si divergieran, la marca
apareceria desplazada respecto a los paises y no habria forma de saber por
que.

## Panel por HTTPS

El panel pide una contrasena y devuelve todo lo capturado. Sin cifrar, eso
viaja en claro por la red —incluida la propia contrasena.

Se activa en **Ajustes → General** y requiere reiniciar el panel. Si no
indicas certificado propio, k0Pot **genera uno autofirmado** la primera vez,
valido dos anos y renovado antes de caducar. El navegador avisara la primera
vez, y es correcto: no hay ninguna autoridad que pueda verificar un panel de
red interna. Lo que si cambia es que el trafico va cifrado.

Detalles que evitan los tropiezos tipicos:

- **El puerto atiende los dos protocolos.** Quien llegue con el enlace viejo
  `http://…` recibe un 308 hacia `https://` en vez de un error ilegible o un
  timeout. Se mira el primer byte de la conexion: `0x16` es el saludo de TLS.
- **La cookie de sesion se marca `Secure`** automaticamente, y se anade
  `Strict-Transport-Security`.
- **El certificado solo incluye la direccion del panel.** Enumerar todas las
  interfaces seria comodo, pero un certificado publica lo que contiene: ahi
  apareceria la IP expuesta del honeypot y las redes de Docker. Es un mapa de
  la maquina a cambio de ahorrarse escribir bien una direccion.

Con certificado propio: pon las rutas del `.crt` y el `.key` en esos mismos
ajustes y se usaran tal cual.

## Avisos

Un panel solo avisa a quien lo tiene abierto. La primera intrusion real de
este honeypot ocurrio a las 11:40 y se descubrio horas despues, porque a
alguien le dio por abrir el navegador.

k0Pot puede escribirte cuando alguien **consigue entrar** o **se sirve de la
maquina**, por ntfy, Telegram o un webhook propio. Se configura en Ajustes →
Avisos, con un boton para mandarse uno de prueba: un aviso que no llega el
dia que hace falta no se distingue de no tener avisos.

Dos decisiones que evitan el fallo tipico de este tipo de sistemas:

- **Solo lo grave.** Un honeypot expuesto genera cientos de eventos al dia.
  Mandarlos todos garantiza que se dejen de leer, que es peor que no mandar
  ninguno.
- **Uno por ataque, no por evento**, y solo una vez. Si el ataque empeora
  -de "entro" a "entro y ademas actuo"- se avisa de nuevo, porque la
  situacion ha cambiado. Si sigue igual, no.

## Endurecimiento del servicio

Las trampas de HTTP, Redis y FTP corren **dentro del proceso del collector,
sobre el anfitrion**, no en un contenedor como Cowrie. El sandbox de systemd
es lo unico que las separa del resto de la maquina, asi que conviene que sea
explicito.

En `deploy/` hay dos variantes:

| | Unidades de usuario | Unidades de sistema (`deploy/sistema/`) |
|---|---|---|
| Instalacion | sin root | requiere root |
| Sandbox base | si | si |
| Soltar capacidades, `PrivateDevices`, `ProtectClock` | **no puede** | si |
| Ocultar `~/.ssh` y el resto del home | **no puede** | si |
| Sacar el proceso del grupo `docker` | no | si |

La columna de la izquierda no es una eleccion de diseno: en una unidad de
usuario esas directivas **se aceptan y no hacen nada**. `systemctl show` las
da por configuradas, pero `/proc/PID/mountinfo` no muestra ningun montaje y
el fichero sigue siendo legible. Estan documentadas en los propios ficheros
para que nadie las de por buenas.

Si el usuario que ejecuta k0Pot pertenece al grupo `docker` -que equivale a
root, porque basta un contenedor con el disco montado-, la variante de
sistema es la unica que puede quitarselo al proceso.

## Decisiones de diseno

| Area | Decision | Motivo |
|---|---|---|
| Alcance | Wrapper sobre Cowrie, no honeypot propio | Los honeypots maduros ya estan resueltos; uno mal hecho es una puerta real |
| Lenguaje | Go, binario unico | Despliegue trivial y poco consumo de memoria |
| Base de datos | SQLite via `modernc.org/sqlite` | Cero configuracion y sin CGO |
| IA | Aprende sola en segundo plano; varios modelos con failover automatico; abrir nunca llama al modelo | El panel refresca cada 20 s: gastar al mirar quemaria la cuota; cada modelo se limita por su proveedor |
| Contexto | Catalogo propio + lo aprendido y guardado, no la memoria suelta del modelo | Un modelo explica de memoria una ruta con el mismo aplomo acierte o no; k0Pot guarda lo que aprende |
| Idioma | Espanol en codigo y comentarios | El proyecto se escribe y se lee en espanol |

Sobre la penultima: cuando k0Pot no sabe que significa algo, **no lo inventa**.
Una ruta desconocida aparece descrita y sin interpretar. Quien lee el panel no
tiene forma de distinguir una explicacion buena de una inventada, asi que
callar es mas honesto que acertar a veces.

## Licencia

MIT. Ver [LICENSE](LICENSE).

Cowrie se ejecuta como contenedor independiente y se lee su registro; no se
enlaza su codigo, asi que su licencia no alcanza a este proyecto.
