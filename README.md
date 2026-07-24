# k0Pot

Honeypot ligero que **explica** lo que pasa en lugar de limitarse a
registrarlo. Captura los ataques, separa el ruido de lo que importa y, cuando
quieres entender uno de verdad, **te lo cuenta con IA en lenguaje llano**
—que es, como funciona y que buscaban— sin que tengas que ser analista de
seguridad.

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
   saber. Un catalogo propio traduce lo rutinario al instante; y para lo que
   no basta con eso —entender un ataque entero, un binario capturado o una
   campana coordinada— esta el boton de **Explicar con IA**.

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

## Entender con IA: ataques, campanas y artefactos

Es lo que mas distingue a k0Pot. Cuando abres el detalle de algo y quieres
saber que esta pasando de verdad, tienes un boton de **Explicar con IA** que
lo cuenta para alguien con conocimientos minimos, **traduciendo cada
termino**. Esta en los tres sitios donde importa:

- **Un ataque** — que buscaban, **como funciona la tecnica paso a paso**,
  hasta donde llegaron, y que significaria en un servidor de verdad.
- **Una campana** (varias IPs con el mismo guion) — que operacion coordinada
  hay detras y por que reparten el trabajo entre tantas direcciones.
- **Un artefacto capturado** (posible malware) — que es y que hace, deducido
  de su tipo y de las cadenas de texto que lleva dentro, **sin ejecutarlo**.

La explicacion de un ataque sigue esta forma, en prosa llana:

1. **Que buscan.** El proposito en una frase.
2. **Como funciona.** Que tecnica es, por que funciona y como se encadenan
   los pasos del registro.
3. **Hasta donde llegaron.** "No pasaron de llamar a la puerta" es una
   respuesta perfecta y frecuente.
4. **Que significaria en un servidor de verdad**, y que revisar alli.

Cada explicacion se **guarda** con lo explicado (por su clave, hash o
huella), asi que reabrirlo no vuelve a gastar. El encuadre es defensivo: al
modelo se le dice por delante de todo que esto es un **senuelo** y que NO
recomiende aislar la maquina ni cerrar la trampa (ver *"Los textos hablan de
un senuelo"* mas abajo).

**El proveedor es intercambiable.** Vale cualquier API compatible con OpenAI
—Groq, OpenRouter, Mistral, Together, Ollama— o la de Anthropic; se elige en
Ajustes. **Sin clave, k0Pot funciona igual**: solo se apagan las
explicaciones, y todo lo demas (semaforo, agrupacion, catalogo, informe) se
calcula con reglas, gratis. Ademas **la IA nunca se gasta sola** (ver mas
abajo): solo cuando pulsas, y una llamada que el proveedor rechaza no
consume cuota.

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

Se activan y desactivan desde el panel. Los puertos son configurables; el
panel indica a cuales hay que redirigir el trafico.

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

## La IA nunca se gasta sola

El principio: **nada que cueste dinero ocurre sin que lo pidas**.

- **El panel es gratis y siempre al dia.** El semaforo, el reparto por
  gravedad y por servicio y las metricas se calculan con reglas
  deterministas, al momento. Ningun refresco llama a un modelo de pago.
- **La IA entra solo cuando pulsas.** "Explicar con IA" en un ataque, una
  campana o un artefacto es el unico gasto, y es justo el momento en que
  alguien quiere entender algo. Cada explicacion se guarda: reabrirla no
  vuelve a gastar.
- **El informe completo** ("Generar informe") es un documento con toda la
  actividad, redactado por reglas: se abre cuantas veces quieras sin coste.

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
| Informes | Reglas siempre; IA solo a peticion | El panel refresca cada 20 s: que eso costara dinero gastaria la cuota en mirar |
| Contexto | Catalogo propio, no memoria del modelo | Un modelo explica de memoria que es una ruta con el mismo aplomo acierte o no |
| Idioma | Espanol en codigo y comentarios | El proyecto se escribe y se lee en espanol |

Sobre la penultima: cuando k0Pot no sabe que significa algo, **no lo inventa**.
Una ruta desconocida aparece descrita y sin interpretar. Quien lee el panel no
tiene forma de distinguir una explicacion buena de una inventada, asi que
callar es mas honesto que acertar a veces.

## Licencia

MIT. Ver [LICENSE](LICENSE).

Cowrie se ejecuta como contenedor independiente y se lee su registro; no se
enlaza su codigo, asi que su licencia no alcanza a este proyecto.
