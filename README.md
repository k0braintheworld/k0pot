# k0Pot

Honeypot ligero que explica lo que pasa en lugar de limitarse a registrarlo.

Alternativa simplificada a [T-Pot](https://github.com/telekom-security/tpotce):
en vez de veinte honeypots sobre un stack ELK de 16 GB, reutiliza los que ya
funcionan bien y aporta la capa que suele faltar — **traducir los ataques a
lenguaje que se entienda sin ser analista de seguridad**.

> **Estado: en desarrollo.** Funciona y captura ataques reales, pero cambia a
> menudo y no ha pasado por una auditoria independiente.

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
   saber.

## Como funciona

```
   internet
      |
      v
 [ Cowrie ]  SSH y Telnet, en contenedor
 [ trampas ] HTTP, Redis, FTP, nativas en Go
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

## Servicios

| Servicio | Puerto por defecto | Motor |
|---|---|---|
| SSH | 2222 | Cowrie (shell emulada completa) |
| Telnet | 2223 | Cowrie |
| HTTP | 8081 | nativo |
| Redis | 6379 | nativo |
| FTP | 2121 | nativo |

Se activan y desactivan desde el panel. Los puertos son configurables; el
panel indica a cuales hay que redirigir el trafico.

## Requisitos

- Go 1.24 o superior para compilar. Sin CGO: no hace falta gcc.
- Docker y Docker Compose para Cowrie.
- Opcional: clave de [AbuseIPDB](https://www.abuseipdb.com) (1.000 consultas
  gratis al dia) para saber quien esta detras de cada IP.
- Opcional: cualquier API compatible con OpenAI (Groq, OpenRouter, Mistral,
  Ollama en local) o Anthropic, para los informes en lenguaje natural.

**k0Pot funciona sin ninguna de las dos claves.** Sin AbuseIPDB no enriquece
las IPs; sin proveedor de IA los informes los redactan las reglas, que son
deterministas, instantaneas y gratis.

## Primeros pasos

```sh
git clone https://github.com/k0braintheworld/k0pot.git
cd k0pot
cp .env.ejemplo .env        # opcional: claves de API

# Los volumenes de Cowrie tienen que existir y ser tuyos. Si los crea
# Docker seran de root y Cowrie no podra escribir sus claves de host.
mkdir -p data/cowrie/lib/{downloads,tty,snapshots} data/cowrie/log

go build -o k0pot ./cmd/k0pot
docker compose up -d
./k0pot -crear-usuario tunombre
./k0pot -web 127.0.0.1:8080
```

El panel queda en `http://127.0.0.1:8080`. Para dejarlo corriendo solo, en
`deploy/` hay unidades de systemd de usuario.

Otras ordenes utiles:

```sh
./k0pot -resumen -dias 7      # resumen por consola
./k0pot -informe              # informe redactado
./k0pot -reclasificar         # revisa el historico con el criterio de hoy
./k0pot -usuarios             # cuentas del panel
```

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
sudo install -m 755 deploy/k0pot-nft.sh /usr/local/sbin/k0pot-nft
sudo k0pot-nft aplicar
sudo k0pot-nft confirmar      # desde OTRA sesion, antes de 2 minutos
```

Un `nft -f` a pelo con `policy drop` es la forma mas rapida de quedarse fuera
de un servidor remoto.

Para comprobarlo desde fuera: `deploy/comprobar-aislamiento.sh <IP-expuesta>
<IP-gestion>`, ejecutado **desde otra maquina**. Desde el propio servidor no
demuestra nada.

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
| Informes | Reglas + IA opcional | Las reglas cubren lo rutinario gratis; la IA solo donde aporta |
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
