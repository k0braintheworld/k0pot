#!/bin/bash
#
# Instalador de k0Pot.
#
# Existe porque instalarlo a mano son doce pasos y cada uno tiene una forma
# silenciosa de salir mal: volumenes creados por root que Cowrie no puede
# escribir, el contenedor publicado en todas las interfaces por no poner la
# IP delante, servicios que no arrancan tras un reinicio por no habilitar el
# linger. Todo eso ya ha pasado.
#
# Lo que este script NO hace, a proposito: aplicar el cortafuegos. Eso exige
# root y puede dejarte fuera del servidor, asi que se prepara el fichero con
# tus direcciones y se te dice como aplicarlo con la red de seguridad.
#
set -uo pipefail

BASE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
cd "$BASE" || exit 1

rojo()  { printf "\033[31m%s\033[0m\n" "$*"; }
verde() { printf "\033[32m%s\033[0m\n" "$*"; }
gris()  { printf "\033[90m%s\033[0m\n" "$*"; }
paso()  { printf "\n\033[1m== %s\033[0m\n" "$*"; }

fallo() { rojo "$*"; exit 1; }

# ── Comprobaciones previas ──────────────────────────────────────────────
paso "Comprobando el entorno"

[ "$(id -u)" -ne 0 ] || fallo \
  "No lo ejecutes como root: k0Pot corre como un usuario normal y sus datos
   quedarian en manos de root. Hazlo con tu propio usuario."

command -v go >/dev/null || fallo \
  "Falta Go. Instalalo (1.24 o superior) y vuelve a intentarlo."
echo "  Go:     $(go version | awk '{print $3}')"

command -v docker >/dev/null || fallo \
  "Falta Docker. Hace falta para Cowrie, que es el honeypot de SSH y Telnet."
if ! docker info >/dev/null 2>&1; then
  fallo "Docker no responde sin sudo. Anade tu usuario al grupo docker
   (sudo usermod -aG docker \$USER) y vuelve a entrar en la sesion."
fi
echo "  Docker: $(docker --version | awk '{print $3}' | tr -d ,)"

docker compose version >/dev/null 2>&1 || fallo \
  "Falta el plugin 'docker compose'."

# Dos copias del proyecto en la misma maquina comparten nombre de proyecto
# en Docker y se pisan el contenedor sin avisar. Paso de verdad.
ya="$(docker ps -a --filter name=k0pot-cowrie --format '{{.Label "com.docker.compose.project.working_dir"}}' | head -1)"
if [ -n "$ya" ] && [ "$ya" != "$BASE" ]; then
  fallo "Ya hay un k0Pot instalado en $ya.
   Dos copias comparten nombre de contenedor y se pisan la una a la otra.
   Usa esa instalacion, o borra la otra antes de seguir."
fi

# ── Red ─────────────────────────────────────────────────────────────────
paso "Interfaces de red"
echo "  Un honeypot necesita DOS: una para el panel -tu red- y otra"
echo "  expuesta, donde escuchan las trampas. Que sea la misma es"
echo "  invitar a un atacante a tu red."
echo
ip -o -4 addr show scope global | awk '{printf "    %-10s %s\n", $2, $4}'
echo

leer() { # leer <pregunta> <variable> [valor por defecto]
  local resp
  read -r -p "  $1${3:+ [$3]}: " resp
  printf -v "$2" '%s' "${resp:-${3:-}}"
}

leer "IP de GESTION (por donde entraras al panel)" IP_GESTION
leer "IP EXPUESTA (donde escucharan los honeypots)" IP_EXPUESTA

for v in IP_GESTION IP_EXPUESTA; do
  ip=${!v}
  [ -n "$ip" ] || fallo "Falta $v."
  ip -o -4 addr show | grep -qw "$ip" || fallo \
    "$ip no existe en esta maquina. Configurala antes de instalar."
done
[ "$IP_GESTION" != "$IP_EXPUESTA" ] || fallo \
  "Las dos IP son la misma. Asi no hay separacion posible: el honeypot
   quedaria escuchando en tu propia red."

red_de() { echo "$1" | cut -d. -f1-3; }
if [ "$(red_de "$IP_GESTION")" = "$(red_de "$IP_EXPUESTA")" ]; then
  rojo "  AVISO: las dos IP estan en la misma /24."
  rojo "  Eso NO es aislamiento: separa por donde escucha cada cosa, pero"
  rojo "  un atacante seguiria en tu red. Ponlas en VLAN distintas."
  leer "Seguir de todos modos (si/no)" SEGUIR "no"
  [ "$SEGUIR" = "si" ] || exit 1
fi

# ── Preparacion ─────────────────────────────────────────────────────────
paso "Preparando directorios"
# Si los crea Docker seran de root y Cowrie -que corre con tu UID- no podra
# escribir sus claves de host. Sin ellas no arrancan ni SSH ni Telnet, y el
# contenedor sigue apareciendo como "Up".
mkdir -p data/cowrie/lib/downloads data/cowrie/lib/tty data/cowrie/lib/snapshots \
         data/cowrie/log data/tls
chmod 700 data/tls
echo "  data/ listo, con tu usuario como dueno"

paso "Configuracion"
if [ ! -f .env ]; then
  cp .env.ejemplo .env
  echo "  .env creado a partir del ejemplo"
fi
# La IP expuesta es obligatoria: sin ella compose se niega a arrancar, para
# no publicar los honeypots en todas las interfaces.
if grep -q "^K0POT_IP_EXPUESTA=" .env; then
  sed -i "s|^K0POT_IP_EXPUESTA=.*|K0POT_IP_EXPUESTA=$IP_EXPUESTA|" .env
else
  echo "K0POT_IP_EXPUESTA=$IP_EXPUESTA" >> .env
fi
echo "  interfaz expuesta: $IP_EXPUESTA"
gris "  Las claves de API (AbuseIPDB, IA) son opcionales y se editan luego"
gris "  en .env o directamente desde el panel."

paso "Compilando"
go build -o k0pot ./cmd/k0pot || fallo "No compila."
echo "  binario listo: $(./k0pot -version 2>/dev/null || echo k0pot)"

paso "Arrancando Cowrie"
docker compose up -d || fallo "No se pudo levantar Cowrie."
echo "  Cowrie tarda unos segundos en escuchar; es normal."

# ── Cortafuegos, preparado pero SIN aplicar ─────────────────────────────
paso "Preparando el cortafuegos"
sed -e "s|^define IP_GESTION  = .*|define IP_GESTION  = $IP_GESTION|" \
    -e "s|^define IP_EXPUESTA = .*|define IP_EXPUESTA = $IP_EXPUESTA|" \
    -e "s|^define RED_GESTION = .*|define RED_GESTION = $(red_de "$IP_GESTION").0/24|" \
    deploy/aislamiento.nft > deploy/aislamiento.local.nft
echo "  deploy/aislamiento.local.nft escrito con tus direcciones"
gris "  No se aplica aqui: exige root y un error puede dejarte fuera."

# ── systemd ─────────────────────────────────────────────────────────────
paso "Servicios"
mkdir -p ~/.config/systemd/user
cp deploy/k0pot-collector.service deploy/k0pot-panel.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable k0pot-collector k0pot-panel >/dev/null 2>&1
echo "  unidades instaladas y habilitadas"

# Sin linger, los servicios de usuario mueren al cerrar la sesion SSH y no
# vuelven tras un reinicio. Es el fallo mas facil de no ver.
if [ "$(loginctl show-user "$USER" -p Linger --value 2>/dev/null)" != "yes" ]; then
  rojo "  FALTA: los servicios no sobreviviran a cerrar la sesion ni a un reinicio."
  echo "  Ejecuta:  sudo loginctl enable-linger $USER"
else
  echo "  linger activo: arrancan solos tras un reinicio"
fi

systemctl --user start k0pot-collector k0pot-panel 2>/dev/null

# ── Cuenta ──────────────────────────────────────────────────────────────
paso "Cuenta del panel"
if ./k0pot -usuarios 2>/dev/null | grep -q .; then
  echo "  ya hay cuentas creadas"
else
  echo "  Crea la primera cuenta:"
  ./k0pot -crear-usuario "${SUDO_USER:-$USER}"
fi

# ── Que queda ───────────────────────────────────────────────────────────
paso "Instalado. Lo que queda, y hay que hacerlo a mano"
cat <<FIN

  1. CORTAFUEGOS. Es lo que impide que un atacante salte del honeypot a tu
     red. Aplicalo con la red de seguridad -revierte solo a los 120 s si no
     confirmas- y ten a mano la consola del hipervisor:

       sudo install -m 755 deploy/k0pot-nft.sh /usr/local/sbin/k0pot-nft
       sudo k0pot-nft aplicar
       sudo k0pot-nft confirmar      # desde OTRA sesion, antes de 2 minutos

  2. PANEL. Entra en https://$IP_GESTION:8080 y activa HTTPS en
     Ajustes -> General si aun no lo esta. Ahi mismo eliges que honeypots
     quieres y en que puertos.

  3. AVISOS. Ajustes -> Avisos. Sin esto el panel solo avisa a quien lo
     tenga abierto.

  4. ROUTER. Redirige los puertos a $IP_EXPUESTA, NUNCA a $IP_GESTION.
     Apuntar a la de gestion meteria el trafico hostil en tu red.

  Comprueba el aislamiento DESDE OTRA MAQUINA antes de publicar:
     deploy/comprobar-aislamiento.sh $IP_EXPUESTA $IP_GESTION

FIN
verde "Listo."
