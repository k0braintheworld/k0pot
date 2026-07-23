#!/bin/bash
#
# Aplicador del cortafuegos de k0Pot, con red de seguridad.
#
# Cargar "nft -f" a pelo un ruleset con "policy drop" es la forma mas
# rapida de quedarse fuera de un servidor remoto: si el nombre de una
# interfaz no coincide, o una IP cambio, la regla que te deja entrar no
# casa, la politica se impone y pierdes el acceso. nftables no avisa: un
# iifname inexistente es sintacticamente valido, simplemente no casa nunca.
#
# Aqui se hacen tres cosas antes y despues de cargar:
#   1. Se valida que las IP del fichero existan de verdad en la maquina.
#   2. Se guarda el ruleset actual para poder deshacer.
#   3. Se arma un temporizador que revierte solo a los 120 s salvo que
#      confirmes DESDE LA SESION NUEVA. Si te equivocas, esperas dos
#      minutos y vuelves a entrar, sin pedir la consola del hipervisor.
#
# Uso:
#   sudo k0pot-nft aplicar [fichero]
#   sudo k0pot-nft confirmar
#   sudo k0pot-nft revertir
#   sudo k0pot-nft estado
#
set -uo pipefail

# El fichero del repositorio lleva valores de EJEMPLO. Si existe una copia
# .local.nft -ignorada por git- se usa esa: asi tu direccionamiento real no
# acaba en el repositorio y actualizar el proyecto no te pisa la config.
BASE="$(cd "$(dirname "$(readlink -f "$0")")" 2>/dev/null && pwd || echo /home/k0pot/k0pot/deploy)"
if [ -r "$BASE/aislamiento.local.nft" ]; then
  FICHERO_POR_DEFECTO="$BASE/aislamiento.local.nft"
else
  FICHERO_POR_DEFECTO="$BASE/aislamiento.nft"
fi
RESPALDO=/var/backups/k0pot/ruleset-anterior.nft
APLICADO=/var/backups/k0pot/ultimo-aplicado
UNIDAD=k0pot-nft-revertir
MARGEN=120

rojo()  { printf "\033[31m%s\033[0m\n" "$*"; }
verde() { printf "\033[32m%s\033[0m\n" "$*"; }

if [ "$(id -u)" -ne 0 ]; then
  rojo "Hay que ejecutarlo como root: sudo $0 $*"
  exit 1
fi

# Extrae el valor de un "define" del fichero de reglas.
definicion() {
  sed -n "s/^[[:space:]]*define[[:space:]]\+$2[[:space:]]*=[[:space:]]*\([^[:space:]#]\+\).*/\1/p" "$1" | head -1
}

aplicar() {
  local fichero="${1:-$FICHERO_POR_DEFECTO}"

  [ -r "$fichero" ] || { rojo "No se puede leer $fichero"; exit 1; }

  # ── 1. Validacion ────────────────────────────────────────────────────
  echo "Comprobando $fichero"

  if ! nft -c -f "$fichero"; then
    rojo "El fichero tiene errores de sintaxis. No se aplica nada."
    exit 1
  fi
  echo "  sintaxis correcta"

  local fallos=0
  for nombre in IP_GESTION IP_EXPUESTA; do
    local ip
    ip="$(definicion "$fichero" "$nombre")"
    if [ -z "$ip" ]; then
      rojo "  falta 'define $nombre' en el fichero"
      fallos=$((fallos + 1))
      continue
    fi
    if ip -o -4 addr show | grep -qw "$ip"; then
      echo "  $nombre = $ip  (presente en la maquina)"
    else
      rojo "  $nombre = $ip  NO existe en esta maquina"
      fallos=$((fallos + 1))
    fi
  done

  # Las interfaces se avisan pero no bloquean: el ruleset esta anclado a
  # IP precisamente para sobrevivir a que cambien de nombre.
  for nombre in IF_GESTION IF_EXPUESTA; do
    local iface
    iface="$(definicion "$fichero" "$nombre" | tr -d '"')"
    if [ -n "$iface" ] && ! ip -o link show | grep -q ": $iface:"; then
      echo "  aviso: $nombre = $iface no existe (se ignora; manda la IP)"
    fi
  done

  if [ "$fallos" -gt 0 ]; then
    rojo ""
    rojo "$fallos problema(s). No se aplica nada: aplicarlo te dejaria fuera."
    rojo "Corrige los 'define' del principio de $fichero y repite."
    exit 1
  fi

  # ── 2. Respaldo ──────────────────────────────────────────────────────
  mkdir -p "$(dirname "$RESPALDO")"
  nft list ruleset > "$RESPALDO" 2>/dev/null || : > "$RESPALDO"
  echo "  ruleset actual guardado en $RESPALDO"
  readlink -f "$fichero" > "$APLICADO"

  # ── 3. Aplicar y armar el hombre muerto ──────────────────────────────
  systemctl stop "$UNIDAD.timer" 2>/dev/null
  systemd-run --quiet --on-active="$MARGEN" --unit="$UNIDAD" \
    "$(readlink -f "$0")" revertir-auto || {
      rojo "No se pudo armar el temporizador de reversion. No se aplica nada."
      exit 1
    }

  if ! nft -f "$fichero"; then
    rojo "Fallo al cargar. Revirtiendo ya."
    revertir
    exit 1
  fi

  verde ""
  verde "Reglas aplicadas."
  echo
  echo "  ABRE OTRA SESION AHORA y comprueba que entras."
  echo "  Si funciona, confirma dentro de $MARGEN segundos:"
  echo
  echo "      sudo k0pot-nft confirmar"
  echo
  echo "  Si no confirmas, a los $MARGEN s se revierte solo y recuperas el acceso."
}

confirmar() {
  if ! systemctl stop "$UNIDAD.timer" 2>/dev/null; then
    echo "No habia ninguna reversion pendiente. Nada que confirmar."
    return
  fi
  systemctl reset-failed "$UNIDAD.service" 2>/dev/null
  verde "Confirmado. Las reglas se quedan."

  # Persistir es parte de confirmar, no un paso aparte que se recuerda a
  # mano. Dejarlo suelto crea dos fuentes de verdad: el fichero que se
  # aplica y el que se carga al arrancar. Cuando divergen, un reinicio
  # devuelve en silencio a unas reglas viejas que nadie eligio.
  local fichero
  fichero="$(cat "$APLICADO" 2>/dev/null)"
  if [ -n "$fichero" ] && [ -r "$fichero" ]; then
    cp "$fichero" /etc/nftables.conf
    systemctl enable nftables >/dev/null 2>&1
    echo "  /etc/nftables.conf actualizado; sobrevive al reinicio"
  else
    rojo "  no se pudo persistir: no consta que fichero se aplico"
  fi
}

revertir() {
  systemctl stop "$UNIDAD.timer" 2>/dev/null
  systemctl reset-failed "$UNIDAD.service" 2>/dev/null
  nft flush ruleset
  if [ -s "$RESPALDO" ]; then
    nft -f "$RESPALDO" && echo "Restaurado el ruleset anterior."
  else
    echo "No habia ruleset previo: el cortafuegos queda vacio (todo abierto)."
  fi
}

estado() {
  if systemctl is-active --quiet "$UNIDAD.timer"; then
    rojo "REVERSION PENDIENTE — se deshara solo si no confirmas."
    systemctl list-timers "$UNIDAD.timer" --no-pager 2>/dev/null | sed -n 2p
    echo "  confirmar con: sudo k0pot-nft confirmar"
  else
    verde "Sin reversion pendiente."
  fi
  echo
  echo "Tablas cargadas:"
  nft list tables 2>/dev/null | sed "s/^/  /" || echo "  (ninguna)"

  # Lo que se aplica y lo que se carga al arrancar son dos ficheros
  # distintos. Que coincidan no es evidente, y cuando divergen el fallo
  # aparece semanas despues, en un reinicio, sin nada que lo relacione.
  echo
  echo "Al reiniciar:"
  local aplicado
  aplicado="$(cat "$APLICADO" 2>/dev/null)"
  if ! systemctl is-enabled nftables >/dev/null 2>&1; then
    rojo "  nftables NO esta habilitado: al reiniciar no habra reglas"
  elif [ -z "$aplicado" ]; then
    echo "  no consta que fichero se aplico; no se puede comprobar"
  elif [ ! -r /etc/nftables.conf ]; then
    rojo "  /etc/nftables.conf no existe: al reiniciar no habra reglas"
  elif diff -q "$aplicado" /etc/nftables.conf >/dev/null 2>&1; then
    verde "  se cargara lo mismo que hay ahora ($aplicado)"
  else
    rojo "  /etc/nftables.conf NO coincide con lo aplicado ($aplicado)"
    echo "  se corrige confirmando otra vez: sudo k0pot-nft confirmar"
  fi
}

case "${1:-}" in
  aplicar)       aplicar "${2:-}" ;;
  confirmar)     confirmar ;;
  revertir)      revertir ;;
  revertir-auto) logger -t k0pot-nft "sin confirmacion en ${MARGEN}s: revirtiendo"; revertir ;;
  estado)        estado ;;
  *)
    echo "Uso: sudo k0pot-nft {aplicar [fichero]|confirmar|revertir|estado}"
    exit 1
    ;;
esac
