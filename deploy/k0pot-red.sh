#!/usr/bin/env bash
#
# Ayudante privilegiado de k0Pot para la configuracion de red.
#
# Es lo UNICO que k0pot puede ejecutar como root, y a proposito hace muy
# poco: escribe un fichero de netplan propio, lo valida y lo aplica con un
# temporizador que lo revierte solo. Cambiar mal una IP en un servidor
# remoto te deja fuera, asi que la vuelta atras no es opcional.
#
#   k0pot-red.sh aplicar   < config.yaml   aplica con reversion automatica
#   k0pot-red.sh confirmar                 cancela la reversion
#   k0pot-red.sh revertir                  vuelve atras ya
#   k0pot-red.sh mostrar                   imprime la configuracion actual
#
set -euo pipefail

DESTINO=/etc/netplan/90-k0pot.yaml
COPIA=/var/lib/k0pot/90-k0pot.yaml.anterior
TESTIGO=/var/lib/k0pot/red-pendiente
# Margen para que el operador compruebe que sigue teniendo acceso.
ESPERA=${K0POT_ESPERA:-120}

mkdir -p /var/lib/k0pot

case "${1:-}" in
aplicar)
  nuevo=$(mktemp /tmp/k0pot-red.XXXXXX.yaml)
  trap 'rm -f "$nuevo"' EXIT
  cat > "$nuevo"

  # Netplan exige 0600: si no, avisa y puede negarse a leerlo.
  chmod 600 "$nuevo"

  # Guardar lo que hubiera para poder deshacer.
  if [ -f "$DESTINO" ]; then cp -a "$DESTINO" "$COPIA"; else rm -f "$COPIA"; fi

  cp -a "$nuevo" "$DESTINO"
  chmod 600 "$DESTINO"

  # generate valida la sintaxis y la coherencia ANTES de tocar la red.
  if ! netplan generate 2>&1; then
    echo "configuracion invalida; se deshace" >&2
    if [ -f "$COPIA" ]; then cp -a "$COPIA" "$DESTINO"; else rm -f "$DESTINO"; fi
    netplan generate >/dev/null 2>&1 || true
    exit 1
  fi

  # Interruptor de hombre muerto: si nadie confirma, se revierte solo.
  date +%s > "$TESTIGO"
  setsid bash -c "
    sleep $ESPERA
    if [ -f '$TESTIGO' ]; then
      logger -t k0pot-red 'nadie confirmo el cambio de red: revirtiendo'
      if [ -f '$COPIA' ]; then cp -a '$COPIA' '$DESTINO'; else rm -f '$DESTINO'; fi
      netplan apply
      rm -f '$TESTIGO'
    fi
  " >/dev/null 2>&1 < /dev/null &

  netplan apply
  echo "aplicado; se revertira en ${ESPERA}s salvo que se confirme"
  ;;

confirmar)
  rm -f "$TESTIGO"
  echo "confirmado; no habra reversion"
  ;;

revertir)
  rm -f "$TESTIGO"
  if [ -f "$COPIA" ]; then cp -a "$COPIA" "$DESTINO"; else rm -f "$DESTINO"; fi
  netplan apply
  echo "revertido"
  ;;

mostrar)
  [ -f "$DESTINO" ] && cat "$DESTINO" || echo "# sin configuracion propia de k0pot"
  ;;

*)
  echo "uso: $0 {aplicar|confirmar|revertir|mostrar}" >&2
  exit 2
  ;;
esac
