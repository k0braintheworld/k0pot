#!/usr/bin/env bash
# Comprueba si el aislamiento del honeypot es real.
#
# Se ejecuta DESDE OTRA MAQUINA de la red interna, no desde el servidor:
# probar el aislamiento desde dentro no demuestra nada.
#
#   ./comprobar-aislamiento.sh <IP-expuesta> <IP-de-gestion>
set -u

EXPUESTA="${1:?falta la IP expuesta}"
GESTION="${2:?falta la IP de gestion}"
fallos=0

probar () { # descripcion  puerto  esperado(abierto|cerrado)
  local desc="$1" ip="$2" puerto="$3" esperado="$4"
  if nc -z -w 3 "$ip" "$puerto" 2>/dev/null; then real="abierto"; else real="cerrado"; fi
  if [ "$real" = "$esperado" ]; then
    printf "  OK    %-46s %s\n" "$desc" "$real"
  else
    printf "  FALLO %-46s %s (esperaba %s)\n" "$desc" "$real" "$esperado"
    fallos=$((fallos+1))
  fi
}

# Si no se llega ni a la red expuesta, no se puede concluir nada sobre sus
# puertos: hay que ejecutar esto DESDE esa red.
alcanzable="si"
if ! ping -c 1 -W 2 "$EXPUESTA" >/dev/null 2>&1 && ! nc -z -w 3 "$EXPUESTA" 22 2>/dev/null; then
  alcanzable="no"
fi

if [ "$alcanzable" = "no" ]; then
  echo "== Interfaz expuesta ($EXPUESTA): NO SE ALCANZA desde aqui =="
  echo "   Eso es lo esperado si estas en la red interna y el aislamiento"
  echo "   funciona. Para comprobar que los honeypots responden, ejecuta"
  echo "   este script desde la red expuesta o desde internet."
  echo
  echo "== Interfaz de gestion ($GESTION) =="
  probar "panel de k0pot" "$GESTION" 8080 abierto
  probar "SSH real"       "$GESTION"   22 abierto
  echo
  [ "$fallos" -eq 0 ] && echo "Gestion correcta; la parte expuesta queda sin comprobar." \
                      || echo "$fallos comprobacion(es) fallida(s)."
  exit $((fallos > 0))
fi

echo "== Interfaz expuesta ($EXPUESTA): solo honeypots =="
probar "SSH del honeypot (Cowrie)"        "$EXPUESTA" 2222 abierto
probar "Telnet del honeypot"              "$EXPUESTA" 2223 abierto
probar "SSH REAL del servidor"            "$EXPUESTA"   22 cerrado
probar "panel de k0pot"                   "$EXPUESTA" 8080 cerrado

echo "== Interfaz de gestion ($GESTION) =="
probar "panel de k0pot"                   "$GESTION"  8080 abierto
probar "SSH real"                         "$GESTION"    22 abierto

echo
if [ "$EXPUESTA" = "$GESTION" ]; then
  echo "AVISO: has dado la misma IP dos veces."
fi
# Misma /24 en ambas: no hay separacion posible, lo diga quien lo diga.
if [ "${EXPUESTA%.*}" = "${GESTION%.*}" ]; then
  echo "PELIGRO: ambas IPs estan en la misma red /24."
  echo "         No hay aislamiento: quien llega a una, llega a la otra."
  echo "         Separa las redes en el hipervisor y el router primero."
  fallos=$((fallos+1))
fi

[ "$fallos" -eq 0 ] && echo "Aislamiento correcto." || echo "$fallos comprobacion(es) fallida(s)."
exit $((fallos > 0))
