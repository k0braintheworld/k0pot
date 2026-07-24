#!/bin/bash
#
# Aplica una actualizacion de k0Pot subida desde el panel.
#
# El panel corre sin privilegios y NO instala nada: deja el .deb preparado, y
# este ayudante -que ejecutas TU con sudo- lo verifica y lo instala. Asi,
# comprometer el panel expuesto a internet no da root en el host: el unico que
# instala eres tu, escribiendo tu contrasena.
#
set -uo pipefail

DEB="${1:-/var/lib/k0pot/actualizacion.deb}"

rojo()  { printf "\033[31m%s\033[0m\n" "$*"; }
verde() { printf "\033[32m%s\033[0m\n" "$*"; }

if [ "$(id -u)" -ne 0 ]; then
  rojo "Ejecutalo con sudo: sudo k0pot-actualizar"
  exit 1
fi

if [ ! -r "$DEB" ]; then
  rojo "No hay ninguna actualizacion preparada en $DEB."
  echo "Sube el .deb desde el panel (Ajustes -> Actualizaciones) y repite."
  exit 1
fi

command -v dpkg-deb >/dev/null || { rojo "Falta dpkg-deb."; exit 1; }

# Verificar que de verdad es el paquete k0pot antes de tocar nada. dpkg es la
# validacion autoritativa: un .deb cualquiera se rechaza aqui.
info="$(dpkg-deb --info "$DEB" 2>/dev/null)" || { rojo "El fichero no es un .deb valido."; exit 1; }
paquete="$(printf '%s\n' "$info" | sed -n 's/^ *Package: *//p' | head -1)"
version="$(printf '%s\n' "$info" | sed -n 's/^ *Version: *//p' | head -1)"
if [ "$paquete" != "k0pot" ]; then
  rojo "Ese .deb no es el paquete k0pot (dice: '${paquete:-desconocido}'). No se instala."
  exit 1
fi

actual="$(dpkg-query -W -f='${Version}' k0pot 2>/dev/null || echo 'ninguna')"
echo "  Version instalada ahora: $actual"
echo "  Version del paquete subido: $version"
echo
printf "  Instalar esta actualizacion? (si/no): "
read -r respuesta
if [ "$respuesta" != "si" ]; then
  echo "Cancelado. No se ha tocado nada; el .deb sigue preparado."
  exit 0
fi

echo
echo "== Instalando (resuelve dependencias y reinicia los servicios)"
if apt-get install -y --allow-downgrades "$DEB"; then
  rm -f "$DEB"
  echo
  verde "Actualizado a $version."
  systemctl is-active k0pot-collector k0pot-panel k0pot-cowrie 2>/dev/null | sed "s/^/  /"
else
  rojo "La instalacion fallo. El .deb sigue en $DEB por si quieres reintentar."
  exit 1
fi
