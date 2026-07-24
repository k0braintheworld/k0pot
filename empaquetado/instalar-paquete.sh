#!/bin/bash
#
# Instalador de k0Pot en un solo paso, para instalar desde el paquete .deb.
#
# Instala el paquete con todas sus dependencias (Docker, nftables...) y a
# continuacion lanza el asistente, que detecta las IP de la maquina, crea la
# cuenta del panel, deja el cortafuegos generado y termina indicando la URL.
#
# Uso, en el servidor recien montado, con el .deb al lado:
#
#     sudo ./instalar.sh              (coge el k0pot_*.deb del directorio)
#     sudo ./instalar.sh k0pot.deb    (o le indicas cual)
#
set -euo pipefail

BASE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"

# Instalar y configurar necesitan root; si no lo es, se re-lanza con sudo.
if [ "$(id -u)" -ne 0 ]; then
  exec sudo "$0" "$@"
fi

DEB="${1:-}"
if [ -z "$DEB" ]; then
  DEB="$(ls -1t "$BASE"/k0pot_*.deb 2>/dev/null | head -1)"
fi
if [ -z "$DEB" ] || [ ! -r "$DEB" ]; then
  echo "No encuentro ningun k0pot_*.deb (ni junto a este script ni como argumento)."
  echo "Uso: sudo ./instalar.sh [ruta-al-.deb]"
  exit 1
fi

echo "== Instalando $(basename "$DEB") y sus dependencias"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq || true
# dpkg coloca el paquete; "apt-get -f install" resuelve las dependencias que
# le falten (Docker, nftables, adduser). Es el patron robusto para un .deb
# local sin repositorio.
dpkg -i "$DEB" || true
apt-get install -y -f

echo
echo "== Configuracion inicial"
k0pot-configurar
