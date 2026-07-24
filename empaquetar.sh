#!/bin/bash
#
# Construye el paquete .deb de k0Pot.
#
# Sin dependencias de empaquetado mas alla de dpkg-deb, que viene en
# cualquier Debian o Ubuntu: el proyecto es un binario y unos ficheros de
# configuracion, y montar debhelper alrededor de eso seria mas maquinaria
# que producto.
#
set -euo pipefail

BASE="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
cd "$BASE"

VERSION="${1:-$(git describe --tags --always 2>/dev/null | sed 's/^v//' || echo 0.1.0)}"
ARCO="$(dpkg --print-architecture)"
DESTINO="$BASE/dist"
ARBOL="$DESTINO/k0pot_${VERSION}_${ARCO}"

command -v dpkg-deb >/dev/null || { echo "Falta dpkg-deb"; exit 1; }
command -v go >/dev/null || { echo "Falta Go"; exit 1; }

echo "== Compilando k0pot $VERSION"
# Estatico y sin CGO: el mismo .deb vale en cualquier distribucion con la
# misma arquitectura, sin arrastrar dependencias de libc.
CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=$VERSION" \
  -o "$DESTINO/k0pot" ./cmd/k0pot

echo "== Montando el arbol del paquete"
rm -rf "$ARBOL"
mkdir -p "$ARBOL"/DEBIAN \
         "$ARBOL"/usr/bin \
         "$ARBOL"/usr/sbin \
         "$ARBOL"/usr/lib/systemd/system \
         "$ARBOL"/usr/share/k0pot/deploy \
         "$ARBOL"/usr/share/doc/k0pot

install -m 755 "$DESTINO/k0pot"                        "$ARBOL/usr/bin/k0pot"
install -m 755 empaquetado/sistema/k0pot-configurar    "$ARBOL/usr/sbin/k0pot-configurar"
# El script se busca sus .nft JUNTO A SI MISMO (readlink -f), asi que va
# donde estan, en /usr/share/k0pot/deploy, y en /usr/sbin queda solo un
# symlink para tenerlo en el PATH. Copiarlo a /usr/sbin lo separaria de sus
# ficheros y "aplicar" no encontraria el aislamiento.
install -m 755 deploy/k0pot-nft.sh                     "$ARBOL/usr/share/k0pot/deploy/k0pot-nft"
ln -s /usr/share/k0pot/deploy/k0pot-nft                "$ARBOL/usr/sbin/k0pot-nft"
install -m 644 empaquetado/sistema/*.service           "$ARBOL/usr/lib/systemd/system/"
install -m 644 docker-compose.yml                      "$ARBOL/usr/share/k0pot/"
install -m 644 deploy/cowrie.cfg                       "$ARBOL/usr/share/k0pot/"
install -m 644 .env.ejemplo                            "$ARBOL/usr/share/k0pot/k0pot.env.ejemplo"
install -m 644 deploy/aislamiento.nft                  "$ARBOL/usr/share/k0pot/deploy/"
install -m 755 deploy/comprobar-aislamiento.sh         "$ARBOL/usr/share/k0pot/deploy/"
install -m 644 README.md LICENSE                       "$ARBOL/usr/share/doc/k0pot/"

# El compose del paquete apunta a las rutas del sistema y toma el UID del
# servicio del entorno: el usuario k0pot lo crea el postinst y su UID no se
# conoce hasta entonces.
sed -e 's|\./data/cowrie|/var/lib/k0pot/cowrie|g' \
    -e 's|\./deploy/cowrie.cfg|/usr/share/k0pot/cowrie.cfg|' \
    -e 's|^    user: "1000:1000"|    user: "${K0POT_UID}:${K0POT_GID}"|' \
    docker-compose.yml > "$ARBOL/usr/share/k0pot/docker-compose.yml"

sed "s/^Version: VERSION/Version: $VERSION/" empaquetado/debian/control > "$ARBOL/DEBIAN/control"
install -m 755 empaquetado/debian/postinst "$ARBOL/DEBIAN/postinst"
install -m 755 empaquetado/debian/prerm    "$ARBOL/DEBIAN/prerm"
install -m 755 empaquetado/debian/postrm   "$ARBOL/DEBIAN/postrm"
# No se declara ningun conffile a proposito. k0pot.env lo genera el postinst
# a partir del ejemplo, y ademas contiene claves: declararlo haria que dpkg
# preguntara por conflictos en cada actualizacion sobre un fichero que el
# paquete ni siquiera trae.

echo "== Construyendo"
dpkg-deb --root-owner-group --build "$ARBOL" >/dev/null
PAQUETE="$ARBOL.deb"

echo
echo "  $PAQUETE"
dpkg-deb --info "$PAQUETE" | grep -E "Package|Version|Architecture|Depends" | sed 's/^/  /'
echo "  tamano: $(du -h "$PAQUETE" | cut -f1)"
echo
echo "  Instalar:  sudo apt install $PAQUETE"
echo "  Configurar: sudo k0pot-configurar"
