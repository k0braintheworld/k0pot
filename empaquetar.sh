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

# La version debe empezar por digito (dpkg lo exige). Con etiquetas se usa la
# etiqueta; sin ellas, "git describe" devuelve el hash pelado -que no vale-,
# asi que se cae a una base con el hash detras: 0.0.0+gitHASH.
if [ -n "${1:-}" ]; then
  VERSION="$1"
else
  # El "|| true" es imprescindible con "set -e -o pipefail": sin etiquetas,
  # git describe sale con error y, aun capturado el stderr, la tuberia
  # arrastraria al script entero fuera en la propia asignacion.
  VERSION="$(git describe --tags 2>/dev/null | sed 's/^v//' || true)"
  if [ -z "$VERSION" ]; then
    VERSION="0.0.0+git$(git rev-parse --short HEAD 2>/dev/null || echo 0)"
  fi
fi
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
# dist/ queda limpio en cada build: se van los .deb y arboles de versiones
# anteriores, para poder entregar la carpeta sin restos que confundan.
rm -rf "$DESTINO"/k0pot_*_amd64
rm -f "$DESTINO"/k0pot_*.deb
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

# Junto al .deb viajan el instalador de un paso y una guia para no
# entendidos, para copiar dist/ al servidor y lanzar "sudo ./instalar.sh".
# El instalador del paquete NO es el instalar.sh de la raiz (ese instala
# desde codigo, para desarrollo): es el de empaquetado/.
install -m 755 empaquetado/instalar-paquete.sh "$DESTINO/instalar.sh"
install -m 644 empaquetado/LEEME.txt            "$DESTINO/LEEME.txt"

echo
echo "  $PAQUETE"
dpkg-deb --info "$PAQUETE" | grep -E "Package|Version|Architecture|Depends" | sed 's/^/  /'
echo "  tamano: $(du -h "$PAQUETE" | cut -f1)"
echo
# Intermedios fuera: en dist/ solo quedan el .deb, instalar.sh y LEEME.txt.
rm -rf "$ARBOL"
rm -f "$DESTINO/k0pot"

echo "  Instalar todo (un paso): copia la carpeta dist/ al servidor y ejecuta"
echo "                           sudo ./instalar.sh"
echo
echo "  O a mano:  sudo apt install $PAQUETE  &&  sudo k0pot-configurar"
