#!/usr/bin/env python3
"""Inyecta el botin (deploy/loot) en el filesystem falso de Cowrie.

Lee un fs.pickle base y, por cada fichero bajo deploy/loot, crea la entrada
correspondiente en el arbol con su contenido EMBEBIDO (inline). Como Cowrie
sirve el contenido inline cuando 'contents_path' no esta fijado, no hace
falta montar ningun honeyfs aparte: el pickle basta.

Uso:  plantar-botin.py <fs-base.pickle> <deploy/loot> <fs-botin.pickle>
"""
import os, sys, pickle, time

A_NAME, A_TYPE = 0, 1
A_UID, A_GID, A_SIZE, A_MODE, A_CTIME = 2, 3, 4, 5, 6
A_CONTENTS, A_TARGET, A_REALFILE = 7, 8, 9
T_DIR, T_FILE = 1, 2
CTIME = 1718150400  # fijo, para builds reproducibles

def hijos(nodo):
    return nodo[A_CONTENTS]

def buscar(nodo, nombre):
    for c in hijos(nodo):
        if c[A_NAME] == nombre:
            return c
    return None

def dir_entry(nombre):
    return [nombre, T_DIR, 0, 0, 4096, 0o40700, CTIME, [], None, None]

def asegurar_dir(raiz, partes):
    """Crea (si faltan) los directorios del camino y devuelve el ultimo."""
    nodo = raiz
    for p in partes:
        sig = buscar(nodo, p)
        if sig is None:
            sig = dir_entry(p)
            hijos(nodo).append(sig)
        elif sig[A_TYPE] != T_DIR:
            raise SystemExit(f"conflicto: {p} existe y no es directorio")
        nodo = sig
    return nodo

def plantar(raiz, vpath, datos):
    partes = [x for x in vpath.split("/") if x]
    nombre = partes[-1]
    carpeta = asegurar_dir(raiz, partes[:-1])
    # Los secretos van con permisos restrictivos, mas creibles.
    modo = 0o100600 if any(s in vpath for s in (".ssh/", ".aws/", ".env")) else 0o100644
    entrada = [nombre, T_FILE, 0, 0, len(datos), modo, CTIME, datos, None, None]
    prev = buscar(carpeta, nombre)
    if prev is not None:
        hijos(carpeta).remove(prev)
    hijos(carpeta).append(entrada)

# Binarios que deben EXISTIR en el FS para que sus txtcmds (salida
# creible) se apliquen; si no, Cowrie responde 'command not found' y
# delata la trampa. El contenido es un encabezado ELF de pega: da igual,
# porque el txtcmd sustituye la salida. Ver deploy/cowrie-txtcmds.
BINARIOS = ["/usr/bin/mysql", "/usr/bin/docker", "/usr/bin/aws", "/usr/bin/sshpass"]
ELF = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56

def plantar_binarios(raiz):
    for vpath in BINARIOS:
        partes = [x for x in vpath.split('/') if x]
        carpeta = asegurar_dir(raiz, partes[:-1])
        nombre = partes[-1]
        prev = buscar(carpeta, nombre)
        if prev is not None:
            hijos(carpeta).remove(prev)
        hijos(carpeta).append([nombre, T_FILE, 0, 0, len(ELF), 0o100755, CTIME, ELF, None, None])
        print('  binario', vpath)

def main():
    base, loot, salida = sys.argv[1], sys.argv[2], sys.argv[3]
    with open(base, "rb") as f:
        raiz = pickle.load(f)
    n = 0
    for dirpath, _dirs, files in os.walk(loot):
        for fn in files:
            real = os.path.join(dirpath, fn)
            vpath = "/" + os.path.relpath(real, loot)
            with open(real, "rb") as f:
                datos = f.read()
            plantar(raiz, vpath, datos)
            print("  plantado", vpath, f"({len(datos)} b)")
            n += 1
    plantar_binarios(raiz)
    with open(salida, "wb") as f:
        pickle.dump(raiz, f)
    print(f"{n} ficheros de botin plantados -> {salida}")

if __name__ == "__main__":
    main()
