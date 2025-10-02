#!/usr/bin/env python3
"""
inject_protector.py
Usage:
  python inject_protector.py <fichier_local.py> <url_fichier_distant>
  python inject_protector.py --remove <fichier_local.py>

Le protecteur compare le code local* (hors bloc protecteur) avec le code distant.
*Le fichier distant doit contenir le code original sans bloc protecteur.
"""
import sys, os, re

MARKER_START = "# -- BEGIN INTEGRITY PROTECTOR v1 --"
MARKER_END   = "# -- END INTEGRITY PROTECTOR v1 --"

PROTECTOR_TEMPLATE = r'''{start}
# Ceci est un bloc ajouté automatiquement pour vérifier l'intégrité du fichier.
# Il retire ce bloc avant de comparer au fichier distant.
import sys, hashlib, urllib.request, urllib.error, time, io, os

def _integrity_fail(msg):
    try:
        sys.stderr.write("\\n[INTEGRITY ALERT] " + msg + "\\n")
    except Exception:
        pass
    # Empêche l'exécution du reste du script
    sys.exit(1)

def _read_local_without_block():
    try:
        with open(__file__, "rb") as f:
            data = f.read()
    except Exception as e:
        # si on ne peut pas lire le fichier local, on bloque par prudence
        _integrity_fail("Impossible de lire le fichier local: {}".format(e))
    start = b"{start_b}"
    end = b"{end_b}"
    si = data.find(start)
    ei = data.find(end)
    if si != -1 and ei != -1 and ei > si:
        # on retire le bloc protecteur (inclus)
        new = data[:si] + data[ei + len(end):]
    else:
        new = data
    return new

def _fetch_remote(url, timeout=6):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "IntegrityChecker/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.read()
    except Exception as e:
        _integrity_fail("Impossible de récupérer le fichier distant ({}).".format(e))

def _sha256(b):
    import hashlib
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def _check():
    # URL fournie par l'injecteur (modifie par inject_protector.py)
    url = "{remote_url}"
    local_code = _read_local_without_block()
    remote_code = _fetch_remote(url)
    if _sha256(local_code) != _sha256(remote_code):
        _integrity_fail("Contenu local différent du fichier distant. Execution interrompue.")
    # sinon tout va bien, on continue normalement

_check()
{end}
'''

def inject(local_path, remote_url):
    if not os.path.exists(local_path):
        print(f"[ERREUR] Fichier local introuvable: {local_path}")
        return 2

    with open(local_path, "rb") as f:
        orig = f.read()

    text = orig.decode('utf-8', errors='surrogateescape')

    # si déjà présent, on remplace le bloc existant
    pattern = re.compile(re.escape(MARKER_START) + r".*?" + re.escape(MARKER_END), flags=re.DOTALL)
    protector = PROTECTOR_TEMPLATE.format(
        start=MARKER_START,
        end=MARKER_END,
        start_b=MARKER_START.encode('utf-8').decode('latin1'),
        end_b=MARKER_END.encode('utf-8').decode('latin1'),
        remote_url=remote_url
    )

    if pattern.search(text):
        new_text = pattern.sub(protector, text)
        action = "remplacé"
    else:
        # placer après shebang et éventuelle ligne d'encodage
        lines = text.splitlines(True)
        insert_at = 0
        if lines and lines[0].startswith("#!"):
            insert_at = 1
        # encodage (ex: # -*- coding: utf-8 -*-)
        if insert_at < len(lines) and re.match(r"\s*#.*coding[:=]\s*[-\w.]+", lines[insert_at]):
            insert_at += 1
        new_text = "".join(lines[:insert_at]) + protector + "".join(lines[insert_at:])
        action = "inséré"

    # sauvegarde d'une copie de sauvegarde
    backup = local_path + ".bak"
    try:
        with open(backup, "wb") as b:
            b.write(orig)
    except Exception as e:
        print(f"[ATTENTION] Impossible d'écrire la sauvegarde {backup}: {e}")

    try:
        with open(local_path, "wb") as w:
            w.write(new_text.encode('utf-8'))
    except Exception as e:
        print(f"[ERREUR] Impossible d'écrire le fichier modifié: {e}")
        return 3

    print(f"[OK] Bloc protecteur {action} dans {local_path}. Sauvegarde: {backup}")
    print("-> N'oublie pas d'héberger la version originale (sans bloc protecteur) à l'URL distante fournie.")
    return 0

def remove(local_path):
    if not os.path.exists(local_path):
        print(f"[ERREUR] Fichier local introuvable: {local_path}")
        return 2
    with open(local_path, "rb") as f:
        orig = f.read()
    text = orig.decode('utf-8', errors='surrogateescape')
    pattern = re.compile(re.escape(MARKER_START) + r".*?" + re.escape(MARKER_END), flags=re.DOTALL)
    if not pattern.search(text):
        print("[INFO] Aucun bloc protecteur détecté.")
        return 0
    new_text = pattern.sub("", text)
    backup = local_path + ".bak_remove"
    try:
        with open(backup, "wb") as b:
            b.write(orig)
    except Exception as e:
        print(f"[ATTENTION] Impossible d'écrire la sauvegarde {backup}: {e}")
    try:
        with open(local_path, "wb") as w:
            w.write(new_text.encode('utf-8'))
    except Exception as e:
        print(f"[ERREUR] Impossible d'écrire le fichier modifié: {e}")
        return 3
    print(f"[OK] Bloc protecteur retiré de {local_path}. Sauvegarde: {backup}")
    return 0

def main(argv):
    if len(argv) == 3 and argv[1] == "--remove":
        return remove(argv[2])
    if len(argv) != 3:
        print(__doc__)
        return 1
    local, url = argv[1], argv[2]
    return inject(local, url)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
