#!/usr/bin/env python3
"""
protectme.py - injecteur / retrait d'un bloc de vérification d'intégrité

Usage:
  python protectme.py <fichier_local.py> <url_fichier_distant>
  python protectme.py --remove <fichier_local.py>
  python protectme.py --verbose <fichier_local.py> <url_fichier_distant>

Notes:
 - Le fichier distant doit contenir la version ORIGINALE (sans bloc protecteur).
 - Le script travaille en bytes afin d'éviter tout problème d'encodage.
"""
from __future__ import annotations
import sys
import os
import re
import hashlib
import urllib.request
import urllib.parse
from typing import Tuple

MARKER_START = "# -- BEGIN INTEGRITY PROTECTOR v1 --"
MARKER_END   = "# -- END INTEGRITY PROTECTOR v1 --"

# Template avec placeholders simples (on remplace plus bas avec .replace pour éviter les soucis de format)
PROTECTOR_TEMPLATE = (
    "__MARKER_START__\n"
    "# Ceci est un bloc ajouté automatiquement pour vérifier l'intégrité du fichier.\n"
    "# Il retire ce bloc avant de comparer au fichier distant.\n"
    "import sys, hashlib, urllib.request, time, os\n\n"
    "def _integrity_fail(msg):\n"
    "    try:\n"
    "        sys.stderr.write(\"\\n[INTEGRITY ALERT] \" + msg + \"\\n\")\n"
    "    except Exception:\n"
    "        pass\n"
    "    sys.exit(1)\n\n"
    "def _read_local_without_block():\n"
    "    try:\n"
    "        with open(__file__, 'rb') as f:\n"
    "            data = f.read()\n"
    "    except Exception as e:\n"
    "        _integrity_fail('Impossible de lire le fichier local: ' + str(e))\n"
    "    start_b = b\"__MARKER_START__\"\n"
    "    end_b = b\"__MARKER_END__\"\n"
    "    si = data.find(start_b)\n"
    "    ei = data.find(end_b)\n"
    "    if si != -1 and ei != -1 and ei > si:\n"
    "        # supprime bloc inclus\n"
    "        return data[:si] + data[ei + len(end_b):]\n"
    "    return data\n\n"
    "def _fetch_remote(url, timeout=10):\n"
    "    try:\n"
    "        req = urllib.request.Request(url, headers={\"User-Agent\": \"IntegrityChecker/1.0\"})\n"
    "        with urllib.request.urlopen(req, timeout=timeout) as r:\n"
    "            return r.read()\n"
    "    except Exception as e:\n"
    "        _integrity_fail('Impossible de récupérer le fichier distant: ' + str(e))\n\n"
    "def _sha256(b):\n"
    "    h = hashlib.sha256()\n"
    "    h.update(b)\n"
    "    return h.hexdigest()\n\n"
    "def _check():\n"
    "    url = \"__REMOTE_URL__\"\n"
    "    local_code = _read_local_without_block()\n"
    "    remote_code = _fetch_remote(url)\n"
    "    if _sha256(local_code) != _sha256(remote_code):\n"
    "        _integrity_fail('Contenu local différent du fichier distant. Execution interrompue.')\n"
    "    # sinon ok\n\n"
    "_check()\n"
    "__MARKER_END__\n"
)

def normalize_github_raw(url: str) -> str:
    """
    Convertit plusieurs formes GitHub en raw.githubusercontent.com si possible.
    - https://github.com/user/repo/blob/branch/path -> https://raw.githubusercontent.com/user/repo/branch/path
    - https://raw.githubusercontent.com/... (déjà raw) -> retourne identique
    - https://github.com/user/repo/raw/refs/heads/... -> tente de corriger aussi
    """
    parsed = urllib.parse.urlparse(url)
    if "github.com" in parsed.netloc:
        path = parsed.path
        # /user/repo/blob/branch/path...
        parts = path.split("/")
        if len(parts) > 4 and parts[3] == "blob":
            user = parts[1]; repo = parts[2]; branch = parts[4]; rest = "/".join(parts[5:])
            return f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{rest}"
        # parfois 'refs/heads' inclus
        if "/refs/heads/" in path:
            # /user/repo/refs/heads/branch/path -> /user/repo/branch/path
            m = re.match(r"^/([^/]+)/([^/]+)/refs/heads/([^/]+)/(.*)$", path)
            if m:
                user, repo, branch, rest = m.groups()
                return f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{rest}"
    # si déjà raw ou autre domaine, on laisse tel quel
    return url

def sha256_bytes(b: bytes) -> str:
    h = hashlib.sha256(); h.update(b); return h.hexdigest()

def fetch_url_bytes(url: str, timeout: int = 10) -> Tuple[bytes, int]:
    req = urllib.request.Request(url, headers={"User-Agent": "IntegrityChecker/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read()
        return data, r.getcode() if hasattr(r, "getcode") else 200

def inject(local_path: str, remote_url: str, verbose: bool = False) -> int:
    if not os.path.exists(local_path):
        print(f"[ERREUR] Fichier local introuvable: {local_path}")
        return 2

    remote_url = normalize_github_raw(remote_url)
    if verbose:
        print("[DEBUG] URL utilisée :", remote_url)

    # préparer le bloc protecteur (str), puis bytes
    protector_str = PROTECTOR_TEMPLATE.replace("__MARKER_START__", MARKER_START).replace(
        "__MARKER_END__", MARKER_END).replace("__REMOTE_URL__", remote_url)
    protector_bytes = protector_str.encode("utf-8")

    with open(local_path, "rb") as f:
        orig = f.read()

    # recherche des marqueurs en bytes
    start_b = MARKER_START.encode("utf-8")
    end_b = MARKER_END.encode("utf-8")

    if orig.find(start_b) != -1 and orig.find(end_b) != -1:
        # remplacer le bloc existant : trouver indices et substituer
        si = orig.find(start_b)
        ei = orig.find(end_b, si)
        if ei == -1:
            print("[ERREUR] Marqueur de fin trouvé incomplet - arrêt pour sécurité.")
            return 4
        new_bytes = orig[:si] + protector_bytes + orig[ei + len(end_b):]
        action = "remplacé"
    else:
        # insertion : essayer de placer après shebang et ligne d'encodage si présente
        try:
            text = orig.decode("utf-8", errors="surrogateescape")
            lines = text.splitlines(True)
            insert_at = 0
            if lines and lines[0].startswith("#!"):
                insert_at = 1
            if insert_at < len(lines) and re.match(r"\s*#.*coding[:=]\s*[-\w.]+", lines[insert_at]):
                insert_at += 1
            prefix = "".join(lines[:insert_at]).encode("utf-8")
            suffix = "".join(lines[insert_at:]).encode("utf-8")
            new_bytes = prefix + protector_bytes + suffix
        except Exception:
            # si on ne peut pas décoder, on préfixe simplement
            new_bytes = protector_bytes + orig
        action = "inséré"

    # sauvegarde
    backup = local_path + ".bak"
    try:
        with open(backup, "wb") as b:
            b.write(orig)
    except Exception as e:
        print(f"[ATTENTION] Impossible d'écrire la sauvegarde {backup}: {e}")

    try:
        with open(local_path, "wb") as w:
            w.write(new_bytes)
    except Exception as e:
        print(f"[ERREUR] Impossible d'écrire le fichier modifié: {e}")
        return 3

    print(f"[OK] Bloc protecteur {action} dans {local_path}. Sauvegarde: {backup}")
    print("-> URL utilisée (normalisée si applicable):", remote_url)
    if verbose:
        # afficher hash local (apres retrait du bloc) et remote pour debug
        # on calcule local_code en retirant le bloc injecté (comme fera le protecteur)
        local_without = remove_block_bytes(new_bytes)
        try:
            remote_bytes, status = fetch_url_bytes(remote_url)
            print(f"[DEBUG] remote HTTP status: {status}, remote size: {len(remote_bytes)} bytes")
        except Exception as e:
            print(f"[DEBUG] fetch remote failed: {e}")
            return 0
        print(f"[DEBUG] sha256 local (sans bloc): {sha256_bytes(local_without)}")
        print(f"[DEBUG] sha256 remote:       {sha256_bytes(remote_bytes)}")
    return 0

def remove_block_bytes(data: bytes) -> bytes:
    start_b = MARKER_START.encode("utf-8")
    end_b = MARKER_END.encode("utf-8")
    si = data.find(start_b)
    if si == -1:
        return data
    ei = data.find(end_b, si)
    if ei == -1:
        # si fin manquante, renvoie original (sécurité)
        return data
    return data[:si] + data[ei + len(end_b):]

def remove(local_path: str) -> int:
    if not os.path.exists(local_path):
        print(f"[ERREUR] Fichier local introuvable: {local_path}")
        return 2
    with open(local_path, "rb") as f:
        orig = f.read()

    start_b = MARKER_START.encode("utf-8")
    end_b = MARKER_END.encode("utf-8")
    si = orig.find(start_b)
    ei = orig.find(end_b, si) if si != -1 else -1
    if si == -1 or ei == -1:
        print("[INFO] Aucun bloc protecteur détecté.")
        return 0

    new_bytes = orig[:si] + orig[ei + len(end_b):]

    backup = local_path + ".bak_remove"
    try:
        with open(backup, "wb") as b:
            b.write(orig)
    except Exception as e:
        print(f"[ATTENTION] Impossible d'écrire la sauvegarde {backup}: {e}")

    try:
        with open(local_path, "wb") as w:
            w.write(new_bytes)
    except Exception as e:
        print(f"[ERREUR] Impossible d'écrire le fichier modifié: {e}")
        return 3

    print(f"[OK] Bloc protecteur retiré de {local_path}. Sauvegarde: {backup}")
    return 0

def main(argv):
    if len(argv) == 3 and argv[1] == "--remove":
        return remove(argv[2])
    if len(argv) == 4 and argv[1] == "--verbose":
        local, url = argv[2], argv[3]
        return inject(local, url, verbose=True)
    if len(argv) != 3:
        print(__doc__)
        return 1
    local, url = argv[1], argv[2]
    return inject(local, url, verbose=False)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
