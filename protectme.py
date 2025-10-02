#!/usr/bin/env python3
"""
protectme.py - injecteur / retrait d'un bloc de vérification d'intégrité (version bytes)

Usage:
  python protectme.py <fichier_local.py> <url_fichier_distant>
  python protectme.py --remove <fichier_local.py>
  python protectme.py --verbose <fichier_local.py> <url_fichier_distant>
"""
from __future__ import annotations
import sys
import os
import re
import hashlib
import urllib.request
import urllib.parse

MARKER_START = b"# -- BEGIN INTEGRITY PROTECTOR v2 --\n"
MARKER_END   = b"# -- END INTEGRITY PROTECTOR v2 --\n"

# Corps du protecteur en bytes (on utilisera .replace sur les tokens bytes)
PROTECTOR_BODY = (
    b"# Ceci est un bloc automatique de verification d'integrite.\n"
    b"# Il retire ce bloc avant de comparer au fichier distant.\n"
    b"import sys, hashlib, urllib.request\n\n"
    b"def _integrity_fail(msg):\n"
    b"    try:\n"
    b"        sys.stderr.write('\\n[INTEGRITY ALERT] ' + msg + '\\n')\n"
    b"    except Exception:\n"
    b"        pass\n"
    b"    sys.exit(1)\n\n"
    b"def _normalize_bytes(b):\n"
    b"    if b.startswith(b'\\xef\\xbb\\xbf'):\n"
    b"        b = b[3:]\n"
    b"    b = b.replace(b'\\r\\n', b'\\n').replace(b'\\r', b'\\n')\n"
    b"    lines = b.split(b'\\n')\n"
    b"    lines = [ln.rstrip() for ln in lines]\n"
    b"    return b'\\n'.join(lines)\n\n"
    b"def _read_local_without_block_bytes():\n"
    b"    try:\n"
    b"        with open(__file__, 'rb') as f:\n"
    b"            data = f.read()\n"
    b"    except Exception as e:\n"
    b"        _integrity_fail('Impossible de lire le fichier local: ' + str(e))\n"
    b"    s = b'__MARKER_START__'\n"
    b"    e = b'__MARKER_END__'\n"
    b"    si = data.find(s)\n"
    b"    ei = data.find(e)\n"
    b"    if si != -1 and ei != -1 and ei > si:\n"
    b"        data = data[:si] + data[ei + len(e):]\n"
    b"    return _normalize_bytes(data)\n\n"
    b"def _fetch_remote_norm(url):\n"
    b"    try:\n"
    b"        req = urllib.request.Request(url, headers={'User-Agent': 'IntegrityChecker/1.0'})\n"
    b"        with urllib.request.urlopen(req, timeout=10) as r:\n"
    b"            raw = r.read()\n"
    b"            return _normalize_bytes(raw)\n"
    b"    except Exception as e:\n"
    b"        _integrity_fail('Impossible de recuperer le fichier distant: ' + str(e))\n\n"
    b"def _sha256(b):\n"
    b"    h = hashlib.sha256(); h.update(b); return h.hexdigest()\n\n"
    b"def _check_remote(url):\n"
    b"    local = _read_local_without_block_bytes()\n"
    b"    remote = _fetch_remote_norm(url)\n"
    b"    if _sha256(local) != _sha256(remote):\n"
    b"        _integrity_fail('Contenu local different du fichier distant. Execution interrompue.')\n"
    b"\n"
    b"_check_remote('__REMOTE_URL__')\n"
)

def normalize_github_raw(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if "github.com" in parsed.netloc:
        path = parsed.path
        parts = path.split("/")
        if len(parts) > 4 and parts[3] == "blob":
            user, repo, branch = parts[1], parts[2], parts[4]
            rest = "/".join(parts[5:])
            return f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{rest}"
        m = re.match(r"^/([^/]+)/([^/]+)/refs/heads/([^/]+)/(.*)$", path)
        if m:
            user, repo, branch, rest = m.groups()
            return f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{rest}"
    return url

def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def fetch_url_bytes(url: str, timeout: int = 10):
    req = urllib.request.Request(url, headers={"User-Agent": "IntegrityChecker/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read(), (r.getcode() if hasattr(r, "getcode") else 200)

def inject(local_path: str, remote_url: str, verbose: bool = False) -> int:
    if not os.path.exists(local_path):
        print(f"[ERREUR] Fichier local introuvable: {local_path}")
        return 2

    remote_url = normalize_github_raw(remote_url)
    if verbose:
        print("[DEBUG] URL utilisée :", remote_url)

    # construire le bloc protecteur bytes
    body = PROTECTOR_BODY.replace(b"__REMOTE_URL__", remote_url.encode("utf-8"))
    body = body.replace(b"__MARKER_START__", MARKER_START.strip()).replace(b"__MARKER_END__", MARKER_END.strip())
    protector = MARKER_START + body + MARKER_END

    with open(local_path, "rb") as f:
        orig = f.read()

    # trouver si déjà présent
    si = orig.find(MARKER_START)
    ei = orig.find(MARKER_END, si) if si != -1 else -1

    if si != -1 and ei != -1:
        # remplacer l'ancien bloc complet
        if ei <= si:
            print("[ERREUR] Marqueurs incohérents dans le fichier local.") 
            return 4
        new = orig[:si] + protector + orig[ei + len(MARKER_END):]
        action = "remplacé"
    else:
        # insertion après shebang + ligne d'encodage si possible (en tentant decode utf-8)
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
            new = prefix + protector + suffix
        except Exception:
            new = protector + orig
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
            w.write(new)
    except Exception as e:
        print(f"[ERREUR] Impossible d'écrire le fichier modifié: {e}")
        return 3

    print(f"[OK] Bloc protecteur {action} dans {local_path}. Sauvegarde: {backup}")
    print("-> URL utilisée (normalisée si applicable):", remote_url)

    if verbose:
        # pour debug : afficher SHA256 normalisés local (sans bloc) et remote
        local_without = remove_block_bytes(new)
        try:
            remote_raw, status = fetch_url_bytes(remote_url)
            remote_norm = normalize_bytes(remote_raw)
            print(f"[DEBUG] remote HTTP status: {status}, remote size: {len(remote_raw)} bytes")
        except Exception as e:
            print(f"[DEBUG] fetch remote failed: {e}")
            return 0
        print(f"[DEBUG] sha256 local (norm): {sha256_bytes(local_without)}")
        print(f"[DEBUG] sha256 remote (norm): {sha256_bytes(remote_norm)}")
    return 0

def remove_block_bytes(data: bytes) -> bytes:
    si = data.find(MARKER_START)
    if si == -1:
        return normalize_bytes(data)
    ei = data.find(MARKER_END, si)
    if ei == -1:
        return normalize_bytes(data)
    pure = data[:si] + data[ei + len(MARKER_END):]
    return normalize_bytes(pure)

def normalize_bytes(b: bytes) -> bytes:
    if b.startswith(b'\xef\xbb\xbf'):
        b = b[3:]
    b = b.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    lines = b.split(b'\n')
    lines = [ln.rstrip() for ln in lines]
    return b'\n'.join(lines)

def remove(local_path: str) -> int:
    if not os.path.exists(local_path):
        print(f"[ERREUR] Fichier local introuvable: {local_path}")
        return 2
    with open(local_path, "rb") as f:
        orig = f.read()

    si = orig.find(MARKER_START)
    ei = orig.find(MARKER_END, si) if si != -1 else -1
    if si == -1 or ei == -1:
        print("[INFO] Aucun bloc protecteur détecté.")
        return 0

    new = orig[:si] + orig[ei + len(MARKER_END):]

    backup = local_path + ".bak_remove"
    try:
        with open(backup, "wb") as b:
            b.write(orig)
    except Exception as e:
        print(f"[ATTENTION] Impossible d'écrire la sauvegarde {backup}: {e}")

    try:
        with open(local_path, "wb") as w:
            w.write(new)
    except Exception as e:
        print(f"[ERREUR] Impossible d'écrire le fichier modifié: {e}")
        return 3

    print(f"[OK] Bloc protecteur retiré de {local_path}. Sauvegarde: {backup}")
    return 0

def main(argv):
    if len(argv) == 3 and argv[1] == "--remove":
        return remove(argv[2])
    if len(argv) == 4 and argv[1] == "--verbose":
        return inject(argv[2], argv[3], verbose=True)
    if len(argv) != 3:
        print(__doc__)
        return 1
    return inject(argv[1], argv[2], verbose=False)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
