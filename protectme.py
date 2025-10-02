#!/usr/bin/env python3
"""
protectme.py - injecteur HMAC corrigé (bytes-safe, markers complets)

Usage:
  python protectme.py <local.py> <remote_raw_url>
  python protectme.py --remove <local.py>
  python protectme.py --verbose <local.py> <remote_raw_url>
"""
from __future__ import annotations
import os, sys, re, hashlib, hmac, urllib.request, urllib.parse, stat

# MARKERS (avec newline final)
MARKER_START = b"# -- BEGIN INTEGRITY PROTECTOR HMAC v1 --\n"
MARKER_END   = b"# -- END INTEGRITY PROTECTOR HMAC v1 --\n"

KEY_PATH = os.path.expanduser("~/.protectme_key")
KEY_LEN = 32  # bytes

# Protecteur (ASCII-only). Tokens: __HMAC__, __REMOTE_URL__, __KEY_PATH__, __MARKER_START__, __MARKER_END__
PROTECTOR_BODY = (
    b"# Protecteur HMAC (injected). No accents - ASCII only.\n"
    b"import sys, hashlib, hmac, urllib.request\n\n"
    b"def _norm(b):\n"
    b"    if b.startswith(b'\\xef\\xbb\\xbf'): b = b[3:]\n"
    b"    b = b.replace(b'\\r\\n', b'\\n').replace(b'\\r', b'\\n')\n"
    b"    lines = b.split(b'\\n')\n"
    b"    lines = [ln.rstrip() for ln in lines]\n"
    b"    return b'\\n'.join(lines)\n\n"
    b"def _read_local_without_block():\n"
    b"    try:\n"
    b"        with open(__file__, 'rb') as f: data = f.read()\n"
    b"    except Exception as e:\n"
    b"        sys.stderr.write('IMPOSSIBLE LIRE LOCAL: '+str(e)+'\\n'); sys.exit(1)\n"
    b"    # use full markers (including newline)\n"
    b"    s = b'__MARKER_START__'\n"
    b"    e = b'__MARKER_END__'\n"
    b"    si = data.find(s)\n"
    b"    if si == -1:\n"
    b"        return _norm(data)\n"
    b"    ei = data.find(e, si)\n"
    b"    if ei == -1:\n"
    b"        # incomplete end marker -> treat as tamper\n"
    b"        sys.stderr.write('INTEGRITY: end marker missing\\n'); sys.exit(1)\n"
    b"    # remove entire block including both markers\n"
    b"    return _norm(data[:si] + data[ei + len(e):])\n\n"
    b"def _fetch_remote_norm(url):\n"
    b"    try:\n"
    b"        req = urllib.request.Request(url, headers={'User-Agent':'IntegrityChecker/1.0'})\n"
    b"        with urllib.request.urlopen(req, timeout=10) as r:\n"
    b"            raw = r.read()\n"
    b"            return _norm(raw)\n"
    b"    except Exception as e:\n"
    b"        sys.stderr.write('IMPOSSIBLE FETCH REMOTE: '+str(e)+'\\n'); sys.exit(1)\n\n"
    b"def _hmac_hex(key, b):\n"
    b"    return hmac.new(key, b, hashlib.sha256).hexdigest()\n\n"
    b"EXPECTED_HMAC = '__HMAC__'\n"
    b"REMOTE_URL = '__REMOTE_URL__'\n"
    b"KEY_PATH = '__KEY_PATH__'\n\n"
    b"def _get_key():\n"
    b"    try:\n"
    b"        with open(KEY_PATH, 'rb') as f: return f.read()\n"
    b"    except Exception:\n"
    b"        return None\n\n"
    b"def _check():\n"
    b"    key = _get_key()\n"
    b"    local_norm = _read_local_without_block()\n"
    b"    if key:\n"
    b"        h = _hmac_hex(key, local_norm)\n"
    b"        if not hmac.compare_digest(h, EXPECTED_HMAC):\n"
    b"            sys.stderr.write('\\n[INTEGRITY ALERT] HMAC mismatch (local vs embedded).\\n')\n"
    b"            sys.exit(1)\n"
    b"    else:\n"
    b"        remote = _fetch_remote_norm(REMOTE_URL)\n"
    b"        if hashlib.sha256(local_norm).hexdigest() != hashlib.sha256(remote).hexdigest():\n"
    b"            sys.stderr.write('\\n[INTEGRITY ALERT] local != remote (no key fallback).\\n')\n"
    b"            sys.exit(1)\n"
    b"\n"
    b"_check()\n"
)

# ---------- helper functions for the injector script ----------

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

def ensure_key():
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f: return f.read()
    key = os.urandom(KEY_LEN)
    with open(KEY_PATH, "wb") as f: f.write(key)
    try:
        os.chmod(KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass
    print(f"[INFO] Clé créée: {KEY_PATH} (chmod 600 recommandé)")
    return key

def compute_normalized_bytes_from_url(url: str):
    req = urllib.request.Request(url, headers={"User-Agent":"IntegrityChecker/1.0"})
    with urllib.request.urlopen(req, timeout=10) as r:
        data = r.read()
    if data.startswith(b'\xef\xbb\xbf'): data = data[3:]
    data = data.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    lines = data.split(b'\n')
    lines = [ln.rstrip() for ln in lines]
    return b'\n'.join(lines)

def inject(local_path: str, remote_url: str, verbose: bool=False) -> int:
    if not os.path.exists(local_path):
        print("[ERREUR] fichier introuvable:", local_path); return 2

    remote_url = normalize_github_raw(remote_url)
    try:
        remote_norm = compute_normalized_bytes_from_url(remote_url)
    except Exception as e:
        print("[ERREUR] impossible de fetch remote:", e); return 4

    key = ensure_key()
    h = hmac.new(key, remote_norm, hashlib.sha256).hexdigest()

    # replace tokens in protector body (use full markers, not stripped)
    body = PROTECTOR_BODY.replace(b"__HMAC__", h.encode("ascii"))
    body = body.replace(b"__REMOTE_URL__", remote_url.encode("utf-8"))
    body = body.replace(b"__KEY_PATH__", KEY_PATH.encode("utf-8"))
    body = body.replace(b"__MARKER_START__", MARKER_START).replace(b"__MARKER_END__", MARKER_END)
    protector = MARKER_START + body + MARKER_END

    with open(local_path, "rb") as f:
        orig = f.read()

    si = orig.find(MARKER_START)
    ei = orig.find(MARKER_END, si) if si != -1 else -1

    if si != -1 and ei != -1:
        if ei <= si:
            print("[ERREUR] marqueurs incoherents"); return 4
        new = orig[:si] + protector + orig[ei + len(MARKER_END):]
        action = "remplacé"
    else:
        # insertion after shebang / encoding lines if possible
        try:
            text = orig.decode("utf-8", errors="surrogateescape")
            lines = text.splitlines(True)
            insert_at = 0
            if lines and lines[0].startswith("#!"): insert_at = 1
            if insert_at < len(lines) and re.match(r"\s*#.*coding[:=]\s*[-\w.]+", lines[insert_at]):
                insert_at += 1
            prefix = "".join(lines[:insert_at]).encode("utf-8")
            suffix = "".join(lines[insert_at:]).encode("utf-8")
            new = prefix + protector + suffix
        except Exception:
            new = protector + orig
        action = "inséré"

    backup = local_path + ".bak"
    try:
        with open(backup, "wb") as b:
            b.write(orig)
    except Exception as e:
        print("[ATTENTION] impossible d'ecrire backup:", e)

    try:
        with open(local_path, "wb") as w:
            w.write(new)
    except Exception as e:
        print("[ERREUR] impossible d'ecrire fichier modifié:", e); return 3

    print(f"[OK] Bloc protecteur {action} dans {local_path}. Sauvegarde: {backup}")
    print("-> URL utilisée (normalisée si applicable):", remote_url)
    if verbose:
        print("[DEBUG] HMAC embarqué:", h)
        print("[DEBUG] clé local path:", KEY_PATH)
    return 0

def remove(local_path: str) -> int:
    if not os.path.exists(local_path):
        print("[ERREUR] fichier introuvable:", local_path); return 2
    with open(local_path, "rb") as f:
        orig = f.read()
    si = orig.find(MARKER_START)
    ei = orig.find(MARKER_END, si) if si != -1 else -1
    if si == -1 or ei == -1:
        print("[INFO] Aucun bloc protecteur détecté."); return 0
    new = orig[:si] + orig[ei + len(MARKER_END):]
    bak = local_path + ".bak_remove"
    try:
        with open(bak, "wb") as b: b.write(orig)
    except Exception as e:
        print("[ATTENTION] impossible d'ecrire backup:", e)
    try:
        with open(local_path, "wb") as w: w.write(new)
    except Exception as e:
        print("[ERREUR] impossible d'ecrire fichier modifié:", e); return 3
    print("[OK] Bloc protecteur retiré. Sauvegarde:", bak)
    return 0

def main(argv):
    if len(argv) == 3 and argv[1] == "--remove":
        return remove(argv[2])
    if len(argv) == 4 and argv[1] == "--verbose":
        return inject(argv[2], argv[3], verbose=True)
    if len(argv) != 3:
        print(__doc__); return 1
    return inject(argv[1], argv[2], verbose=False)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
