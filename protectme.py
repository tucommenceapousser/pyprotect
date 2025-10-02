#!/usr/bin/env python3
"""
protectme.py - injecteur HMAC corrigé (safe string embedding)

Usage:
  python protectme.py <local.py> <remote_raw_url>
  python protectme.py --remove <local.py>
  python protectme.py --verbose <local.py> <remote_raw_url>
"""
from __future__ import annotations
import os, sys, re, hashlib, hmac, urllib.request, urllib.parse, stat

# MARKERS (texte)
MARKER_START_TEXT = "# -- BEGIN INTEGRITY PROTECTOR HMAC v1 --\n"
MARKER_END_TEXT   = "# -- END INTEGRITY PROTECTOR HMAC v1 --\n"

# bytes versions (for searching in files)
MARKER_START = MARKER_START_TEXT.encode("utf-8")
MARKER_END = MARKER_END_TEXT.encode("utf-8")

KEY_PATH = os.path.expanduser("~/.protectme_key")
KEY_LEN = 32  # bytes

# Protecteur construit comme str (ASCII-only in body lines).
# On utilise "__MARKER_START_TEXT__" et "__MARKER_END_TEXT__" placeholders,
# puis on génère protector_str et on encode en utf-8 avant écriture.
PROTECTOR_TEMPLATE_STR = """{marker_start}
# Protecteur HMAC (injected). ASCII-only body.
import sys, hashlib, hmac, urllib.request

def _norm(b):
    if b.startswith(b'\\xef\\xbb\\xbf'):
        b = b[3:]
    b = b.replace(b'\\r\\n', b'\\n').replace(b'\\r', b'\\n')
    lines = b.split(b'\\n')
    lines = [ln.rstrip() for ln in lines]
    return b'\\n'.join(lines)

def _read_local_without_block():
    try:
        with open(__file__, 'rb') as f:
            data = f.read()
    except Exception as e:
        sys.stderr.write('IMPOSSIBLE LIRE LOCAL: ' + str(e) + "\\n")
        sys.exit(1)
    # use marker texts and encode to bytes
    s = "{marker_start_text}".encode('utf-8')
    e = "{marker_end_text}".encode('utf-8')
    si = data.find(s)
    if si == -1:
        return _norm(data)
    ei = data.find(e, si)
    if ei == -1:
        sys.stderr.write('INTEGRITY: end marker missing\\n')
        sys.exit(1)
    return _norm(data[:si] + data[ei + len(e):])

def _fetch_remote_norm(url):
    try:
        req = urllib.request.Request(url, headers={{'User-Agent':'IntegrityChecker/1.0'}})
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read()
            return _norm(raw)
    except Exception as e:
        sys.stderr.write('IMPOSSIBLE FETCH REMOTE: ' + str(e) + "\\n")
        sys.exit(1)

def _hmac_hex(key, b):
    return hmac.new(key, b, hashlib.sha256).hexdigest()

EXPECTED_HMAC = "{hmac_expected}"
REMOTE_URL = "{remote_url}"
KEY_PATH = "{key_path}"

def _get_key():
    try:
        with open(KEY_PATH, 'rb') as f:
            return f.read()
    except Exception:
        return None

def _check():
    key = _get_key()
    local_norm = _read_local_without_block()
    if key:
        h = _hmac_hex(key, local_norm)
        if not hmac.compare_digest(h, EXPECTED_HMAC):
            sys.stderr.write('\\n[INTEGRITY ALERT] HMAC mismatch (local vs embedded).\\n')
            sys.exit(1)
    else:
        remote = _fetch_remote_norm(REMOTE_URL)
        if hashlib.sha256(local_norm).hexdigest() != hashlib.sha256(remote).hexdigest():
            sys.stderr.write('\\n[INTEGRITY ALERT] local != remote (no key fallback).\\n')
            sys.exit(1)

_check()
{marker_end}
"""

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
        with open(KEY_PATH, "rb") as f:
            return f.read()
    key = os.urandom(KEY_LEN)
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    try:
        os.chmod(KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)  # chmod 600
    except Exception:
        pass
    print(f"[INFO] Clé créée: {KEY_PATH} (chmod 600 recommandé)")
    return key

def compute_normalized_bytes_from_url(url: str):
    req = urllib.request.Request(url, headers={"User-Agent":"IntegrityChecker/1.0"})
    with urllib.request.urlopen(req, timeout=10) as r:
        data = r.read()
    if data.startswith(b'\xef\xbb\xbf'):
        data = data[3:]
    data = data.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    lines = data.split(b'\n')
    lines = [ln.rstrip() for ln in lines]
    return b'\n'.join(lines)

def inject(local_path: str, remote_url: str, verbose: bool=False) -> int:
    if not os.path.exists(local_path):
        print("[ERREUR] fichier introuvable:", local_path)
        return 2

    remote_url = normalize_github_raw(remote_url)
    try:
        remote_norm = compute_normalized_bytes_from_url(remote_url)
    except Exception as e:
        print("[ERREUR] impossible de fetch remote:", e)
        return 4

    key = ensure_key()
    h = hmac.new(key, remote_norm, hashlib.sha256).hexdigest()

    # build protector_str safely: marker texts inserted as plain text (quoted within template)
    protector_str = PROTECTOR_TEMPLATE_STR.format(
        marker_start=MARKER_START_TEXT,
        marker_end=MARKER_END_TEXT,
        marker_start_text=MARKER_START_TEXT.replace('"', '\\"'),
        marker_end_text=MARKER_END_TEXT.replace('"', '\\"'),
        hmac_expected=h,
        remote_url=remote_url.replace('"', '\\"'),
        key_path=KEY_PATH.replace('"', '\\"')
    )

    protector_bytes = protector_str.encode("utf-8")

    # read original file bytes
    with open(local_path, "rb") as f:
        orig = f.read()

    # search for existing markers (byte search)
    si = orig.find(MARKER_START)
    ei = orig.find(MARKER_END, si) if si != -1 else -1

    if si != -1 and ei != -1:
        if ei <= si:
            print("[ERREUR] marqueurs incoherents")
            return 4
        new = orig[:si] + protector_bytes + orig[ei + len(MARKER_END):]
        action = "remplacé"
    else:
        # insert after shebang / encoding line if any
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
            new = prefix + protector_bytes + suffix
        except Exception:
            new = protector_bytes + orig
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
        print("[ERREUR] impossible d'ecrire fichier modifié:", e)
        return 3

    print(f"[OK] Bloc protecteur {action} dans {local_path}. Sauvegarde: {backup}")
    print("-> URL utilisée (normalisée si applicable):", remote_url)
    if verbose:
        print("[DEBUG] HMAC embarqué:", h)
        print("[DEBUG] clé local path:", KEY_PATH)
    return 0

def remove(local_path: str) -> int:
    if not os.path.exists(local_path):
        print("[ERREUR] fichier introuvable:", local_path)
        return 2
    with open(local_path, "rb") as f:
        orig = f.read()
    si = orig.find(MARKER_START)
    ei = orig.find(MARKER_END, si) if si != -1 else -1
    if si == -1 or ei == -1:
        print("[INFO] Aucun bloc protecteur détecté.")
        return 0
    new = orig[:si] + orig[ei + len(MARKER_END):]
    bak = local_path + ".bak_remove"
    try:
        with open(bak, "wb") as b:
            b.write(orig)
    except Exception as e:
        print("[ATTENTION] impossible d'ecrire backup:", e)
    try:
        with open(local_path, "wb") as w:
            w.write(new)
    except Exception as e:
        print("[ERREUR] impossible d'ecrire fichier modifié:", e)
        return 3
    print("[OK] Bloc protecteur retiré. Sauvegarde:", bak)
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
