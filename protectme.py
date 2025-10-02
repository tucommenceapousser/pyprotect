#!/usr/bin/env python3
"""
protectme_norm.py

Usage:
  python protectme_norm.py <local.py> <remote_raw_url>
  python protectme_norm.py --remove <local.py>
  python protectme_norm.py --verbose <local.py> <remote_raw_url>

Méthode: normalisation (BOM, CRLF -> LF, trimming EOL spaces) puis SHA256 comparison.
"""
import sys, os, re, hashlib, urllib.request, urllib.parse

MARKER_START = b"# -- BEGIN INTEGRITY PROTECTOR v2 --\n"
MARKER_END   = b"# -- END INTEGRITY PROTECTOR v2 --\n"

PROTECTOR_BODY = (
    b"# Ceci est un bloc automatique de verification d'integrite.\n"
    b"import sys, hashlib, urllib.request\n\n"
    b"def _integrity_fail(msg):\n"
    b"    try:\n"
    b"        sys.stderr.write('\\n[INTEGRITY ALERT] ' + msg + '\\n')\n"
    b"    except Exception:\n"
    b"        pass\n"
    b"    sys.exit(1)\n\n"
    b"def _normalize_bytes(b):\n"
    b"    # retire BOM\n"
    b"    if b.startswith(b'\\xef\\xbb\\xbf'):\n"
    b"        b = b[3:]\n"
    b"    # convertir CRLF ou CR to LF\n"
    b"    b = b.replace(b'\\r\\n', b'\\n').replace(b'\\r', b'\\n')\n"
    b"    # retirer espaces de fin de ligne\n"
    b"    lines = b.split(b'\\n')\n"
    b"    lines = [ln.rstrip() for ln in lines]\n"
    b"    return b'\\n'.join(lines)\n\n"
    b"def _read_local_without_block_bytes():\n"
    b"    try:\n"
    b"        with open(__file__, 'rb') as f:\n"
    b"            data = f.read()\n"
    b"    except Exception as e:\n"
    b"        _integrity_fail('Impossible de lire le fichier local: ' + str(e))\n"
    b"    s = " + repr(MARKER_START) + b"\n"
    b"    e = " + repr(MARKER_END) + b"\n"
    b"    si = data.find(s)\n"
    b"    ei = data.find(e)\n"
    b"    if si != -1 and ei != -1 and ei > si:\n"
    b"        data = data[:si] + data[ei + len(e):]\n"
    b"    return _normalize_bytes(data)\n\n"
    b"def _fetch_remote_norm(url):\n"
    b"    try:\n"
    b"        req = urllib.request.Request(url, headers={'User-Agent': 'IntegrityChecker/1.0'})\n"
    b"        with urllib.request.urlopen(req, timeout=10) as r:\n"
    b"            rb = r.read()\n"
    b"            return _normalize_bytes(rb)\n"
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
    b"_check_remote('%REMOTE_URL%')\n"
)

def normalize_github_raw(url):
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

def sha256_bytes(b): return hashlib.sha256(b).hexdigest()

def inject(local, remote_url, verbose=False):
    if not os.path.exists(local):
        print("Fichier local introuvable:", local); return 2
    remote_url = normalize_github_raw(remote_url)
    # build protector bytes
    body = PROTECTOR_BODY.replace(b"%REMOTE_URL%", remote_url.encode("utf-8"))
    protector = MARKER_START + body + MARKER_END

    with open(local, "rb") as f: orig = f.read()
    # if already present, replace whole existing marker block
    si = orig.find(MARKER_START); ei = orig.find(MARKER_END, si) if si!=-1 else -1
    if si != -1 and ei != -1:
        new = orig[:si] + protector + orig[ei + len(MARKER_END):]
        action = "remplacé"
    else:
        # insert after shebang/encoding if possible
        try:
            text = orig.decode("utf-8", errors="surrogateescape")
            lines = text.splitlines(True)
            insert_at = 0
            if lines and lines[0].startswith("#!"): insert_at=1
            if insert_at < len(lines) and re.match(r"\s*#.*coding[:=]\s*[-\w.]+", lines[insert_at]): insert_at+=1
            prefix = "".join(lines[:insert_at]).encode("utf-8")
            suffix = "".join(lines[insert_at:]).encode("utf-8")
            new = prefix + protector + suffix
        except Exception:
            new = protector + orig
        action = "inséré"

    # write backup + new
    bak = local + ".bak"
    try:
        with open(bak, "wb") as b: b.write(orig)
    except Exception as e:
        print("Impossible d'ecrire backup:", e)
    with open(local, "wb") as w: w.write(new)
    print("[OK] Bloc protecteur", action, "dans", local, "Sauvegarde:", bak)
    print("-> URL utilisée (normalisée si applicable):", remote_url)
    if verbose:
        # compute normalized hashes for debugging
        local_norm = remove_block_and_normalize(new)
        try:
            req = urllib.request.Request(remote_url, headers={"User-Agent":"IntegrityChecker/1.0"})
            with urllib.request.urlopen(req, timeout=10) as r:
                remote_raw = r.read()
        except Exception as e:
            print("Erreur fetch remote:", e); return 0
        remote_norm = normalize_bytes(remote_raw)
        print("[DEBUG] sha256 local (norm):", sha256_bytes(local_norm))
        print("[DEBUG] sha256 remote (norm):", sha256_bytes(remote_norm))
    return 0

def remove_block_and_normalize(data_bytes):
    si = data_bytes.find(MARKER_START)
    if si == -1: return normalize_bytes(data_bytes)
    ei = data_bytes.find(MARKER_END, si)
    if ei == -1: return normalize_bytes(data_bytes)
    pure = data_bytes[:si] + data_bytes[ei + len(MARKER_END):]
    return normalize_bytes(pure)

def normalize_bytes(b):
    if b.startswith(b'\xef\xbb\xbf'): b = b[3:]
    b = b.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    lines = b.split(b'\n')
    lines = [ln.rstrip() for ln in lines]
    return b'\n'.join(lines)

def remove(local):
    if not os.path.exists(local): print("Fichier local introuvable:", local); return 2
    with open(local,"rb") as f: orig = f.read()
    si = orig.find(MARKER_START); ei = orig.find(MARKER_END, si) if si!=-1 else -1
    if si==-1 or ei==-1:
        print("Aucun bloc protecteur detecte."); return 0
    new = orig[:si] + orig[ei + len(MARKER_END):]
    bak = local + ".bak_remove"
    try:
        with open(bak,"wb") as b: b.write(orig)
    except Exception as e:
        print("Impossible d'ecrire backup:", e)
    with open(local,"wb") as w: w.write(new)
    print("[OK] Bloc protecteur retire de", local, "Sauvegarde:", bak)
    return 0

def main(argv):
    if len(argv)==3 and argv[1]=="--remove": return remove(argv[2])
    if len(argv)==4 and argv[1]=="--verbose": return inject(argv[2], argv[3], verbose=True)
    if len(argv)!=3:
        print(__doc__); return 1
    return inject(argv[1], argv[2], verbose=False)

if __name__=="__main__":
    sys.exit(main(sys.argv))
