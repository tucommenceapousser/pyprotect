#!/usr/bin/env python3
"""
protectme_debug.py
Usage:
  python protectme_debug.py <fichier_local.py> <url_fichier_distant>
  python protectme_debug.py --remove <fichier_local.py>
  python protectme_debug.py --verbose <fichier_local.py> <url_fichier_distant>

Injecte un protecteur qui, en cas d'échec, affiche :
 - sha256(local_norm) et sha256(remote_norm)
 - tailles (bytes)
 - premiers octets (texte et hex)
pour diagnostiquer toute différence d'encodage/EOL/BOM/espaces invisibles.
"""
from __future__ import annotations
import sys, os, re, hashlib, urllib.request, urllib.parse

MARKER_START = b"# -- BEGIN INTEGRITY PROTECTOR DEBUG v1 --\n"
MARKER_END   = b"# -- END INTEGRITY PROTECTOR DEBUG v1 --\n"

# corps du protecteur (bytes). Token __REMOTE_URL__ remplacé à l'injection.
PROTECTOR_BODY = (
    b"# Bloc injecte: verif integrite (debug mode)\\n"
    b"import sys, hashlib, urllib.request, binascii\\n\\n"
    b"def _norm(b):\\n"
    b"    if b.startswith(b'\\xef\\xbb\\xbf'): b=b[3:]\\n"
    b"    b = b.replace(b'\\r\\n', b'\\n').replace(b'\\r', b'\\n')\\n"
    b"    lines = b.split(b'\\n')\\n"
    b"    lines = [ln.rstrip() for ln in lines]\\n"
    b"    return b'\\n'.join(lines)\\n\\n"
    b"def _read_local_without_block():\\n"
    b"    try:\\n"
    b"        with open(__file__, 'rb') as f: data = f.read()\\n"
    b"    except Exception as e:\\n"
    b"        sys.stderr.write('IMPOSSIBLE LIRE LOCAL: '+str(e)+\"\\n\")\\n"
    b"        sys.exit(1)\\n"
    b"    s = b'__MARKER_START__'\\n"
    b"    e = b'__MARKER_END__'\\n"
    b"    si = data.find(s)\\n"
    b"    ei = data.find(e)\\n"
    b"    if si != -1 and ei != -1 and ei > si:\\n"
    b"        data = data[:si] + data[ei + len(e):]\\n"
    b"    return _norm(data)\\n\\n"
    b"def _fetch_remote_norm(url):\\n"
    b"    try:\\n"
    b"        req = urllib.request.Request(url, headers={'User-Agent':'IntegrityChecker/1.0'})\\n"
    b"        with urllib.request.urlopen(req, timeout=10) as r: rb = r.read()\\n"
    b"        return _norm(rb)\\n"
    b"    except Exception as e:\\n"
    b"        sys.stderr.write('IMPOSSIBLE FETCH REMOTE: '+str(e)+\"\\n\"); sys.exit(1)\\n\\n"
    b"def _sha(b):\\n"
    b"    h = hashlib.sha256(); h.update(b); return h.hexdigest()\\n\\n"
    b"def _dump_prefix(b, n=200):\\n"
    b"    try: t = b.decode('utf-8', errors='replace')\\n"
    b"    except Exception: t = ''\\n"
    b"    return t[:n], binascii.hexlify(b[:n]).decode('ascii')\\n\\n"
    b"def _check():\\n"
    b"    url = '__REMOTE_URL__'\\n"
    b"    local = _read_local_without_block()\\n"
    b"    remote = _fetch_remote_norm(url)\\n"
    b"    if _sha(local) != _sha(remote):\\n"
    b"        sys.stderr.write('\\n[INTEGRITY ALERT] mismatch detected\\n')\\n"
    b"        sys.stderr.write('local sha256: '+_sha(local)+'\\n')\\n"
    b"        sys.stderr.write('remote sha256:'+_sha(remote)+'\\n')\\n"
    b"        sys.stderr.write('local size: '+str(len(local))+' bytes\\n')\\n"
    b"        sys.stderr.write('remote size:'+str(len(remote))+' bytes\\n')\\n"
    b"        lt, lhex = _dump_prefix(local)\\n"
    b"        rt, rhex = _dump_prefix(remote)\\n"
    b"        sys.stderr.write('--- local prefix (text) ---\\n'+lt+'\\n')\\n"
    b"        sys.stderr.write('--- local prefix (hex) ---\\n'+lhex+'\\n')\\n"
    b"        sys.stderr.write('--- remote prefix (text) ---\\n'+rt+'\\n')\\n"
    b"        sys.stderr.write('--- remote prefix (hex) ---\\n'+rhex+'\\n')\\n"
    b"        sys.exit(1)\\n"
    b"    # ok -> continue\\n"
    b"_check()\\n"
)

def normalize_github_raw(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    if "github.com" in parsed.netloc:
        path = parsed.path
        parts = path.split("/")
        if len(parts) > 4 and parts[3] == "blob":
            user, repo, branch = parts[1], parts[2], parts[4]; rest = "/".join(parts[5:])
            return f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{rest}"
        m = re.match(r"^/([^/]+)/([^/]+)/refs/heads/([^/]+)/(.*)$", path)
        if m:
            user, repo, branch, rest = m.groups()
            return f"https://raw.githubusercontent.com/{user}/{repo}/{branch}/{rest}"
    return url

def sha256(b: bytes) -> str:
    h = hashlib.sha256(); h.update(b); return h.hexdigest()

def inject(local_path: str, remote_url: str, verbose: bool=False) -> int:
    if not os.path.exists(local_path):
        print("[ERREUR] fichier local introuvable:", local_path); return 2
    remote_url = normalize_github_raw(remote_url)
    if verbose: print("[DEBUG] URL utilisée :", remote_url)

    body = PROTECTOR_BODY.replace(b"__REMOTE_URL__", remote_url.encode("utf-8"))
    body = body.replace(b"__MARKER_START__", MARKER_START.strip()).replace(b"__MARKER_END__", MARKER_END.strip())
    protector = MARKER_START + body + MARKER_END

    with open(local_path, "rb") as f: orig = f.read()

    si = orig.find(MARKER_START); ei = orig.find(MARKER_END, si) if si!=-1 else -1
    if si!=-1 and ei!=-1:
        if ei <= si: print("[ERREUR] marqueurs incoherents"); return 4
        new = orig[:si] + protector + orig[ei + len(MARKER_END):]; action="remplacé"
    else:
        try:
            text = orig.decode("utf-8", errors="surrogateescape"); lines = text.splitlines(True)
            insert_at = 0
            if lines and lines[0].startswith("#!"): insert_at=1
            if insert_at < len(lines) and re.match(r"\s*#.*coding[:=]\s*[-\w.]+", lines[insert_at]): insert_at+=1
            prefix = "".join(lines[:insert_at]).encode("utf-8"); suffix = "".join(lines[insert_at:]).encode("utf-8")
            new = prefix + protector + suffix
        except Exception:
            new = protector + orig
        action="inséré"

    bak = local_path + ".bak"
    try:
        with open(bak, "wb") as b: b.write(orig)
    except Exception as e:
        print("[ATTENTION] impossible d'ecrire backup:", e)
    with open(local_path, "wb") as w: w.write(new)

    print(f"[OK] Bloc protecteur {action} dans {local_path}. Sauvegarde: {bak}")
    print("-> URL utilisée (normalisée si applicable):", remote_url)

    if verbose:
        # affiche hashes normalisés pour debug à l'injection
        # calcule local_norm comme fera le protecteur
        def norm(b): 
            if b.startswith(b'\\xef\\xbb\\xbf'): b=b[3:]
            b=b.replace(b'\\r\\n', b'\\n').replace(b'\\r', b'\\n')
            lines=b.split(b'\\n'); lines=[ln.rstrip() for ln in lines]; return b'\\n'.join(lines)
        start = MARKER_START; end = MARKER_END
        si = new.find(start); ei = new.find(end, si) if si!=-1 else -1
        if si!=-1 and ei!=-1:
            local_without = new[:si] + new[ei + len(end):]
        else:
            local_without = new
        local_norm = norm(local_without)
        try:
            req = urllib.request.Request(remote_url, headers={"User-Agent":"IntegrityChecker/1.0"})
            with urllib.request.urlopen(req, timeout=10) as r: remote_raw = r.read()
            remote_norm = norm(remote_raw)
            print("[DEBUG] sha256 local (norm):", sha256(local_norm))
            print("[DEBUG] sha256 remote (norm):", sha256(remote_norm))
            print("[DEBUG] remote size:", len(remote_raw))
        except Exception as e:
            print("[DEBUG] fetch remote failed:", e)
    return 0

def remove(local_path: str) -> int:
    if not os.path.exists(local_path):
        print("[ERREUR] fichier local introuvable:", local_path); return 2
    with open(local_path, "rb") as f: orig = f.read()
    si = orig.find(MARKER_START); ei = orig.find(MARKER_END, si) if si!=-1 else -1
    if si==-1 or ei==-1:
        print("[INFO] Aucun bloc protecteur détecté."); return 0
    new = orig[:si] + orig[ei + len(MARKER_END):]
    bak = local_path + ".bak_remove"
    try:
        with open(bak, "wb") as b: b.write(orig)
    except Exception as e:
        print("[ATTENTION] impossible d'ecrire backup:", e)
    with open(local_path, "wb") as w: w.write(new)
    print("[OK] Bloc protecteur retiré de", local_path, "Sauvegarde:", bak)
    return 0

def main(argv):
    if len(argv)==3 and argv[1]=="--remove": return remove(argv[2])
    if len(argv)==4 and argv[1]=="--verbose": return inject(argv[2], argv[3], verbose=True)
    if len(argv)!=3:
        print(__doc__); return 1
    return inject(argv[1], argv[2], verbose=False)

if __name__=="__main__":
    sys.exit(main(sys.argv))
