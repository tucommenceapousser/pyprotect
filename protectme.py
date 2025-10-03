#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
protectme.py — outil fiable pour :
 - générer une paire RSA (priv.pem / pub.pem) via openssl
 - signer un fichier Python (signer la version normalisée SANS bloc)
 - injecter un bloc vérificateur (pub + signature encodées) dans le fichier
 - retirer le bloc vérificateur
 - vérification runtime : cryptography (si présent) ou openssl fallback

Usage (interactive):
  python3 protectme.py

Usage (non-interactive):
  python3 protectme.py --generate-keys priv.pem pub.pem
  python3 protectme.py --sign-inject priv.pem pub.pem target.py
  python3 protectme.py --remove target.py
  python3 protectme.py --verbose --sign-inject priv.pem pub.pem target.py
"""
from __future__ import annotations
import os, sys, re, subprocess, tempfile, base64, shutil, stat

# Markers (texte, avec newline)
MARKER_START_TXT = "# -- BEGIN SIGNATURE VERIFIER v3 --\n"
MARKER_END_TXT   = "# -- END SIGNATURE VERIFIER v3 --\n"
MARKER_START = MARKER_START_TXT.encode("utf-8")
MARKER_END = MARKER_END_TXT.encode("utf-8")

# Template for injected verifier (uses @@TOKENS@@ to avoid str.format issues)
VERIFIER_TEMPLATE = r"""
@@MARKER_START@@
# Auto-injected signature verifier (v3)
# Verifier injected by protectme.py
import os, sys, tempfile, base64, shutil

_pub_b64 = r'''@@PUB_B64@@'''
_sig_b64 = r'''@@SIG_B64@@'''

def _normalize(b: bytes) -> bytes:
    # remove BOM, unify newlines, strip trailing spaces on lines
    if b.startswith(b'\xef\xbb\xbf'):
        b = b[3:]
    b = b.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    lines = b.split(b'\n')
    lines = [ln.rstrip() for ln in lines]
    return b'\n'.join(lines)

def _read_without_block() -> bytes:
    try:
        with open(__file__, 'rb') as f:
            data = f.read()
    except Exception as e:
        sys.stderr.write("INTEGRITY ERROR: cannot read file: " + str(e) + "\n")
        sys.exit(1)
    s = "@@MARKER_START_TEXT@@".encode("utf-8")
    e = "@@MARKER_END_TEXT@@".encode("utf-8")
    si = data.find(s)
    if si == -1:
        return _normalize(data)
    ei = data.find(e, si)
    if ei == -1:
        sys.stderr.write("INTEGRITY ERROR: end marker missing\n"); sys.exit(1)
    pure = data[:si] + data[ei + len(e):]
    return _normalize(pure)

def _verify_with_cryptography(pub_pem: bytes, sig: bytes, data: bytes) -> bool:
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        pub = load_pem_public_key(pub_pem)
        pub.verify(sig, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

def _verify_with_openssl(pub_pem: bytes, sig: bytes, data: bytes) -> bool:
    try:
        with tempfile.NamedTemporaryFile(delete=False) as tf_pub:
            tf_pub.write(pub_pem); tf_pub.flush(); pub_path = tf_pub.name
        with tempfile.NamedTemporaryFile(delete=False) as tf_sig:
            tf_sig.write(sig); tf_sig.flush(); sig_path = tf_sig.name
        with tempfile.NamedTemporaryFile(delete=False) as tf_code:
            tf_code.write(data); tf_code.flush(); code_path = tf_code.name
        cmd = ["openssl", "dgst", "-sha256", "-verify", pub_path, "-signature", sig_path, code_path]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        for p in (pub_path, sig_path, code_path):
            try: os.unlink(p)
            except Exception: pass
        return ("Verified OK" in (proc.stdout or "")) or (proc.returncode == 0 and "Verified OK" in (proc.stdout or ""))
    except Exception:
        return False

def _run_check():
    pub_pem = base64.b64decode(_pub_b64.encode("utf-8"))
    sig = base64.b64decode(_sig_b64.encode("utf-8"))
    data = _read_without_block()
    if _verify_with_cryptography(pub_pem, sig, data):
        return
    if shutil.which("openssl"):
        if _verify_with_openssl(pub_pem, sig, data):
            return
    sys.stderr.write("\n[INTEGRITY ALERT] signature verification failed\n")
    sys.exit(1)

# execute check at import/runtime
_run_check()
@@MARKER_END@@
"""

# ---------------- helpers ----------------

def run_cmd(cmd: list[str], check=True, capture=False):
    if capture:
        return subprocess.run(cmd, capture_output=True, text=True)
    try:
        print("Running:", " ".join(cmd))
        subprocess.run(cmd, check=check)
        return None
    except subprocess.CalledProcessError as e:
        print("Command failed:", e)
        return None

def normalize_bytes(b: bytes) -> bytes:
    if b.startswith(b'\xef\xbb\xbf'):
        b = b[3:]
    b = b.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    lines = b.split(b'\n')
    lines = [ln.rstrip() for ln in lines]
    return b'\n'.join(lines)

def read_without_block(path: str) -> bytes:
    raw = open(path, "rb").read()
    si = raw.find(MARKER_START)
    if si == -1:
        return normalize_bytes(raw)
    ei = raw.find(MARKER_END, si)
    if ei == -1:
        raise RuntimeError("end marker missing in file")
    pure = raw[:si] + raw[ei + len(MARKER_END):]
    return normalize_bytes(pure)

def generate_keys(priv="priv.pem", pub="pub.pem", bits=3072):
    if not shutil.which("openssl"):
        print("openssl not found on PATH. Install openssl to generate keys.")
        return False
    if os.path.exists(priv) or os.path.exists(pub):
        if input("One of the key files exists. Overwrite? (y/N) ").strip().lower() != "y":
            print("Aborted.")
            return False
    if run_cmd(["openssl", "genpkey", "-algorithm", "RSA", "-out", priv, "-pkeyopt", f"rsa_keygen_bits:{bits}"]) is None:
        return False
    if run_cmd(["openssl", "rsa", "-in", priv, "-pubout", "-out", pub]) is None:
        return False
    try:
        os.chmod(priv, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass
    print("Keys generated:", priv, pub)
    return True

def sign_normalized_bytes(priv_path: str, data: bytes) -> bytes:
    # write normalized bytes to temp file and call openssl to sign
    if not shutil.which("openssl"):
        raise RuntimeError("openssl required for signing")
    tf = tempfile.NamedTemporaryFile(delete=False)
    tf.write(data); tf.flush(); tf.close()
    sig_tf = tempfile.NamedTemporaryFile(delete=False)
    sig_tf.close()
    cmd = ["openssl","dgst","-sha256","-sign",priv_path,"-out",sig_tf.name,tf.name]
    print("Running:", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        os.unlink(tf.name); os.unlink(sig_tf.name)
        raise RuntimeError("openssl sign failed: " + (proc.stderr or proc.stdout))
    sig = open(sig_tf.name, "rb").read()
    os.unlink(tf.name); os.unlink(sig_tf.name)
    return sig

def inject_signed(pub_path: str, priv_path: str, target: str, verbose=False) -> bool:
    if not os.path.exists(pub_path):
        print("Public key not found:", pub_path); return False
    if not os.path.exists(priv_path):
        print("Private key not found:", priv_path); return False

    # read target normalized bytes (remove any existing block first)
    try:
        normalized = read_without_block(target)
    except Exception as e:
        print("Error reading target without block:", e); return False

    # sign normalized bytes
    try:
        sig = sign_normalized_bytes(priv_path, normalized)
    except Exception as e:
        print("Signing failed:", e); return False

    # verify signature immediately (sanity)
    pub_pem = open(pub_path, "rb").read()
    pub_b64 = base64.b64encode(pub_pem).decode("utf-8")
    sig_b64 = base64.b64encode(sig).decode("utf-8")
    # verify with openssl to be sure
    ok = False
    if shutil.which("openssl"):
        # write temp files
        with tempfile.NamedTemporaryFile(delete=False) as tf_pub:
            tf_pub.write(pub_pem); tf_pub.flush(); pubf = tf_pub.name
        with tempfile.NamedTemporaryFile(delete=False) as tf_sig:
            tf_sig.write(sig); tf_sig.flush(); sigf = tf_sig.name
        with tempfile.NamedTemporaryFile(delete=False) as tf_code:
            tf_code.write(normalized); tf_code.flush(); codef = tf_code.name
        proc = subprocess.run(["openssl","dgst","-sha256","-verify",pubf,"-signature",sigf,codef], capture_output=True, text=True)
        for p in (pubf, sigf, codef):
            try: os.unlink(p)
            except Exception: pass
        if "Verified OK" in (proc.stdout or ""):
            ok = True
        else:
            print("OpenSSL sanity verification failed:", proc.stdout, proc.stderr)
            return False

    # build verifier string by replacing tokens
    verifier = VERIFIER_TEMPLATE
    verifier = verifier.replace("@@MARKER_START@@", MARKER_START_TXT.rstrip("\n"))
    verifier = verifier.replace("@@MARKER_END@@", MARKER_END_TXT.rstrip("\n"))
    verifier = verifier.replace("@@PUB_B64@@", pub_b64)
    verifier = verifier.replace("@@SIG_B64@@", sig_b64)
    verifier = verifier.replace("@@MARKER_START_TEXT@@", MARKER_START_TXT.rstrip("\n"))
    verifier = verifier.replace("@@MARKER_END_TEXT@@", MARKER_END_TXT.rstrip("\n"))
    # ensure newline after block when inserted
    verifier_full = verifier + "\n"

    # prepare insertion: keep shebang + encoding
    original_raw = open(target, "rb").read()
    try:
        s = original_raw.decode("utf-8", errors="surrogateescape")
        lines = s.splitlines(True)
        insert_at = 0
        if lines and lines[0].startswith("#!"):
            insert_at = 1
        if insert_at < len(lines) and re.match(r"\s*#.*coding[:=]\s*[-\w.]+", lines[insert_at]):
            insert_at += 1
        prefix = "".join(lines[:insert_at]).encode("utf-8")
        suffix = "".join(lines[insert_at:]).encode("utf-8")
        # remove previous block from suffix if present
        si = suffix.find(MARKER_START)
        if si != -1:
            ei = suffix.find(MARKER_END, si)
            if ei != -1:
                suffix = suffix[:si] + suffix[ei + len(MARKER_END):]
        new_bytes = prefix + verifier_full.encode("utf-8") + suffix
    except Exception:
        new_bytes = verifier_full.encode("utf-8") + original_raw

    # backup and write
    bak = target + ".bak"
    try:
        open(bak, "wb").write(original_raw)
    except Exception as e:
        print("Warning: could not write backup:", e)
    try:
        open(target, "wb").write(new_bytes)
    except Exception as e:
        print("Failed to write target:", e); return False

    print(f"[OK] verifier injected into {target} (backup: {bak})")
    if verbose:
        print("[DEBUG] pub len:", len(pub_pem), "sig len:", len(sig), "normalized len:", len(normalized))
    return True

def remove_block(target: str) -> bool:
    if not os.path.exists(target):
        print("Target not found:", target); return False
    raw = open(target, "rb").read()
    si = raw.find(MARKER_START)
    if si == -1:
        print("No verifier block found."); return False
    ei = raw.find(MARKER_END, si)
    if ei == -1:
        print("End marker not found; aborting."); return False
    new = raw[:si] + raw[ei + len(MARKER_END):]
    bak = target + ".bak_remove"
    open(bak, "wb").write(raw)
    open(target, "wb").write(new)
    print(f"[OK] verifier removed. Backup: {bak}")
    return True

# ---------------- CLI / interactive ----------------

def interactive():
    print("=== protectme v3 interactive ===")
    while True:
        print("\nActions:")
        print(" 1) generate keys (openssl priv.pem pub.pem)")
        print(" 2) sign & inject (recommended)")
        print(" 3) remove verifier block")
        print(" 4) exit")
        choice = input("Choice: ").strip()
        if choice == "1":
            priv = input("Private key path [priv.pem]: ").strip() or "priv.pem"
            pub = input("Public key path [pub.pem]: ").strip() or "pub.pem"
            bits = int(input("RSA bits [3072]: ").strip() or "3072")
            generate_keys(priv, pub, bits)
        elif choice == "2":
            priv = input("Private key path [priv.pem]: ").strip() or "priv.pem"
            pub = input("Public key path [pub.pem]: ").strip() or "pub.pem"
            target = input("Target python file: ").strip()
            if not target:
                print("No target provided."); continue
            inject_signed = inject_signed if False else inject_signed  # avoid linter warning
            ok = inject_signed(pub, priv, target, verbose=True)
            if not ok:
                print("Failed to inject.")
        elif choice == "3":
            target = input("Target python file: ").strip()
            if not target:
                print("No target."); continue
            remove_block(target)
        elif choice == "4":
            break
        else:
            print("Invalid choice.")

def parse_cli():
    import argparse
    p = argparse.ArgumentParser(prog="protectme.py", description="Sign & inject verifier (protectme v3)")
    p.add_argument("--generate-keys", nargs=2, metavar=("PRIV","PUB"), help="generate keys (non-interactive)")
    p.add_argument("--sign-inject", nargs=3, metavar=("PRIV","PUB","FILE"), help="sign target (without block) and inject verifier")
    p.add_argument("--remove", nargs=1, metavar=("FILE"), help="remove verifier block from FILE")
    p.add_argument("--verbose", action="store_true", help="verbose debug")
    return p.parse_args()

def main():
    args = parse_cli()
    if args.generate_keys:
        priv, pub = args.generate_keys; return 0 if generate_keys(priv, pub) else 2
    if args.sign_inject:
        priv, pub, target = args.sign_inject
        if not os.path.exists(priv) or not os.path.exists(pub):
            print("Keys missing."); return 3
        return 0 if inject_signed(pub, priv, target, verbose=args.verbose) else 4
    if args.remove:
        return 0 if remove_block(args.remove[0]) else 5
    interactive()
    return 0

if __name__ == "__main__":
    sys.exit(main())
