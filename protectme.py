#!/usr/bin/env python3
"""
protectme.py - Sign & inject verifier (correct order: sign original -> inject)

Features:
 - generate RSA keypair (openssl)
 - sign a target Python file (signs the file content WITHOUT verifier block)
 - inject a verifier block that contains public key + signature (base64)
 - verifier removes injected block at runtime, normalizes bytes and verifies signature
 - removal of verifier block supported
 - fallback verification: cryptography (in-memory) -> openssl (external)
"""
from __future__ import annotations
import os, sys, subprocess, shutil, tempfile, base64, re

# plain text markers (include newline)
MARKER_START = "# -- BEGIN SIGNATURE VERIFIER v2 --\n"
MARKER_END   = "# -- END SIGNATURE VERIFIER v2 --\n"

# verifier template uses @@TOKENS@@ to avoid format issues
VERIFIER_TEMPLATE = r"""
@@MARKER_START@@
# Auto-injected signature verifier (v2)
# Verifier embedded by protectme.py
import os, sys, tempfile, subprocess, base64, shutil

_pub_b64 = r'''@@PUB_B64@@'''
_sig_b64 = r'''@@SIG_B64@@'''

def _normalize(b: bytes) -> bytes:
    # remove BOM, unify newlines, strip trailing spaces
    if b.startswith(b'\xef\xbb\xbf'):
        b = b[3:]
    b = b.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    lines = b.split(b'\n')
    lines = [ln.rstrip() for ln in lines]
    return b'\n'.join(lines)

def _read_file_without_block() -> bytes:
    try:
        with open(__file__, 'rb') as f:
            data = f.read()
    except Exception as e:
        sys.stderr.write("INTEGRITY ERROR: cannot read file: " + str(e) + "\n")
        sys.exit(1)
    start = "@@MARKER_START_TEXT@@".encode("utf-8")
    end = "@@MARKER_END_TEXT@@".encode("utf-8")
    si = data.find(start)
    if si == -1:
        return _normalize(data)
    ei = data.find(end, si)
    if ei == -1:
        sys.stderr.write("INTEGRITY ERROR: end marker missing\n"); sys.exit(1)
    pure = data[:si] + data[ei + len(end):]
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
        # cleanup
        for p in (pub_path, sig_path, code_path):
            try: os.unlink(p)
            except Exception: pass
        return ("Verified OK" in (proc.stdout or "")) or (proc.returncode == 0 and "Verified OK" in (proc.stdout or ""))
    except Exception:
        return False

def _run():
    pub_pem = base64.b64decode(_pub_b64.encode("utf-8"))
    sig = base64.b64decode(_sig_b64.encode("utf-8"))
    data = _read_file_without_block()
    # try in-memory crypto first
    ok = _verify_with_cryptography(pub_pem, sig, data)
    if ok:
        return
    # else fallback to openssl if available
    if shutil.which("openssl"):
        ok2 = _verify_with_openssl(pub_pem, sig, data)
        if ok2:
            return
    sys.stderr.write("\n[INTEGRITY ALERT] signature verification failed\n")
    sys.exit(1)

_run()
@@MARKER_END@@
"""

def run_cmd(cmd, check=True):
    try:
        print("Running:", " ".join(cmd))
        subprocess.run(cmd, check=check)
        return True
    except subprocess.CalledProcessError as e:
        print("Command failed:", e)
        return False

def normalize_bytes(b: bytes) -> bytes:
    if b.startswith(b'\xef\xbb\xbf'):
        b = b[3:]
    b = b.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    lines = b.split(b'\n')
    lines = [ln.rstrip() for ln in lines]
    return b'\n'.join(lines)

def read_without_block_bytes(path: str) -> bytes:
    with open(path, "rb") as f:
        data = f.read()
    s = MARKER_START.encode("utf-8")
    e = MARKER_END.encode("utf-8")
    si = data.find(s)
    if si == -1:
        return normalize_bytes(data)
    ei = data.find(e, si)
    if ei == -1:
        raise RuntimeError("end marker missing in file")
    pure = data[:si] + data[ei + len(e):]
    return normalize_bytes(pure)

def generate_keys(priv="priv.pem", pub="pub.pem", bits=3072):
    if os.path.exists(priv) or os.path.exists(pub):
        if input("One of the key files exists. Overwrite? (y/N) ").strip().lower() != "y":
            print("Aborted.")
            return False
    if not shutil.which("openssl"):
        print("openssl not found on PATH; cannot generate keys.")
        return False
    if not run_cmd(["openssl", "genpkey", "-algorithm", "RSA", "-out", priv, "-pkeyopt", f"rsa_keygen_bits:{bits}"], check=False):
        return False
    if not run_cmd(["openssl", "rsa", "-in", priv, "-pubout", "-out", pub], check=False):
        return False
    print("Keys generated:", priv, pub)
    return True

def sign_content_with_priv(priv_path: str, content_bytes: bytes) -> bytes:
    # write normalized content to temp file and run openssl dgst -sha256 -sign
    tf = tempfile.NamedTemporaryFile(delete=False)
    try:
        tf.write(content_bytes); tf.flush(); tf.close()
        sig_tf = tempfile.NamedTemporaryFile(delete=False)
        sig_tf.close()
        cmd = ["openssl", "dgst", "-sha256", "-sign", priv_path, "-out", sig_tf.name, tf.name]
        if not run_cmd(cmd, check=False):
            raise RuntimeError("openssl signing failed")
        with open(sig_tf.name, "rb") as sf:
            sig = sf.read()
    finally:
        for p in (tf.name, sig_tf.name):
            try: os.unlink(p)
            except Exception: pass
    return sig

def inject_signed(pub_path: str, priv_path: str, target: str, verbose: bool=False) -> bool:
    if not os.path.exists(pub_path):
        print("Public key not found:", pub_path); return False
    if not os.path.exists(priv_path):
        print("Private key not found:", priv_path); return False
    # read original file and compute normalized bytes without any existing block
    try:
        orig_bytes = read_without_block_bytes(target)
    except Exception as e:
        print("Error reading target without block:", e); return False
    # sign normalized bytes
    sig = sign_content_with_priv(priv_path, orig_bytes)
    pub_pem = open(pub_path, "rb").read()
    pub_b64 = base64.b64encode(pub_pem).decode("utf-8")
    sig_b64 = base64.b64encode(sig).decode("utf-8")
    # prepare verifier text by replacing tokens
    verifier = VERIFIER_TEMPLATE
    verifier = verifier.replace("@@MARKER_START@@", MARKER_START.rstrip("\n"))
    verifier = verifier.replace("@@MARKER_END@@", MARKER_END.rstrip("\n"))
    verifier = verifier.replace("@@PUB_B64@@", pub_b64)
    verifier = verifier.replace("@@SIG_B64@@", sig_b64)
    verifier = verifier.replace("@@MARKER_START_TEXT@@", MARKER_START.rstrip("\n"))
    verifier = verifier.replace("@@MARKER_END_TEXT@@", MARKER_END.rstrip("\n"))
    # ensure final verifier contains newline-terminated markers
    verifier = verifier.replace("@@MARKER_START@@", MARKER_START.rstrip("\n")).replace("@@MARKER_END@@", MARKER_END.rstrip("\n"))
    verifier_full = verifier
    # create new file content: insert after shebang + encoding line if present
    with open(target, "rb") as f:
        original_raw = f.read()
    try:
        txt = original_raw.decode("utf-8", errors="surrogateescape")
        lines = txt.splitlines(True)
        insert_at = 0
        if lines and lines[0].startswith("#!"):
            insert_at = 1
        if insert_at < len(lines) and re.match(r"\s*#.*coding[:=]\s*[-\w.]+", lines[insert_at]):
            insert_at += 1
        prefix = "".join(lines[:insert_at]).encode("utf-8")
        suffix = "".join(lines[insert_at:]).encode("utf-8")
        new_bytes = prefix + verifier_full.encode("utf-8") + b"\n" + suffix
    except Exception:
        new_bytes = verifier_full.encode("utf-8") + b"\n" + original_raw
    # backup and write
    bak = target + ".bak"
    with open(bak, "wb") as bf:
        bf.write(original_raw)
    with open(target, "wb") as wf:
        wf.write(new_bytes)
    print(f"[OK] Injected verifier into {target} (backup: {bak})")
    if verbose:
        print("[DEBUG] pub len:", len(pub_pem), "sig len:", len(sig))
    return True

def remove_verifier(target: str) -> bool:
    if not os.path.exists(target):
        print("Target not found:", target); return False
    raw = open(target, "rb").read()
    s = MARKER_START.encode("utf-8")
    e = MARKER_END.encode("utf-8")
    si = raw.find(s)
    if si == -1:
        print("No verifier block found."); return False
    ei = raw.find(e, si)
    if ei == -1:
        print("End marker missing; aborting."); return False
    new = raw[:si] + raw[ei + len(e):]
    bak = target + ".bak_remove"
    with open(bak, "wb") as bf:
        bf.write(raw)
    with open(target, "wb") as wf:
        wf.write(new)
    print("Verifier removed. Backup:", bak)
    return True

def interactive():
    print("=== protectme interactive ===")
    while True:
        print("\nActions:")
        print(" 1) generate-keys")
        print(" 2) sign + inject (recommended)")
        print(" 3) remove verifier")
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
                print("No target."); continue
            if not os.path.exists(priv):
                print("Private key missing:", priv); continue
            if not os.path.exists(pub):
                print("Public key missing:", pub); continue
            sign_ok = inject_signed(pub, priv, target, verbose=True)
            if not sign_ok:
                print("Failed to inject.")
        elif choice == "3":
            target = input("Target python file: ").strip()
            remove_verifier(target)
        elif choice == "4":
            break
        else:
            print("Invalid")

def parse_cli():
    import argparse
    p = argparse.ArgumentParser(description="protectme: sign & inject verifier")
    p.add_argument("--generate-keys", nargs=2, metavar=("PRIV","PUB"), help="generate keys (non-interactive)")
    p.add_argument("--sign-inject", nargs=3, metavar=("PRIV","PUB","FILE"), help="sign target (without block) and inject verifier (non-interactive)")
    p.add_argument("--remove", nargs=1, metavar=("FILE"), help="remove verifier from FILE")
    return p.parse_args()

def main():
    args = parse_cli()
    if args.generate_keys:
        priv, pub = args.generate_keys
        return 0 if generate_keys(priv, pub) else 2
    if args.sign_inject:
        priv, pub, target = args.sign_inject
        if not os.path.exists(priv) or not os.path.exists(pub):
            print("Keys missing."); return 3
        return 0 if inject_signed(pub, priv, target, verbose=True) else 4
    if args.remove:
        return 0 if remove_verifier(args.remove[0]) else 5
    interactive()
    return 0

if __name__ == "__main__":
    sys.exit(main())
