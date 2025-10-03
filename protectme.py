#!/usr/bin/env python3
# protectme_final.py
# Reliable sign & inject tool — verifier is appended at EOF (safe), normalization-consistent.
# Requires: openssl on PATH for keygen/signing (runtime can use cryptography if present).

from __future__ import annotations
import os, sys, subprocess, tempfile, base64, shutil, stat, re

# --- configuration markers (text, end with newline) ---
MARKER_START_TXT = "# -- BEGIN PROTECTOR v1 --\n"
MARKER_END_TXT   = "# -- END PROTECTOR v1 --\n"
MARKER_START = MARKER_START_TXT.encode("utf-8")
MARKER_END = MARKER_END_TXT.encode("utf-8")

# verifier template (triple-double outer, triple-single for embedded base64)
VERIFIER_TEMPLATE = """{marker_start}
# Auto-injected integrity verifier (v1)
# This block is appended by protectme_final.py
import sys, os, base64, tempfile, shutil

_pub_b64 = r'''{pub_b64}'''
_sig_b64 = r'''{sig_b64}'''

def _normalize(b: bytes) -> bytes:
    if b.startswith(b'\\xef\\xbb\\bf'):
        b = b[3:]
    b = b.replace(b'\\r\\n', b'\\n').replace(b'\\r', b'\\n')
    lines = b.split(b'\\n')
    lines = [ln.rstrip() for ln in lines]
    return b'\\n'.join(lines)

def _read_without_block() -> bytes:
    try:
        with open(__file__, 'rb') as f:
            raw = f.read()
    except Exception as e:
        sys.stderr.write("\\n[INTEGRITY ERROR] cannot read file: {}\\n".format(e))
        sys.exit(1)
    start = {marker_start_bytes}
    end = {marker_end_bytes}
    # We expect the protector to be appended at EOF; find last occurrence of start
    si = raw.rfind(start)
    if si == -1:
        # no block -> normalize entire file
        return _normalize(raw)
    # ensure end after start
    ei = raw.find(end, si)
    if ei == -1:
        sys.stderr.write("\\n[INTEGRITY ERROR] protector end marker missing\\n")
        sys.exit(1)
    # remove block (from start to end+len(end))
    pure = raw[:si] + raw[ei + len(end):]
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
            tf_pub.write(pub_pem); tf_pub.flush(); pubf = tf_pub.name
        with tempfile.NamedTemporaryFile(delete=False) as tf_sig:
            tf_sig.write(sig); tf_sig.flush(); sigf = tf_sig.name
        with tempfile.NamedTemporaryFile(delete=False) as tf_code:
            tf_code.write(data); tf_code.flush(); codef = tf_code.name
        proc = subprocess.run(["openssl","dgst","-sha256","-verify",pubf,"-signature",sigf,codef], capture_output=True, text=True)
        for p in (pubf, sigf, codef):
            try: os.unlink(p)
            except Exception: pass
        return ("Verified OK" in (proc.stdout or "")) or (proc.returncode == 0 and "Verified OK" in (proc.stdout or ""))
    except Exception:
        return False

def _run_check():
    pub_pem = base64.b64decode(_pub_b64.encode("utf-8"))
    sig = base64.b64decode(_sig_b64.encode("utf-8"))
    data = _read_without_block()
    # prefer cryptography in-memory
    if _verify_with_cryptography(pub_pem, sig, data):
        return
    # fallback to openssl binary if present
    if shutil.which("openssl"):
        if _verify_with_openssl(pub_pem, sig, data):
            return
    sys.stderr.write("\\n[INTEGRITY ALERT] signature verification failed\\n")
    sys.exit(1)

# run check immediately
_run_check()
{marker_end}
"""

# ---------------- utilities ----------------

def normalize_bytes(b: bytes) -> bytes:
    if b.startswith(b'\xef\xbb\xbf'):
        b = b[3:]
    b = b.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    lines = b.split(b'\n')
    lines = [ln.rstrip() for ln in lines]
    return b'\n'.join(lines)

def read_file_raw(path: str) -> bytes:
    return open(path, "rb").read()

def write_file_raw(path: str, data: bytes):
    open(path, "wb").write(data)

def generate_keys(priv="priv.pem", pub="pub.pem", bits=3072) -> bool:
    if not shutil.which("openssl"):
        print("openssl is required but not found on PATH.")
        return False
    if os.path.exists(priv) or os.path.exists(pub):
        if input("One of the key files exists. Overwrite? (y/N) ").strip().lower() != "y":
            print("Aborted.")
            return False
    print("Running: openssl genpkey ...")
    if subprocess.call(["openssl","genpkey","-algorithm","RSA","-out",priv,"-pkeyopt",f"rsa_keygen_bits:{bits}"]) != 0:
        print("openssl genpkey failed.")
        return False
    if subprocess.call(["openssl","rsa","-in",priv,"-pubout","-out",pub]) != 0:
        print("openssl rsa -pubout failed.")
        return False
    try:
        os.chmod(priv, stat.S_IRUSR | stat.S_IWUSR)
    except Exception:
        pass
    print("Keys generated:", priv, pub)
    return True

def sign_normalized(priv_path: str, data: bytes) -> bytes:
    if not shutil.which("openssl"):
        raise RuntimeError("openssl required for signing")
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        tf.write(data); tf.flush(); temp_path = tf.name
    sig_tmp = tempfile.NamedTemporaryFile(delete=False)
    sig_tmp.close()
    cmd = ["openssl","dgst","-sha256","-sign",priv_path,"-out",sig_tmp.name,temp_path]
    print("Signing with:", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True)
    os.unlink(temp_path)
    if proc.returncode != 0:
        os.unlink(sig_tmp.name)
        raise RuntimeError("openssl signing failed: " + (proc.stderr or proc.stdout))
    sig = open(sig_tmp.name, "rb").read()
    os.unlink(sig_tmp.name)
    return sig

def verify_bytes_with_openssl(pub_pem: bytes, sig: bytes, data: bytes) -> bool:
    # helper used in injector to sanity-check signature
    if not shutil.which("openssl"):
        return False
    with tempfile.NamedTemporaryFile(delete=False) as tf_pub:
        tf_pub.write(pub_pem); tf_pub.flush(); pubf = tf_pub.name
    with tempfile.NamedTemporaryFile(delete=False) as tf_sig:
        tf_sig.write(sig); tf_sig.flush(); sigf = tf_sig.name
    with tempfile.NamedTemporaryFile(delete=False) as tf_code:
        tf_code.write(data); tf_code.flush(); codef = tf_code.name
    proc = subprocess.run(["openssl","dgst","-sha256","-verify",pubf,"-signature",sigf,codef], capture_output=True, text=True)
    for p in (pubf, sigf, codef):
        try: os.unlink(p)
        except Exception: pass
    return ("Verified OK" in (proc.stdout or "")) or (proc.returncode == 0 and "Verified OK" in (proc.stdout or ""))

# ---------------- core flows ----------------

def sign_and_inject(priv_path: str, pub_path: str, target: str, verbose: bool=False) -> bool:
    # ensure files exist
    if not os.path.exists(priv_path):
        print("Private key missing:", priv_path); return False
    if not os.path.exists(pub_path):
        print("Public key missing:", pub_path); return False
    if not os.path.exists(target):
        print("Target missing:", target); return False

    # read raw file and remove any existing protector block (if present)
    raw = read_file_raw(target)
    # find last occurrence of start marker and corresponding end marker
    si = raw.rfind(MARKER_START)
    if si != -1:
        ei = raw.find(MARKER_END, si)
        if ei == -1:
            print("Existing protector block end marker missing. Aborting."); return False
        pure = raw[:si] + raw[ei + len(MARKER_END):]
    else:
        pure = raw

    normalized = normalize_bytes(pure)
    if verbose:
        import hashlib
        print("[DEBUG] normalized sha256:", hashlib.sha256(normalized).hexdigest(), "len:", len(normalized))

    # sign normalized bytes
    try:
        sig = sign_normalized(priv_path, normalized)
    except Exception as e:
        print("Signing error:", e)
        return False

    pub_pem = open(pub_path, "rb").read()
    # sanity verify with openssl if available
    if shutil.which("openssl"):
        ok = verify_bytes_with_openssl(pub_pem, sig, normalized)
        if not ok:
            print("Sanity verification failed after signing. Aborting.")
            return False

    # build verifier block and append at EOF
    pub_b64 = base64.b64encode(pub_pem).decode("ascii")
    sig_b64 = base64.b64encode(sig).decode("ascii")
    verifier = VERIFIER_TEMPLATE.format(
        marker_start=MARKER_START_TXT.rstrip("\n"),
        marker_end=MARKER_END_TXT.rstrip("\n"),
        pub_b64=pub_b64,
        sig_b64=sig_b64,
        marker_start_bytes=repr(MARKER_START),
        marker_end_bytes=repr(MARKER_END),
    )

    # ensure newline separation and append at EOF
    if not raw.endswith(b"\n"):
        raw = raw + b"\n"
    appended = raw + verifier.encode("utf-8")
    # backup and write
    bak = target + ".bak_protect"
    try:
        write_file_raw(bak, read_file_raw(target))
    except Exception:
        pass
    try:
        write_file_raw(target, appended)
    except Exception as e:
        print("Failed to write protected file:", e)
        return False

    print(f"[OK] protector appended to {target} (backup: {bak})")
    if verbose:
        print("[DEBUG] pub_len:", len(pub_pem), "sig_len:", len(sig), "normalized_len:", len(normalized))
    return True

def remove_protector(target: str) -> bool:
    if not os.path.exists(target):
        print("Target missing:", target); return False
    raw = read_file_raw(target)
    si = raw.rfind(MARKER_START)
    if si == -1:
        print("No protector block found."); return False
    ei = raw.find(MARKER_END, si)
    if ei == -1:
        print("Protector end marker not found; aborting."); return False
    new = raw[:si] + raw[ei + len(MARKER_END):]
    bak = target + ".bak_remove"
    write_file_raw(bak, raw)
    write_file_raw(target, new)
    print(f"[OK] protector removed from {target} (backup: {bak})")
    return True

# ---------------- CLI / interactive ----------------

def interactive():
    print("=== protectme_final interactive ===")
    while True:
        print("\nActions:")
        print(" 1) generate keys (openssl priv.pem pub.pem)")
        print(" 2) sign & append protector (recommended)")
        print(" 3) remove protector block")
        print(" 4) exit")
        c = input("Choice: ").strip()
        if c == "1":
            priv = input("Private key path [priv.pem]: ").strip() or "priv.pem"
            pub = input("Public key path [pub.pem]: ").strip() or "pub.pem"
            bits = int(input("RSA bits [3072]: ").strip() or "3072")
            generate_keys(priv, pub, bits)
        elif c == "2":
            priv = input("Private key path [priv.pem]: ").strip() or "priv.pem"
            pub = input("Public key path [pub.pem]: ").strip() or "pub.pem"
            target = input("Target python file: ").strip()
            if not target:
                print("No target"); continue
            ok = sign_and_inject(priv, pub, target, verbose=True)
            if not ok:
                print("Failed.")
        elif c == "3":
            target = input("Target python file: ").strip()
            if not target:
                print("No target"); continue
            remove_protector(target)
        elif c == "4":
            break
        else:
            print("Invalid")

def parse_cli():
    import argparse
    p = argparse.ArgumentParser(prog="protectme_final.py")
    p.add_argument("--generate-keys", nargs=2, metavar=("PRIV","PUB"), help="generate keys")
    p.add_argument("--sign-inject", nargs=3, metavar=("PRIV","PUB","FILE"), help="sign & append protector to FILE")
    p.add_argument("--remove", nargs=1, metavar=("FILE"), help="remove protector from FILE")
    p.add_argument("--verbose", action="store_true", help="verbose")
    return p.parse_args()

def main():
    args = parse_cli()
    if args.generate_keys:
        return 0 if generate_keys(args.generate_keys[0], args.generate_keys[1]) else 2
    if args.sign_inject:
        priv,pub,target = args.sign_inject
        if not os.path.exists(priv) or not os.path.exists(pub):
            print("Keys missing."); return 3
        return 0 if sign_and_inject(priv, pub, target, verbose=args.verbose) else 4
    if args.remove:
        return 0 if remove_protector(args.remove[0]) else 5
    interactive()
    return 0

if __name__ == "__main__":
    sys.exit(main())
