#!/usr/bin/env python3
"""
sign_and_inject.py

Interactive tool:
 - generate RSA keypair (priv.pem / pub.pem) via openssl
 - sign a target file (produces <target>.sig)
 - inject a verification snippet at the top of the target that verifies signature at runtime

Usage:
  python3 sign_and_inject.py
  python3 sign_and_inject.py --remove target.py    # remove injected verifier block
  python3 sign_and_inject.py --help

Requirements:
 - openssl on PATH (for key generation & signing)
 - Python 3.6+
 - optionally: cryptography (pip install cryptography) for runtime verification without calling openssl
"""
from __future__ import annotations
import os
import sys
import subprocess
import shutil
import argparse
import tempfile
import textwrap

MARKER_START = "# -- BEGIN SIGNATURE VERIFIER v1 --"
MARKER_END   = "# -- END SIGNATURE VERIFIER v1 --"

VERIFIER_TEMPLATE = r'''{marker_start}
# Auto-injected signature verifier (v1)
# This code was injected by sign_and_inject.py
# It verifies that the current file's signature (<file>.sig) matches the file contents.
import os, sys, hashlib, tempfile, subprocess

# Public key PEM embedded below:
_pub_pem = r"""{pub_pem}"""

_SIG_FILENAME = "{sig_filename}"  # relative or absolute path to signature file (created by signing step)

def _norm_bytes(b: bytes) -> bytes:
    # normalize: remove BOM, unify line endings, strip trailing spaces on lines
    if b.startswith(b'\xef\xbb\xbf'):
        b = b[3:]
    b = b.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    lines = b.split(b'\n')
    lines = [ln.rstrip() for ln in lines]
    return b'\n'.join(lines)

def _verify_with_cryptography(pub_pem: bytes, sig: bytes, data: bytes) -> bool:
    try:
        # try to use cryptography if available (no external process)
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.primitives import hashes
        pub = load_pem_public_key(pub_pem)
        pub.verify(
            sig,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def _verify_with_openssl(pub_pem: bytes, sig: bytes, data_path: str) -> bool:
    # write pub to temp file and call openssl dgst -sha256 -verify pub -signature sig file
    try:
        with tempfile.NamedTemporaryFile("wb", delete=False) as tf:
            tf.write(pub_pem)
            tf.flush()
            pubpath = tf.name
        cmd = ["openssl", "dgst", "-sha256", "-verify", pubpath, "-signature", _SIG_FILENAME, data_path]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        # cleanup
        try:
            os.unlink(pubpath)
        except Exception:
            pass
        return ("Verified OK" in (proc.stdout or "")) or (proc.returncode == 0 and "Verified OK" in (proc.stdout or ""))
    except Exception:
        return False

def _read_sig(sig_path: str) -> bytes:
    try:
        with open(sig_path, "rb") as f:
            return f.read()
    except Exception:
        return b""

def _run_check():
    # determine signature path
    # If _SIG_FILENAME is absolute, use it; otherwise, sibling to this file
    sig_path = _SIG_FILENAME
    if not os.path.isabs(sig_path):
        sig_path = os.path.join(os.path.dirname(__file__), _SIG_FILENAME)

    if not os.path.exists(sig_path):
        sys.stderr.write("\\n[INTEGRITY ALERT] signature file not found: {}\\n".format(sig_path))
        sys.exit(1)

    # read data (file content) as bytes
    try:
        with open(__file__, "rb") as f:
            raw = f.read()
    except Exception as e:
        sys.stderr.write("\\n[INTEGRITY ALERT] cannot read file: {}\\n".format(e))
        sys.exit(1)

    # remove injected block before verification
    start_marker = b"{marker_start_bytes}"
    end_marker = b"{marker_end_bytes}"
    si = raw.find(start_marker)
    if si != -1:
        ei = raw.find(end_marker, si)
        if ei != -1:
            pure = raw[:si] + raw[ei + len(end_marker):]
        else:
            sys.stderr.write("\\n[INTEGRITY ALERT] end marker missing\\n")
            sys.exit(1)
    else:
        pure = raw

    data = _norm_bytes(pure)
    sig = _read_sig(sig_path)
    if not sig:
        sys.stderr.write("\\n[INTEGRITY ALERT] empty signature file\\n")
        sys.exit(1)

    pub_pem = _pub_pem.encode('utf-8')

    # prefer cryptography (in-memory) if available
    ok = _verify_with_cryptography(pub_pem, sig, data)
    if ok:
        return
    # fallback to openssl if available
    if shutil.which("openssl"):
        ok2 = _verify_with_openssl(pub_pem, sig, os.path.abspath(__file__))
        if ok2:
            return

    # failed
    sys.stderr.write("\\n[INTEGRITY ALERT] signature verification failed.\\n")
    sys.exit(1)

# run check immediately
_run_check()
{marker_end}
'''

def run_command(cmd, check=True):
    try:
        proc = subprocess.run(cmd, check=check)
        return proc.returncode == 0
    except subprocess.CalledProcessError:
        return False

def generate_keys_interactive(priv_path="priv.pem", pub_path="pub.pem", bits=3072):
    print("Generating RSA keypair with openssl (this requires openssl on PATH).")
    print(f"Private key -> {priv_path}")
    print(f"Public key  -> {pub_path}")
    ok = True
    if os.path.exists(priv_path) or os.path.exists(pub_path):
        resp = input("One of the key files exists. Overwrite? (y/N) ").strip().lower()
        if resp != "y":
            print("Aborted key generation.")
            return False
    cmd_gen = ["openssl", "genpkey", "-algorithm", "RSA", "-out", priv_path, f"-pkeyopt", f"rsa_keygen_bits:{bits}"]
    print("Running:", " ".join(cmd_gen))
    if not run_command(cmd_gen, check=False):
        print("openssl genpkey failed. Do you have openssl installed?")
        return False
    cmd_pub = ["openssl", "rsa", "-in", priv_path, "-pubout", "-out", pub_path]
    print("Extracting public key:", " ".join(cmd_pub))
    if not run_command(cmd_pub, check=False):
        print("openssl rsa -pubout failed.")
        return False
    print("Keys generated.")
    return True

def sign_file(priv_path, target_path, sig_path=None):
    if sig_path is None:
        sig_path = target_path + ".sig"
    if not os.path.exists(priv_path):
        print("Private key not found:", priv_path)
        return False
    cmd = ["openssl", "dgst", "-sha256", "-sign", priv_path, "-out", sig_path, target_path]
    print("Signing:", " ".join(cmd))
    ok = run_command(cmd, check=False)
    if not ok:
        print("Signing failed. Ensure openssl is available.")
        return False
    print("Signature written to:", sig_path)
    return True

def inject_verifier(pub_pem_path, target_path, sig_filename=None, overwrite=False):
    # read pub pem
    with open(pub_pem_path, "r", encoding="utf-8") as f:
        pub_pem = f.read()

    if sig_filename is None:
        sig_filename = os.path.basename(target_path) + ".sig"

    # read original file
    with open(target_path, "rb") as f:
        orig = f.read()

    # if already injected, refuse unless overwrite True
    if orig.find(MARKER_START.encode("utf-8")) != -1 and not overwrite:
        print("Verifier block already present in target. Use --force to overwrite.")
        return False

    # build verifier text (escape triple quotes inside pub? we use r"""...""", safe)
    verifier_text = VERIFIER_TEMPLATE.format(
        marker_start=MARKER_START,
        marker_end=MARKER_END,
        pub_pem=pub_pem,
        sig_filename=sig_filename,
        marker_start_bytes=MARKER_START.encode("utf-8"),
        marker_end_bytes=MARKER_END.encode("utf-8")
    )

    # We constructed using repr of bytes markers; but template expects bytes literal placeholders.
    # Replace placeholders of bytes form:
    verifier_text = verifier_text.replace(str(MARKER_START), MARKER_START.decode("utf-8"))
    verifier_text = verifier_text.replace(str(MARKER_END), MARKER_END.decode("utf-8"))

    # final injected bytes
    try:
        verifier_bytes = verifier_text.encode("utf-8")
    except Exception as e:
        print("Encoding verifier failed:", e)
        return False

    # insertion position: after shebang and encoding line if present
    try:
        txt = orig.decode("utf-8", errors="surrogateescape")
        lines = txt.splitlines(True)
        insert_at = 0
        if lines and lines[0].startswith("#!"):
            insert_at = 1
        if insert_at < len(lines) and re.match(r"\s*#.*coding[:=]\s*[-\w.]+", lines[insert_at]):
            insert_at += 1
        prefix = "".join(lines[:insert_at]).encode("utf-8")
        suffix = "".join(lines[insert_at:]).encode("utf-8")
        new = prefix + verifier_bytes + suffix
    except Exception:
        new = verifier_bytes + orig

    backup = target_path + ".bak"
    with open(backup, "wb") as f:
        f.write(orig)
    with open(target_path, "wb") as f:
        f.write(new)
    print("Verifier injected into", target_path, "(backup at", backup, ")")
    return True

def remove_verifier(target_path):
    with open(target_path, "rb") as f:
        orig = f.read()
    start = MARKER_START.encode("utf-8")
    end = MARKER_END.encode("utf-8")
    si = orig.find(start)
    if si == -1:
        print("No verifier block found.")
        return False
    ei = orig.find(end, si)
    if ei == -1:
        print("End marker not found; aborting.")
        return False
    new = orig[:si] + orig[ei + len(end):]
    backup = target_path + ".bak_remove"
    with open(backup, "wb") as f:
        f.write(orig)
    with open(target_path, "wb") as f:
        f.write(new)
    print("Verifier removed. Backup:", backup)
    return True

def interactive_main():
    print("=== sign_and_inject interactive ===\n")
    while True:
        print("Choose action:")
        print(" 1) Generate keypair (openssl priv.pem + pub.pem)")
        print(" 2) Sign a file")
        print(" 3) Sign + inject verifier into file (recommended)")
        print(" 4) Remove verifier from file")
        print(" 5) Exit")
        choice = input("Action (1-5): ").strip()
        if choice == "1":
            priv = input("Private key path [priv.pem]: ").strip() or "priv.pem"
            pub = input("Public key path [pub.pem]: ").strip() or "pub.pem"
            bits = input("RSA bits [3072]: ").strip() or "3072"
            generate_keys_interactive(priv, pub, int(bits))
        elif choice == "2":
            priv = input("Private key path [priv.pem]: ").strip() or "priv.pem"
            target = input("Target file to sign: ").strip()
            if not target:
                print("No target provided.")
                continue
            sig = input("Signature output filename [<target>.sig]: ").strip() or (target + ".sig")
            sign_file(priv, target, sig)
        elif choice == "3":
            priv = input("Private key path [priv.pem]: ").strip() or "priv.pem"
            pub = input("Public key path [pub.pem]: ").strip() or "pub.pem"
            target = input("Target file (python) to sign+inject: ").strip()
            if not target:
                print("No target provided.")
                continue
            signame = input("Signature filename to create next to target [<target>.sig]: ").strip() or (os.path.basename(target) + ".sig")
            # sign
            if not sign_file(priv, target, os.path.join(os.path.dirname(target) or ".", signame)):
                print("Signing failed.")
                continue
            # inject public key (read pub)
            if not os.path.exists(pub):
                print("Public key not found:", pub)
                resp = input("Create pub from priv? (y/N) ").strip().lower()
                if resp == "y":
                    if not generate_keys_interactive(priv, pub):
                        print("Could not generate public key.")
                        continue
                else:
                    continue
            inject_verifier(pub, target, sig_filename=signame, overwrite=True)
        elif choice == "4":
            target = input("Target file to remove verifier from: ").strip()
            if not target:
                continue
            remove_verifier(target)
        elif choice == "5":
            print("Bye.")
            break
        else:
            print("Invalid choice.")

def parse_cli():
    parser = argparse.ArgumentParser(description="Sign and inject verifier helper")
    parser.add_argument("--remove", nargs=1, metavar="FILE", help="remove injected verifier from FILE")
    parser.add_argument("--sign-inject", nargs=3, metavar=("PRIV","PUB","FILE"), help="sign FILE with PRIV and inject verifier with PUB (non-interactive). Signature saved as FILE.sig")
    parser.add_argument("--generate-keys", nargs=2, metavar=("PRIV","PUB"), help="generate keys non-interactive (requires openssl)")
    return parser.parse_args()

def main():
    args = parse_cli()
    if args.remove:
        target = args.remove[0]
        if not os.path.exists(target):
            print("Target not found:", target); sys.exit(2)
        remove_verifier(target); return
    if args.generate_keys:
        priv, pub = args.generate_keys
        generate_keys_interactive(priv, pub)
        return
    if args.sign_inject:
        priv, pub, target = args.sign_inject
        sig = os.path.join(os.path.dirname(target) or ".", os.path.basename(target) + ".sig")
        if not sign_file(priv, target, sig):
            sys.exit(3)
        inject_verifier(pub, target, sig_filename=os.path.basename(sig), overwrite=True)
        return
    # default interactive
    interactive_main()

if __name__ == "__main__":
    main()
