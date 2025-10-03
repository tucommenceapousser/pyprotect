#!/usr/bin/env python3
"""
protectme.py - interactive sign & inject (robust template replacement)

Features:
 - generate RSA keypair (openssl)
 - sign a file (openssl dgst -sha256 -sign)
 - inject a verifier at top of a Python file that checks signature at runtime
 - remove injected verifier
This version avoids str.format() on templates and uses safe token replacement.
"""
from __future__ import annotations
import os, sys, subprocess, shutil, tempfile, base64, re

# markers (plain text)
MARKER_START = "# -- BEGIN SIGNATURE VERIFIER v1 --"
MARKER_END   = "# -- END SIGNATURE VERIFIER v1 --"

# Template uses unique tokens to avoid accidental { } interpretation.
VERIFIER_TEMPLATE = r"""
@@MARKER_START@@
# Auto-injected signature verifier (v1)
# This verifier checks that the signature file @@SIG_FILENAME@@ matches this file's content
import os, sys, tempfile, subprocess, base64, shutil

_pub_pem_b64 = r'''@@PUB_B64@@'''
_sig_b64     = r'''@@SIG_B64@@'''
_sig_filename = "@@SIG_FILENAME@@"

def _norm_bytes(b):
    # remove BOM, unify newlines, strip trailing spaces
    if b.startswith(b'\xef\xbb\xbf'):
        b = b[3:]
    b = b.replace(b'\r\n', b'\n').replace(b'\r', b'\n')
    lines = b.split(b'\n')
    lines = [ln.rstrip() for ln in lines]
    return b'\n'.join(lines)

def _verify_with_openssl(pub_pem_bytes, sig_bytes, tmp_code_path):
    # write pub and sig to temp files and call openssl
    try:
        pubf = tempfile.NamedTemporaryFile(delete=False)
        pubf.write(pub_pem_bytes); pubf.flush(); pubf.close()
        sigf = tempfile.NamedTemporaryFile(delete=False)
        sigf.write(sig_bytes); sigf.flush(); sigf.close()
        cmd = ["openssl", "dgst", "-sha256", "-verify", pubf.name, "-signature", sigf.name, tmp_code_path]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        # cleanup
        try:
            os.unlink(pubf.name)
            os.unlink(sigf.name)
        except Exception:
            pass
        return ("Verified OK" in (proc.stdout or "")) or (proc.returncode == 0 and "Verified OK" in (proc.stdout or ""))
    except Exception:
        return False

def _run_check():
    # determine signature path (relative to file if not absolute)
    sig_path = _sig_filename if os.path.isabs(_sig_filename) else os.path.join(os.path.dirname(__file__), _sig_filename)
    if not os.path.exists(sig_path):
        sys.stderr.write("\\n[INTEGRITY ALERT] signature file not found: {}\\n".format(sig_path))
        sys.exit(1)

    # read this file
    try:
        with open(__file__, "rb") as f:
            raw = f.read()
    except Exception as e:
        sys.stderr.write("\\n[INTEGRITY ALERT] cannot read file: {}\\n".format(e))
        sys.exit(1)

    # remove injected block before verification
    start_marker = b"@@MARKER_START_BYTES@@"
    end_marker = b"@@MARKER_END_BYTES@@"
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

    # load signature
    try:
        with open(sig_path, "rb") as f:
            sig_bytes = f.read()
    except Exception:
        sys.stderr.write("\\n[INTEGRITY ALERT] cannot read signature file\\n")
        sys.exit(1)

    pub_pem_bytes = base64.b64decode(_pub_pem_b64.encode("utf-8"))
    # prefer openssl verification (available on most systems)
    ok = False
    if shutil.which("openssl"):
        # write normalized data to temp file for openssl check
        tmp = tempfile.NamedTemporaryFile(delete=False)
        try:
            tmp.write(data); tmp.flush(); tmp.close()
            ok = _verify_with_openssl(pub_pem_bytes, sig_bytes, tmp.name)
        finally:
            try:
                os.unlink(tmp.name)
            except Exception:
                pass

    if not ok:
        sys.stderr.write("\\n[INTEGRITY ALERT] signature verification failed\\n")
        sys.exit(1)
    # else: verification passed -> continue execution

_run_check()
@@MARKER_END@@
"""

# Helpers
def run_cmd(cmd, check=True):
    try:
        print("Running:", " ".join(cmd))
        subprocess.run(cmd, check=check)
        return True
    except subprocess.CalledProcessError as e:
        print("Command failed:", e)
        return False

def generate_keypair(priv="priv.pem", pub="pub.pem", bits=3072):
    if os.path.exists(priv) or os.path.exists(pub):
        if input("One of the key files exists. Overwrite? (y/N) ").strip().lower() != "y":
            print("Aborted.")
            return False
    cmd_gen = ["openssl", "genpkey", "-algorithm", "RSA", "-out", priv, "-pkeyopt", f"rsa_keygen_bits:{bits}"]
    if not run_cmd(cmd_gen, check=False):
        print("OpenSSL genpkey failed or not installed.")
        return False
    cmd_pub = ["openssl", "rsa", "-in", priv, "-pubout", "-out", pub]
    if not run_cmd(cmd_pub, check=False):
        print("OpenSSL rsa -pubout failed.")
        return False
    print("Keys generated:", priv, pub)
    return True

def sign_file(priv, target, sigfile=None):
    if sigfile is None:
        sigfile = target + ".sig"
    if not os.path.exists(priv):
        print("Private key not found:", priv); return False
    cmd = ["openssl", "dgst", "-sha256", "-sign", priv, "-out", sigfile, target]
    if not run_cmd(cmd, check=False):
        print("Signing failed.")
        return False
    print("Signature written to:", sigfile)
    return True

def inject_verifier(pubfile, target, sig_filename=None, overwrite=False):
    if not os.path.exists(pubfile):
        print("Public key not found:", pubfile); return False
    if sig_filename is None:
        sig_filename = os.path.basename(target) + ".sig"

    # read public key and signature
    with open(pubfile, "rb") as f:
        pub_pem = f.read()
    sig_bytes = b""
    sig_path = sig_filename if os.path.isabs(sig_filename) else os.path.join(os.path.dirname(target), sig_filename)
    if os.path.exists(sig_path):
        with open(sig_path, "rb") as f:
            sig_bytes = f.read()
    else:
        print("Warning: signature file not found at", sig_path, "; injection will still embed pub key and filename.")

    pub_b64 = base64.b64encode(pub_pem).decode("utf-8")
    sig_b64 = base64.b64encode(sig_bytes).decode("utf-8")

    # prepare verifier by replacing tokens
    verifier = VERIFIER_TEMPLATE
    verifier = verifier.replace("@@MARKER_START@@", MARKER_START)
    verifier = verifier.replace("@@MARKER_END@@", MARKER_END)
    verifier = verifier.replace("@@PUB_B64@@", pub_b64)
    verifier = verifier.replace("@@SIG_B64@@", sig_b64)
    verifier = verifier.replace("@@SIG_FILENAME@@", sig_filename)
    # bytes markers for runtime removal
    verifier = verifier.replace("@@MARKER_START_BYTES@@", MARKER_START.encode("utf-8").decode("latin-1"))
    verifier = verifier.replace("@@MARKER_END_BYTES@@", MARKER_END.encode("utf-8").decode("latin-1"))

    # read original file
    with open(target, "rb") as f:
        orig = f.read()

    if orig.find(MARKER_START.encode("utf-8")) != -1 and not overwrite:
        print("Verifier already present. Use overwrite=True to force.")
        return False

    # build new content: insert after shebang and encoding line if present
    try:
        s = orig.decode("utf-8", errors="surrogateescape")
        lines = s.splitlines(True)
        insert_at = 0
        if lines and lines[0].startswith("#!"):
            insert_at = 1
        if insert_at < len(lines) and re.match(r"\s*#.*coding[:=]\s*[-\w.]+", lines[insert_at]):
            insert_at += 1
        prefix = "".join(lines[:insert_at]).encode("utf-8")
        suffix = "".join(lines[insert_at:]).encode("utf-8")
        new = prefix + verifier.encode("utf-8") + suffix
    except Exception:
        new = verifier.encode("utf-8") + orig

    # backup and write
    backup = target + ".bak"
    with open(backup, "wb") as f:
        f.write(orig)
    with open(target, "wb") as f:
        f.write(new)
    print("Verifier injected into", target, "backup:", backup)
    return True

def remove_verifier(target):
    if not os.path.exists(target):
        print("Target missing:", target); return False
    with open(target, "rb") as f:
        orig = f.read()
    start = MARKER_START.encode("utf-8")
    end = MARKER_END.encode("utf-8")
    si = orig.find(start)
    if si == -1:
        print("No verifier block found."); return False
    ei = orig.find(end, si)
    if ei == -1:
        print("End marker not found; aborting."); return False
    new = orig[:si] + orig[ei + len(end):]
    bak = target + ".bak_remove"
    with open(bak, "wb") as f:
        f.write(orig)
    with open(target, "wb") as f:
        f.write(new)
    print("Verifier removed. Backup:", bak)
    return True

def interactive_main():
    print("=== sign_and_inject interactive ===")
    while True:
        print("\nChoose action:")
        print(" 1) Generate keypair (openssl priv.pem + pub.pem)")
        print(" 2) Sign a file")
        print(" 3) Sign + inject verifier into file (recommended)")
        print(" 4) Remove verifier from file")
        print(" 5) Exit")
        choice = input("Action (1-5): ").strip()
        if choice == "1":
            priv = input("Private key path [priv.pem]: ").strip() or "priv.pem"
            pub = input("Public key path [pub.pem]: ").strip() or "pub.pem"
            bits = int(input("RSA bits [3072]: ").strip() or "3072")
            generate_keypair(priv, pub, bits)
        elif choice == "2":
            priv = input("Private key path [priv.pem]: ").strip() or "priv.pem"
            target = input("Target file to sign: ").strip()
            if not target:
                print("No target provided."); continue
            sig = input("Signature filename [<target>.sig]: ").strip() or (target + ".sig")
            sign_file(priv, target, sig)
        elif choice == "3":
            priv = input("Private key path [priv.pem]: ").strip() or "priv.pem"
            pub = input("Public key path [pub.pem]: ").strip() or "pub.pem"
            target = input("Target file (python) to sign+inject: ").strip()
            if not target:
                print("No target provided."); continue
            signame = input("Signature filename to create next to target [<target>.sig]: ").strip() or (os.path.basename(target) + ".sig")
            # sign
            if not sign_file(priv, target, os.path.join(os.path.dirname(target) or ".", signame)):
                print("Signing failed."); continue
            # inject
            inject_verifier(pub, target, sig_filename=signame, overwrite=True)
        elif choice == "4":
            target = input("Target file to remove verifier from: ").strip()
            if not target:
                print("No target provided."); continue
            remove_verifier(target)
        elif choice == "5":
            print("Bye."); break
        else:
            print("Invalid choice.")

def parse_cli():
    import argparse
    p = argparse.ArgumentParser(description="Sign & inject helper")
    p.add_argument("--remove", nargs=1, metavar="FILE", help="remove verifier from FILE")
    p.add_argument("--sign-inject", nargs=3, metavar=("PRIV","PUB","FILE"), help="sign FILE with PRIV and inject with PUB (non-interactive)")
    p.add_argument("--generate-keys", nargs=2, metavar=("PRIV","PUB"), help="generate keys non-interactive")
    return p.parse_args()

def main():
    args = parse_cli()
    if args.remove:
        remove_verifier(args.remove[0]); return
    if args.generate_keys:
        priv,pub = args.generate_keys; generate_keypair(priv,pub)
        return
    if args.sign_inject:
        priv,pub,target = args.sign_inject
        sig = os.path.join(os.path.dirname(target) or ".", os.path.basename(target) + ".sig")
        if not sign_file(priv, target, sig):
            sys.exit(3)
        inject_verifier(pub, target, sig_filename=os.path.basename(sig), overwrite=True)
        return
    interactive_main()

if __name__ == "__main__":
    main()
