#!/usr/bin/env python3
import os
import sys
import subprocess

MARKER_START = "# -- BEGIN SIGNATURE VERIFIER --"
MARKER_END   = "# -- END SIGNATURE VERIFIER --"

VERIFIER_TEMPLATE = '''{marker_start}
import sys, subprocess, tempfile, base64, os

def _verify_signature():
    try:
        pub_pem_b64 = """{pubkey_b64}"""
        sig_b64     = """{sig_b64}"""

        pub_pem = base64.b64decode(pub_pem_b64.encode())
        sig     = base64.b64decode(sig_b64.encode())

        # Recrée fichier temporaire contenant clé publique
        pub_path = os.path.join(tempfile.gettempdir(), "pub.pem")
        with open(pub_path, "wb") as f:
            f.write(pub_pem)

        # Recrée signature temporaire
        sig_path = os.path.join(tempfile.gettempdir(), "sig.bin")
        with open(sig_path, "wb") as f:
            f.write(sig)

        # On relit le fichier courant sans le bloc protecteur
        code_lines = []
        inside = False
        with open(__file__, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip() == "{marker_start}":
                    inside = True
                    continue
                if line.strip() == "{marker_end}":
                    inside = False
                    continue
                if not inside:
                    code_lines.append(line)

        code_clean = "".join(code_lines)
        tmp_code_path = os.path.join(tempfile.gettempdir(), "code_clean.py")
        with open(tmp_code_path, "w", encoding="utf-8") as f:
            f.write(code_clean)

        # Vérification via openssl
        result = subprocess.run([
            "openssl", "dgst", "-sha256",
            "-verify", pub_path,
            "-signature", sig_path,
            tmp_code_path
        ], capture_output=True, text=True)

        if "Verified OK" not in result.stdout:
            print("[INTEGRITY ALERT] Signature verification failed! Execution stopped.", file=sys.stderr)
            sys.exit(1)

    except Exception as e:
        print(f"[INTEGRITY ERROR] {e}", file=sys.stderr)
        sys.exit(1)

_verify_signature()
{marker_end}
'''

def run_cmd(cmd):
    """Exécute une commande shell"""
    print("Running:", " ".join(cmd))
    return subprocess.run(cmd, check=True)

def generate_keypair(priv="priv.pem", pub="pub.pem", bits=3072):
    print(f"Generating RSA keypair ({bits} bits)...")
    run_cmd(["openssl", "genpkey", "-algorithm", "RSA", "-out", priv, "-pkeyopt", f"rsa_keygen_bits:{bits}"])
    run_cmd(["openssl", "rsa", "-in", priv, "-pubout", "-out", pub])
    print(f"Keys generated: {priv}, {pub}")

def sign_file(priv, target, sigfile=None):
    if not sigfile:
        sigfile = target + ".sig"
    print(f"Signing {target} -> {sigfile}")
    run_cmd(["openssl", "dgst", "-sha256", "-sign", priv, "-out", sigfile, target])
    return sigfile

def inject_verifier(pubfile, target, sigfile, overwrite=True):
    # lire clé publique
    with open(pubfile, "rb") as f:
        pub_pem = f.read()
    # lire signature
    with open(sigfile, "rb") as f:
        sig = f.read()

    import base64
    pub_b64 = base64.b64encode(pub_pem).decode()
    sig_b64 = base64.b64encode(sig).decode()

    verifier_text = VERIFIER_TEMPLATE.format(
        marker_start=MARKER_START,
        marker_end=MARKER_END,
        pubkey_b64=pub_b64,
        sig_b64=sig_b64
    )

    # Sauvegarde avant injection
    backup = target + ".bak"
    if not os.path.exists(backup):
        os.rename(target, backup)
    else:
        with open(target, "r", encoding="utf-8") as f:
            orig = f.read()
        with open(backup, "w", encoding="utf-8") as f:
            f.write(orig)

    # Lire code sans ancien bloc
    code_lines = []
    inside = False
    with open(backup, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip() == MARKER_START:
                inside = True
                continue
            if line.strip() == MARKER_END:
                inside = False
                continue
            if not inside:
                code_lines.append(line)

    with open(target, "w", encoding="utf-8") as f:
        f.write(verifier_text + "\n")
        f.write("".join(code_lines))

    print(f"[OK] Verifier injected into {target}, backup -> {backup}")

def remove_verifier(target):
    backup = target + ".bak"
    code_lines = []
    inside = False
    with open(target, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip() == MARKER_START:
                inside = True
                continue
            if line.strip() == MARKER_END:
                inside = False
                continue
            if not inside:
                code_lines.append(line)
    with open(target, "w", encoding="utf-8") as f:
        f.write("".join(code_lines))
    print(f"[OK] Verifier removed from {target}. Backup -> {backup}")

def interactive_main():
    while True:
        print("=== sign_and_inject interactive ===\n")
        print(" 1) Generate keypair (openssl priv.pem + pub.pem)")
        print(" 2) Sign a file")
        print(" 3) Sign + inject verifier into file (recommended)")
        print(" 4) Remove verifier from file")
        print(" 5) Exit")
        choice = input("Action (1-5): ").strip()
        if choice == "1":
            priv = input("Private key path [priv.pem]: ") or "priv.pem"
            pub = input("Public key path [pub.pem]: ") or "pub.pem"
            bits = input("RSA bits [3072]: ") or "3072"
            generate_keypair(priv, pub, int(bits))
        elif choice == "2":
            priv = input("Private key path [priv.pem]: ") or "priv.pem"
            target = input("Target file: ").strip()
            sig = input(f"Signature filename [{target}.sig]: ") or target + ".sig"
            sign_file(priv, target, sig)
        elif choice == "3":
            priv = input("Private key path [priv.pem]: ") or "priv.pem"
            pub = input("Public key path [pub.pem]: ") or "pub.pem"
            target = input("Target file (python) to sign+inject: ").strip()
            sig = input(f"Signature filename to create [{target}.sig]: ") or target + ".sig"
            sign_file(priv, target, sig)
            inject_verifier(pub, target, sig, overwrite=True)
        elif choice == "4":
            target = input("Target file: ").strip()
            remove_verifier(target)
        elif choice == "5":
            sys.exit(0)
        else:
            print("Invalid choice.")

def main():
    interactive_main()

if __name__ == "__main__":
    main()
