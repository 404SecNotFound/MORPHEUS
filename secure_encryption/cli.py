"""
Command-line interface — backward-compatible with v1 and extended for v2.

Supports both interactive prompts and non-interactive flag-based usage.
Passwords are always read interactively (never from argv) unless piped via stdin.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from .core.ciphers import CIPHER_CHOICES
from .core.kdf import KDF_CHOICES
from .core.pipeline import PQ_AVAILABLE, EncryptionPipeline
from .core.validation import check_password_strength, validate_input_text


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secure-encrypt",
        description="SecureDataEncryption v2 — quantum-resistant multi-cipher encryption",
    )
    parser.add_argument(
        "-o", "--operation",
        choices=["encrypt", "decrypt"],
        help="Operation to perform",
    )
    parser.add_argument(
        "-d", "--data",
        help="Plaintext (encrypt) or base64 ciphertext (decrypt). "
             "Omit to enter interactively. Use '-' to read from stdin.",
    )
    parser.add_argument(
        "--cipher",
        choices=list(CIPHER_CHOICES.keys()),
        default="AES-256-GCM",
        help="Symmetric cipher (default: AES-256-GCM)",
    )
    parser.add_argument(
        "--kdf",
        choices=list(KDF_CHOICES.keys()),
        default="Argon2id",
        help="Key derivation function (default: Argon2id)",
    )
    parser.add_argument(
        "--chain",
        action="store_true",
        help="Chain ciphers (AES-256-GCM + ChaCha20-Poly1305) for defense-in-depth",
    )
    parser.add_argument(
        "--hybrid-pq",
        action="store_true",
        help="Enable hybrid post-quantum encryption (ML-KEM-768)",
    )
    parser.add_argument(
        "--pq-public-key",
        help="Base64-encoded ML-KEM-768 public key (for hybrid encrypt)",
    )
    parser.add_argument(
        "--pq-secret-key",
        help="Base64-encoded ML-KEM-768 secret key (for hybrid decrypt)",
    )
    parser.add_argument(
        "--generate-keypair",
        action="store_true",
        help="Generate an ML-KEM-768 keypair and print to stdout",
    )
    # Legacy compat: -p flag accepted but triggers a warning
    parser.add_argument(
        "-p", "--password",
        help=argparse.SUPPRESS,  # Hidden — deprecated, insecure
    )
    return parser


def _read_password(prompt: str = "Enter password: ", confirm: bool = False) -> str:
    """Read password securely from terminal (never from argv)."""
    if not sys.stdin.isatty():
        # Piped input — read one line
        pwd = sys.stdin.readline().rstrip("\n")
    else:
        pwd = getpass.getpass(prompt)

    if confirm and sys.stdin.isatty():
        pwd2 = getpass.getpass("Confirm password: ")
        if pwd != pwd2:
            print("Error: passwords do not match.", file=sys.stderr)
            sys.exit(1)

    return pwd


def _print_status(msg: str, error: bool = False) -> None:
    stream = sys.stderr if error else sys.stdout
    print(msg, file=stream)


def run_cli(argv: list[str] | None = None) -> None:
    """Run the CLI interface."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # --- Generate keypair ---
    if args.generate_keypair:
        if not PQ_AVAILABLE:
            _print_status("Error: pqcrypto not installed. Run: pip install pqcrypto", error=True)
            sys.exit(1)
        from .core.pipeline import pq_generate_keypair
        import base64
        pk, sk = pq_generate_keypair()
        print("ML-KEM-768 Keypair (base64-encoded)")
        print(f"Public key:  {base64.b64encode(pk).decode()}")
        print(f"Secret key:  {base64.b64encode(sk).decode()}")
        print("\nKeys exist only in this terminal output. Copy them now.")
        return

    # --- Determine operation ---
    if args.operation:
        operation = args.operation
    else:
        choice = input("Encrypt or Decrypt? (e/d): ").strip().lower()
        if choice in ("e", "encrypt"):
            operation = "encrypt"
        elif choice in ("d", "decrypt"):
            operation = "decrypt"
        else:
            _print_status("Invalid choice.", error=True)
            sys.exit(1)

    # --- Read data ---
    if args.data == "-":
        data = sys.stdin.read()
    elif args.data:
        data = args.data
    else:
        if operation == "encrypt":
            print("Enter text to encrypt (Ctrl+D or Ctrl+Z when done):")
            lines = []
            try:
                while True:
                    lines.append(input())
            except EOFError:
                pass
            data = "\n".join(lines)
        else:
            data = input("Enter encrypted data: ").strip()

    # --- Validate ---
    if operation == "encrypt":
        valid, err = validate_input_text(data)
        if not valid:
            _print_status(f"Error: {err}", error=True)
            sys.exit(1)

    # --- Password ---
    if args.password:
        print(
            "WARNING: Passing passwords via --password/-p is insecure "
            "(visible in ps, shell history). Use interactive input instead.",
            file=sys.stderr,
        )
        password = args.password
    else:
        password = _read_password(confirm=(operation == "encrypt"))

    if not password:
        _print_status("Error: password cannot be empty", error=True)
        sys.exit(1)

    if operation == "encrypt":
        strength = check_password_strength(password)
        if not strength.is_acceptable:
            _print_status(
                f"Error: password too weak ({strength.label}). "
                + "; ".join(strength.feedback),
                error=True,
            )
            sys.exit(1)

    # --- Build pipeline ---
    cipher_cls = CIPHER_CHOICES[args.cipher]
    kdf_cls = KDF_CHOICES[args.kdf]

    pq_pk = None
    pq_sk = None
    if args.hybrid_pq:
        if not PQ_AVAILABLE:
            _print_status("Error: pqcrypto not installed. Run: pip install pqcrypto", error=True)
            sys.exit(1)
        import base64 as b64
        if args.pq_public_key:
            pq_pk = b64.b64decode(args.pq_public_key)
        if args.pq_secret_key:
            pq_sk = b64.b64decode(args.pq_secret_key)

    pipeline = EncryptionPipeline(
        cipher=cipher_cls(),
        kdf=kdf_cls(),
        chain=args.chain,
        hybrid_pq=args.hybrid_pq,
        pq_public_key=pq_pk,
        pq_secret_key=pq_sk,
    )

    # --- Execute ---
    try:
        if operation == "encrypt":
            result = pipeline.encrypt(data, password)
            print(f"\nEncrypted ({pipeline.description}):")
            print(result)
        else:
            result = pipeline.decrypt(data, password)
            print(f"\nDecrypted:")
            print(result)
    except Exception as exc:
        _print_status(
            "Decryption failed: incorrect password or corrupted data"
            if operation == "decrypt"
            else f"Encryption error: {exc}",
            error=True,
        )
        sys.exit(1)
