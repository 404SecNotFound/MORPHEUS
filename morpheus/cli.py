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
        prog="morpheus",
        description="MORPHEUS — quantum-resistant multi-cipher encryption",
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
        "-f", "--file",
        help="Path to file to encrypt or decrypt. "
             "Output goes to FILE.enc (encrypt) or original name (decrypt).",
    )
    parser.add_argument(
        "--output",
        help="Explicit output file path (overrides default naming).",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite output file if it already exists.",
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
    """Read password securely from terminal (never from argv).

    Uses getpass which reads from /dev/tty on Unix, so passwords are entered
    interactively even when stdin is consumed by --data - or piped input.
    Falls back to stdin only when no TTY is available at all (headless CI).
    """
    try:
        pwd = getpass.getpass(prompt)
    except OSError:
        # No TTY available — fall back to reading one line from stdin
        pwd = sys.stdin.readline().rstrip("\n")
        if confirm:
            print(
                "Warning: password confirmation skipped (no terminal available).",
                file=sys.stderr,
            )
        return pwd

    if confirm:
        try:
            pwd2 = getpass.getpass("Confirm password: ")
        except OSError:
            print("Error: cannot confirm password without a terminal.", file=sys.stderr)
            sys.exit(1)
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

    # --- Read data (skip if file mode) ---
    data = ""
    if not args.file:
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
        _ML_KEM_768_PK_SIZE = 1184
        _ML_KEM_768_SK_SIZE = 2400
        if args.pq_public_key:
            try:
                pq_pk = b64.b64decode(args.pq_public_key, validate=True)
            except Exception:
                _print_status(
                    "Error: --pq-public-key is not valid base64. "
                    "Use the output from --generate-keypair.",
                    error=True,
                )
                sys.exit(1)
            if len(pq_pk) != _ML_KEM_768_PK_SIZE:
                _print_status(
                    f"Error: --pq-public-key has wrong size ({len(pq_pk)} bytes, "
                    f"expected {_ML_KEM_768_PK_SIZE} for ML-KEM-768). "
                    "Use the output from --generate-keypair.",
                    error=True,
                )
                sys.exit(1)
        if args.pq_secret_key:
            try:
                pq_sk = b64.b64decode(args.pq_secret_key, validate=True)
            except Exception:
                _print_status(
                    "Error: --pq-secret-key is not valid base64. "
                    "Use the output from --generate-keypair.",
                    error=True,
                )
                sys.exit(1)
            if len(pq_sk) != _ML_KEM_768_SK_SIZE:
                _print_status(
                    f"Error: --pq-secret-key has wrong size ({len(pq_sk)} bytes, "
                    f"expected {_ML_KEM_768_SK_SIZE} for ML-KEM-768). "
                    "Use the output from --generate-keypair.",
                    error=True,
                )
                sys.exit(1)

    pipeline = EncryptionPipeline(
        cipher=cipher_cls(),
        kdf=kdf_cls(),
        chain=args.chain,
        hybrid_pq=args.hybrid_pq,
        pq_public_key=pq_pk,
        pq_secret_key=pq_sk,
    )

    # --- File mode ---
    if args.file:
        _run_file_operation(args, operation, password, pipeline)
        return

    # --- Text mode ---
    try:
        if operation == "encrypt":
            result = pipeline.encrypt(data, password)
            print(f"\nEncrypted ({pipeline.description}):")
            print(result)
        else:
            result = pipeline.decrypt(data, password)
            print("\nDecrypted:")
            print(result)
    except Exception as exc:
        if operation == "decrypt":
            msg = (
                "Decryption failed: incorrect password or corrupted data.\n"
                "  Hint: if the password is correct, the KDF parameters "
                "(time_cost, memory_cost) may not match\n"
                "  those used during encryption. KDF parameters are not "
                "stored in the ciphertext format."
            )
        else:
            msg = f"Encryption error: {exc}"
        _print_status(msg, error=True)
        sys.exit(1)


def _check_overwrite(path: str, force: bool) -> None:
    """Abort if output file exists and --force was not given."""
    import os

    if os.path.exists(path) and not force:
        _print_status(
            f"Error: output file already exists: {path}\n"
            "  Use --force to overwrite, or --output to choose a different path.",
            error=True,
        )
        sys.exit(1)


def _run_file_operation(args, operation: str, password: str, pipeline) -> None:
    """Encrypt or decrypt a file."""
    import base64
    import os

    file_path = args.file
    if not os.path.isfile(file_path):
        _print_status(f"Error: file not found: {file_path}", error=True)
        sys.exit(1)

    file_size = os.path.getsize(file_path)
    max_size = 100 * 1024 * 1024  # 100 MiB
    if file_size > max_size:
        _print_status(
            f"Error: file too large ({file_size / 1024 / 1024:.1f} MiB, max 100 MiB)",
            error=True,
        )
        sys.exit(1)

    if operation == "encrypt":
        # Read file bytes, base64 encode for the pipeline
        with open(file_path, "rb") as f:
            raw_data = f.read()

        # Wrap raw bytes in a versioned transport envelope
        import json

        ENVELOPE_VERSION = 1
        envelope = json.dumps({
            "envelope_version": ENVELOPE_VERSION,
            "filename": os.path.basename(file_path),
            "data": base64.b64encode(raw_data).decode(),
        })

        try:
            encrypted = pipeline.encrypt(envelope, password)
        except Exception as exc:
            _print_status(f"Encryption error: {exc}", error=True)
            sys.exit(1)

        out_path = args.output or (file_path + ".enc")
        _check_overwrite(out_path, args.force)
        with open(out_path, "w") as f:
            f.write(encrypted)

        _print_status(
            f"Encrypted ({pipeline.description}): {file_path} -> {out_path} "
            f"({file_size} bytes -> {len(encrypted)} chars)"
        )

    else:
        with open(file_path, "r") as f:
            encrypted_data = f.read().strip()

        try:
            decrypted = pipeline.decrypt(encrypted_data, password)
        except Exception:
            _print_status(
                "Decryption failed: incorrect password or corrupted file.\n"
                "  Hint: if the password is correct, the KDF parameters "
                "(time_cost, memory_cost) may not match\n"
                "  those used during encryption. KDF parameters are not "
                "stored in the ciphertext format.",
                error=True,
            )
            sys.exit(1)

        # Try to parse as versioned file envelope
        import json

        ENVELOPE_VERSION = 1
        try:
            envelope = json.loads(decrypted)
            env_ver = envelope.get("envelope_version", 0)
            if env_ver > ENVELOPE_VERSION:
                _print_status(
                    f"Error: envelope version {env_ver} is newer than supported "
                    f"(max {ENVELOPE_VERSION}). Update MORPHEUS to decrypt this file.",
                    error=True,
                )
                sys.exit(1)
            if "data" in envelope and "filename" in envelope:
                raw_data = base64.b64decode(envelope["data"])
                # Sanitize filename to prevent path traversal attacks
                # (e.g., "../../.ssh/authorized_keys" -> "authorized_keys")
                original_name = os.path.basename(envelope["filename"])
                if not original_name:
                    original_name = "decrypted_output"
                out_path = args.output or original_name
                _check_overwrite(out_path, args.force)
                with open(out_path, "wb") as f:
                    f.write(raw_data)
                _print_status(
                    f"Decrypted: {file_path} -> {out_path} ({len(raw_data)} bytes)"
                )
                return
        except (json.JSONDecodeError, KeyError):
            pass

        # Fallback: treat as plain text
        out_path = args.output or file_path.removesuffix(".enc")
        _check_overwrite(out_path, args.force)
        with open(out_path, "w") as f:
            f.write(decrypted)
        _print_status(f"Decrypted: {file_path} -> {out_path}")
