"""
Command-line interface — backward-compatible with v1 and extended for v2.

Supports both interactive prompts and non-interactive flag-based usage.
Passwords are always read interactively (never from argv) unless piped via stdin.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from .core.ciphers import CIPHER_CHOICES, CIPHER_REGISTRY
from .core.formats import (
    FORMAT_VERSION_3, FLAG_CHAINED, FLAG_HYBRID_PQ, FLAG_PADDED,
    deserialize,
)
from .core.kdf import KDF_CHOICES, KDF_REGISTRY
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
    parser.add_argument(
        "--no-strength-check",
        action="store_true",
        help="Skip password strength validation (use with caution).",
    )
    parser.add_argument(
        "--pad",
        action="store_true",
        help="Pad plaintext to hide exact length (privacy protection).",
    )
    parser.add_argument(
        "--fixed-size",
        action="store_true",
        help="Pad all ciphertexts to 64 KiB (constant-size mode, max privacy). "
             "Implies --pad. Input must be < 64 KiB.",
    )
    parser.add_argument(
        "--no-filename",
        action="store_true",
        help="Omit original filename from encrypted envelope (privacy).",
    )
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Benchmark KDF and cipher performance on this hardware, "
             "then print recommended configuration.",
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


def _diagnose_ciphertext(b64_data: str) -> str:
    """Parse a ciphertext header and return a human-readable diagnosis.

    Returns an empty string if the header cannot be parsed.
    """
    try:
        version, cipher_id, kdf_id, flags, _, kdf_params = deserialize(b64_data)
    except Exception:
        return ""

    # Version
    ver_str = "v3 (self-describing)" if version == FORMAT_VERSION_3 else "v2 (legacy)"

    # Cipher
    if flags & FLAG_CHAINED:
        cipher_str = "AES-256-GCM + ChaCha20-Poly1305 (chained)"
    else:
        cipher_cls = CIPHER_REGISTRY.get(cipher_id)
        cipher_str = cipher_cls.name if cipher_cls else f"unknown ({cipher_id:#04x})"

    # KDF
    kdf_cls = KDF_REGISTRY.get(kdf_id)
    kdf_str = kdf_cls.name if kdf_cls else f"unknown ({kdf_id:#04x})"

    # KDF params
    params_str = ""
    if kdf_params and version == FORMAT_VERSION_3:
        if kdf_id == 0x02:  # Argon2id
            params_str = f" (t={kdf_params[0]}, m={kdf_params[1]} KiB, p={kdf_params[2]})"
        elif kdf_id == 0x01:  # Scrypt
            params_str = f" (n={kdf_params[0]}, r={kdf_params[1]}, p={kdf_params[2]})"

    # Flags
    flag_parts = []
    if flags & FLAG_HYBRID_PQ:
        flag_parts.append("hybrid PQ")
    if flags & FLAG_PADDED:
        flag_parts.append("padded")
    flags_str = f"  Flags:   {', '.join(flag_parts)}\n" if flag_parts else ""

    return (
        f"  Format:  {ver_str}\n"
        f"  Cipher:  {cipher_str}\n"
        f"  KDF:     {kdf_str}{params_str}\n"
        f"{flags_str}"
    )


def _run_benchmark() -> None:
    """Benchmark KDF and cipher performance, print recommendations."""
    import os
    import time

    from .core.ciphers import AES256GCM, ChaCha20Poly1305Cipher
    from .core.kdf import Argon2idKDF, ScryptKDF

    print("MORPHEUS Hardware Benchmark")
    print("=" * 50)

    # --- Cipher benchmark ---
    print("\nCipher performance (1 MiB payload, 3 runs):")
    sample = os.urandom(1024 * 1024)  # 1 MiB
    key = os.urandom(32)
    aad = b"benchmark"

    for cipher_cls in (AES256GCM, ChaCha20Poly1305Cipher):
        c = cipher_cls()
        times = []
        for _ in range(3):
            t0 = time.perf_counter()
            nonce, ct = c.encrypt(key, sample, aad)
            c.decrypt(key, nonce, ct, aad)
            times.append(time.perf_counter() - t0)
        avg = sum(times) / len(times)
        throughput = (2 * len(sample)) / avg / (1024 * 1024)  # encrypt + decrypt
        print(f"  {c.name:<24s}  {avg*1000:6.1f} ms  ({throughput:.0f} MiB/s)")

    # Recommend cipher
    aes = AES256GCM()
    chacha = ChaCha20Poly1305Cipher()
    t_aes = min(_bench_cipher(aes, sample, key, aad) for _ in range(3))
    t_chacha = min(_bench_cipher(chacha, sample, key, aad) for _ in range(3))
    if t_aes <= t_chacha:
        ratio = t_chacha / t_aes if t_aes > 0 else 1
        print(f"\n  -> Recommended: AES-256-GCM ({ratio:.1f}x faster, AES-NI likely available)")
    else:
        ratio = t_aes / t_chacha if t_chacha > 0 else 1
        print(f"\n  -> Recommended: ChaCha20-Poly1305 ({ratio:.1f}x faster on this hardware)")

    # --- KDF benchmark ---
    print("\nKDF performance (single derivation):")
    test_password = bytearray(b"benchmark-password")

    kdf_configs = [
        ("Argon2id (default: t=3, m=64M)", Argon2idKDF(time_cost=3, memory_cost=65536, parallelism=4)),
        ("Argon2id (light:   t=1, m=64M)", Argon2idKDF(time_cost=1, memory_cost=65536, parallelism=4)),
        ("Argon2id (strong:  t=5, m=64M)", Argon2idKDF(time_cost=5, memory_cost=65536, parallelism=4)),
        ("Scrypt   (default: n=2^17)",     ScryptKDF(n=2**17, r=8, p=1)),
    ]

    results = []
    for label, kdf in kdf_configs:
        salt = kdf.generate_salt()
        t0 = time.perf_counter()
        kdf.derive(test_password, salt)
        elapsed = time.perf_counter() - t0
        results.append((label, elapsed))
        print(f"  {label:<38s}  {elapsed*1000:7.0f} ms")

    # Recommend KDF config
    default_time = results[0][1]
    print(f"\n  -> Default Argon2id takes {default_time*1000:.0f} ms on this system.")
    if default_time < 0.5:
        print("     Consider increasing time_cost for stronger protection.")
    elif default_time > 3.0:
        print("     Consider reducing time_cost for better responsiveness.")
    else:
        print("     Current defaults are well-suited for this hardware.")

    print(f"\n{'=' * 50}")
    print("Benchmark complete.")


def _bench_cipher(cipher, data, key, aad):
    """Time one encrypt+decrypt cycle."""
    import time
    t0 = time.perf_counter()
    nonce, ct = cipher.encrypt(key, data, aad)
    cipher.decrypt(key, nonce, ct, aad)
    return time.perf_counter() - t0


def run_cli(argv: list[str] | None = None) -> None:
    """Run the CLI interface."""
    parser = _build_parser()
    args = parser.parse_args(argv)

    # --- Benchmark ---
    if args.benchmark:
        _run_benchmark()
        return

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
        if not getattr(args, "no_strength_check", False):
            strength = check_password_strength(password)
            if not strength.is_acceptable:
                _print_status(
                    f"Error: password too weak ({strength.label}). "
                    + "; ".join(strength.feedback),
                    error=True,
                )
                sys.exit(1)
        else:
            _print_status(
                "Warning: password strength check skipped (--no-strength-check).",
                error=True,
            )
        # Irrecoverability warning
        _print_status(
            "WARNING: There is no password recovery. If you forget your "
            "password, your data is permanently and irrecoverably lost.",
            error=True,
        )

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
            result = pipeline.encrypt(data, password, pad=args.pad,
                                      fixed_size=args.fixed_size)
            print(f"\nEncrypted ({pipeline.description}):")
            print(result)
        else:
            result = pipeline.decrypt(data, password)
            print("\nDecrypted:")
            print(result)
    except Exception as exc:
        if operation == "decrypt":
            diag = _diagnose_ciphertext(data)
            msg = f"Decryption failed: {exc}\n"
            if diag:
                msg += f"\nCiphertext details:\n{diag}"
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
        envelope_dict = {
            "envelope_version": ENVELOPE_VERSION,
            "data": base64.b64encode(raw_data).decode(),
        }
        if not getattr(args, "no_filename", False):
            envelope_dict["filename"] = os.path.basename(file_path)
        envelope = json.dumps(envelope_dict)

        try:
            encrypted = pipeline.encrypt(envelope, password, pad=args.pad,
                                        fixed_size=args.fixed_size)
        except Exception as exc:
            _print_status(f"Encryption error: {exc}", error=True)
            sys.exit(1)

        if args.output:
            out_path = args.output
        else:
            # Randomized output name to avoid leaking original filename on disk
            import hashlib
            import time
            rand_id = hashlib.sha256(
                f"{file_path}{time.time_ns()}".encode()
            ).hexdigest()[:12]
            out_path = f"morpheus_{rand_id}.enc"
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
        except Exception as exc:
            diag = _diagnose_ciphertext(encrypted_data)
            msg = f"Decryption failed: {exc}\n"
            if diag:
                msg += f"\nCiphertext details:\n{diag}"
            _print_status(msg, error=True)
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
