"""
Command-line interface — backward-compatible with v1 and extended for v2.

Supports both interactive prompts and non-interactive flag-based usage.

Passwords are normally read interactively, or piped via stdin. A hidden,
deprecated `-p/--password` flag also accepts one from argv; it warns at
runtime because argv is readable by other local users through `ps` and shell
history. Prefer stdin. The same reasoning applies to `--pq-secret-key`, whose
`--pq-secret-key-file` form should be used instead.

stdout carries the payload only. Every banner, prompt and status line goes to
stderr, so `morpheus -o encrypt | morpheus -o decrypt --data -` works.
"""

from __future__ import annotations

import argparse
import contextlib
import getpass
import sys

from . import __version__
from .core.ciphers import CIPHER_CHOICES, CIPHER_REGISTRY
from .core.config import config_path, load_config, save_config
from .core.envelope import decode as envelope_decode
from .core.envelope import encode as envelope_encode
from .core.errors import (
    ConfigurationError,
    DecryptionError,
    FormatError,
    WrongPasswordError,
)
from .core.fileio import atomic_secure_output
from .core.formats import (
    COMMITMENT_SIZE,
    FLAG_CHAINED,
    FLAG_HYBRID_PQ,
    FLAG_PADDED,
    FORMAT_VERSION_3,
    FORMAT_VERSION_4,
    HEADER_SIZE,
    HEADER_SIZE_V3,
    KEY_CHECK_SIZE,
    deserialize,
)
from .core.kdf import KDF_CHOICES, KDF_REGISTRY
from .core.pipeline import _PAD_BUCKETS, PQ_AVAILABLE, EncryptionPipeline
from .core.validation import (
    check_passphrase_strength,
    check_password_leaked,
    check_password_strength,
    validate_input_text,
)

# Shown under the flag list. A bare flag reference tells a reader what exists
# but not what a working command looks like, and the post-quantum route in
# particular is three commands that have to be run in order with the right key
# on each — the one part of this tool nobody guesses correctly from `--help`.
_EPILOG = """\
examples:
  Run with no arguments to launch the wizard.

  Encrypt and decrypt some text
    morpheus -o encrypt --data "sensitive text"
    morpheus -o decrypt --data "BAECAA..."

  Encrypt a file, then restore it
    morpheus -o encrypt -f report.pdf     # -> morpheus_<random>.enc
    morpheus -o decrypt -f morpheus_ab12cd34ef56.enc   # -> report.pdf

  The encrypted name is deliberately random: a file called report.pdf.enc
  would announce what it holds. The real name travels inside the ciphertext
  and comes back on decrypt. Use --output to pick a name yourself.

  Hybrid post-quantum: a second factor on top of the password
    morpheus --generate-keypair --output my.key    # writes my.key + my.key.pub
    morpheus -o encrypt --data "secret" --hybrid-pq --pq-public-key-file my.key.pub
    morpheus -o decrypt --data "BAECAg..." --hybrid-pq --pq-secret-key-file my.key

  Both commands also prompt for a password, and it must be the SAME password.
  --hybrid-pq combines the password key with the ML-KEM shared secret, so the
  secret key alone does not decrypt: the sender and recipient still have to
  share the password over some other channel. This is two-factor, not
  recipient-only encryption. Your data is quantum-resistant without it — see
  the README on what ML-KEM does and does not add.

  Inspect a ciphertext without a password
    morpheus --inspect --data "BAECAA..."

  Stronger settings
    morpheus -o encrypt --data "secret" --chain --kdf Scrypt --pad

Hybrid post-quantum needs the optional pqcrypto package: pip install pqcrypto
Full guide: docs/USAGE.md      Security policy: SECURITY.md
"""


def _format_label(version: int) -> str:
    """Human-readable format version, in one place.

    Three separate sites each spelled this out as a v3-or-else-v2 ternary, so
    adding v4 silently relabelled every v4 ciphertext as "v2 (legacy)" in both
    --inspect and the error diagnostics.
    """
    if version == FORMAT_VERSION_4:
        return "v4 (committing)"
    if version == FORMAT_VERSION_3:
        return "v3 (self-describing)"
    return "v2 (legacy)"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="morpheus",
        description="MORPHEUS — quantum-resistant multi-cipher encryption",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
        help="Show the version and exit.",
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
             "Encrypting writes morpheus_<random>.enc, so the original "
             "filename is not exposed on disk; decrypting restores the real "
             "name from inside the ciphertext. Use --output to choose a path.",
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
        help="Base64-encoded ML-KEM-768 public key (for hybrid encrypt). "
             "It is ~1,580 characters, so prefer --pq-public-key-file.",
    )
    parser.add_argument(
        "--pq-public-key-file",
        help="Path to a file holding the base64 ML-KEM-768 public key. "
             "--generate-keypair writes one as <secret-key-path>.pub.",
    )
    parser.add_argument(
        "--pq-secret-key",
        help="Base64-encoded ML-KEM-768 secret key (for hybrid decrypt). "
             "Discouraged: argv is visible to other local users. Prefer "
             "--pq-secret-key-file.",
    )
    parser.add_argument(
        "--pq-secret-key-file",
        help="Path to a file holding the base64 ML-KEM-768 secret key. "
             "Preferred over --pq-secret-key, which exposes the key in argv.",
    )
    parser.add_argument(
        "--generate-keypair",
        action="store_true",
        help="Generate an ML-KEM-768 keypair. The public key goes to stdout; "
             "the secret key is written to a 0600 file (see --output)",
    )
    # Legacy compat: -p flag accepted but triggers a warning
    parser.add_argument(
        "-p", "--password",
        help=argparse.SUPPRESS,  # Hidden — deprecated, insecure
    )
    parser.add_argument(
        "--check-network",
        action="store_true",
        help="Report which network interfaces currently have a live link, for "
             "setting up on an air-gapped machine. Reads kernel link state "
             "only: it sends no packets and opens no sockets. Exits 1 if any "
             "interface could carry traffic, so a setup script can gate on it. "
             "Linux only; it cannot prove a machine is air-gapped.",
    )
    parser.add_argument(
        "--allow-expensive-kdf",
        action="store_true",
        help="Permit decrypting a ciphertext whose header asks for unusually "
             "expensive KDF settings. Off by default: the header is not "
             "authenticated until after the work is done, so a hostile file "
             "can otherwise spend minutes of CPU and hundreds of MiB.",
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
    parser.add_argument(
        "--passphrase",
        action="store_true",
        help="Use passphrase-mode strength check (word-based, no digit/"
             "special requirement). Requires 4+ words and 20+ characters.",
    )
    parser.add_argument(
        "--check-leaks",
        action="store_true",
        dest="check_leaks",
        help="Check password against Have I Been Pwned breach database "
             "(k-anonymity — only 5 chars of SHA-1 hash are sent). "
             "Requires network access.",
    )
    parser.add_argument(
        "--save-config",
        action="store_true",
        dest="save_config",
        help="Save current cipher/KDF/flag preferences to "
             "~/.morpheus/config.toml for future sessions.",
    )
    parser.add_argument(
        "--inspect",
        action="store_true",
        help="Inspect a ciphertext header without decrypting. "
             "Shows format version, cipher, KDF, flags, and size info. "
             "No password required. Use with --data or --file.",
    )
    parser.add_argument(
        "--dice-entropy",
        type=int,
        metavar="ROLLS",
        help="Report how much entropy a given number of fair dice rolls "
             "carries, and how many more are needed to reach 128 or 256 bits. "
             "Takes a count only: never type the rolls themselves into a "
             "computer. Generates nothing and stores nothing.",
    )
    parser.add_argument(
        "--dice-sides",
        type=int,
        default=6,
        metavar="N",
        help="Faces on the die used with --dice-entropy (default: 6). "
             "Use 2 for coin flips, 20 for a d20.",
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
    """Write a human-readable status line.

    Always stderr, never stdout. stdout carries the payload and nothing else,
    so that `morpheus -o encrypt | morpheus -o decrypt --data -` works. The
    *error* parameter is kept because callers distinguish the two, but it no
    longer selects the stream.
    """
    print(msg, file=sys.stderr)


def _diagnose_ciphertext(b64_data: str) -> str:
    """Parse a ciphertext header and return a human-readable diagnosis.

    Returns an empty string if the header cannot be parsed.
    """
    try:
        version, cipher_id, kdf_id, flags, _, kdf_params = deserialize(b64_data)
    except Exception:
        return ""

    # Version
    ver_str = _format_label(version)

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
    if kdf_params and version in (FORMAT_VERSION_3, FORMAT_VERSION_4):
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


def _progress(msg: str) -> None:
    """Print a progress/status message to stderr (doesn't mix with output)."""
    print(msg, file=sys.stderr, flush=True)


def _suggest_fix(exc: Exception, ciphertext: str = "") -> str:
    """Return actionable suggestions based on the exception type."""
    suggestions: list[str] = []

    if isinstance(exc, WrongPasswordError):
        suggestions.append("Double-check your password (Caps Lock? Typo?)")
        suggestions.append("If this was encrypted with --passphrase, the same password still works for decryption")
    elif isinstance(exc, FormatError):
        suggestions.append("This doesn't look like MORPHEUS ciphertext")
        suggestions.append("Check that the input is complete and unmodified base64")
        suggestions.append("Was this encrypted with a different tool?")
    elif isinstance(exc, ConfigurationError):
        exc_msg = str(exc).lower()
        if "pq" in exc_msg or "secret key" in exc_msg:
            suggestions.append("This ciphertext requires --hybrid-pq and --pq-secret-key to decrypt")
            suggestions.append("Use the secret key from the keypair used during encryption")
    elif isinstance(exc, DecryptionError):
        exc_msg = str(exc).lower()
        if "truncated" in exc_msg:
            suggestions.append("The ciphertext appears incomplete — was it fully copied?")
            suggestions.append("Check for line-break corruption in the base64 string")
        elif "unknown cipher" in exc_msg or "unknown kdf" in exc_msg:
            suggestions.append("This ciphertext uses a cipher/KDF not supported by this version")
            suggestions.append("Update MORPHEUS to the latest version")
        else:
            suggestions.append("Check your password and try again")
    else:
        # cryptography.exceptions.InvalidTag or other
        exc_cls = type(exc).__name__.lower()
        exc_msg = str(exc).lower()
        if "tag" in exc_msg or "tag" in exc_cls:
            suggestions.append("Wrong password, or the ciphertext has been tampered with")
            suggestions.append("If you're sure the password is correct, the data may be corrupted")
        else:
            suggestions.append("An unexpected error occurred during decryption")

    if not suggestions:
        return ""
    return "\n  Suggestions:\n" + "\n".join(f"    - {s}" for s in suggestions)


# Size ceilings, deliberately different in each direction.
#
# One shared 100 MiB limit was applied to plaintext going in and to base64
# ciphertext coming back, which are not the same size. A file is base64-encoded
# into a JSON envelope, encrypted, and the whole thing base64-encoded again, so
# the output runs about 1.78x the input. A 60 MiB file encrypted cleanly and
# the resulting .enc was then refused before decryption started: the tool
# rejecting its own output, with the only copy of the data inside it.
#
# The decrypt ceiling therefore has to clear the largest output the encrypt
# path can produce, with room for the envelope, padding and header overhead.
# `TestFileSizeLimitsAreNotSymmetric` measures the real expansion through the
# real code path and fails if these two drift back together.
_MAX_PLAINTEXT_BYTES = 100 * 1024 * 1024   # 100 MiB in
_MAX_CIPHERTEXT_BYTES = 200 * 1024 * 1024  # 200 MiB back, ~1.78x plus overhead


def _run_check_network() -> None:
    """Report link state so someone can see what is still connected.

    Exits 1 when any interface could carry traffic and 0 when none can, so a
    setup script can refuse to continue. The exit code is a gate, not a
    verdict: 0 means nothing was observed carrying traffic at this instant, and
    that is a much smaller claim than "air-gapped". `describe` spells out the
    difference, and 2 is reserved for platforms where nothing can be read at
    all so a script does not mistake silence for a clean result.
    """
    from .core.netcheck import describe, inspect

    status = inspect()
    print(describe(status))
    if not status.supported:
        sys.exit(2)
    sys.exit(1 if status.live else 0)


def _run_dice_entropy(rolls: int, sides: int) -> None:
    """Report the entropy of a dice session, and what is still owed.

    Takes a *count*, never the rolls. The sequence itself is key material, and
    a tool that accepted it would be asking the user to type their seed into a
    networked general-purpose computer -- the precise thing every dice procedure
    exists to avoid. Nothing here is generated, derived or stored.
    """
    from .core.entropy import FLOOR_BITS, TARGET_BITS, assess_dice

    try:
        a = assess_dice(rolls, sides)
    except ConfigurationError as exc:
        _print_status(f"Error: {exc}", error=True)
        sys.exit(1)

    print("MORPHEUS Dice Entropy")
    print("=" * 44)
    print(f"  Rolls:      {a.rolls} x d{a.sides}")
    print(f"  Per roll:   {a.bits_per_roll:.3f} bits")
    print(f"  Total:      {a.total_bits:.1f} bits")
    print()

    # Each verdict carries one line in ordinary words. The arithmetic above is
    # aimed at a reader who already accepts that entropy is the thing to worry
    # about, and that reader is not the one at risk. The person who needs this
    # most rolls twenty times, reads "51.7 bits", cannot tell whether that is
    # good, and stops.
    if a.meets_target:
        print(f"  Verdict:    Strong. Clears {TARGET_BITS} bits.")
        print("              Nobody can guess this, at any budget.")
        # Rolling past the target cannot improve a seed: 24 words hold 256 bits
        # and the format discards the rest. Saying only "Strong" leaves someone
        # who rolled 300 times assuming the extra 200 bought something.
        if a.rolls > a.rolls_for_target:
            spare = a.rolls - a.rolls_for_target
            print(f"              {a.rolls_for_target} rolls was enough; the "
                  f"other {spare} added nothing,")
            print(f"              because a 24-word seed holds only "
                  f"{TARGET_BITS} bits.")
    elif a.meets_floor:
        short = TARGET_BITS - a.total_bits
        print(f"  Verdict:    OK. Clears the {FLOOR_BITS}-bit floor.")
        print(f"              {short:.1f} bits short of {TARGET_BITS}; "
              f"{a.rolls_for_target} rolls reaches it.")
        print("              Safe to use, but not the strongest a seed can hold.")
    else:
        print(f"  Verdict:    NOT ENOUGH. Below the {FLOOR_BITS}-bit floor.")
        print(f"              Roll {a.shortfall_to_floor} more "
              f"({a.rolls_for_floor} total) to clear it.")
        print("              An attacker with money could search this. "
              "Keep rolling.")

    print()
    print(f"  For d{a.sides}:   {a.rolls_for_floor} rolls -> "
          f"{FLOOR_BITS} bits, {a.rolls_for_target} rolls -> {TARGET_BITS} bits")
    print()
    print("  This counts rolls. It cannot see whether they were fair,")
    print("  independent, ordered and private, and all four are required:")
    print("    - a weighted or shaved die carries less than the figure above")
    print("    - re-rolling a result you disliked discards the entropy you kept")
    print("    - reading dice thrown together in sorted order loses most of it")
    print("    - a sequence that was seen, filmed or typed anywhere is spent")
    print("  Hashing does not add any. SHA-256 over 50 d6 rolls returns 256")
    print("  bits carrying 129.")

    if not a.meets_floor:
        sys.exit(1)


def _run_inspect(b64_data: str) -> None:
    """Inspect a ciphertext header without decrypting — no password needed."""
    import base64

    # Try to parse header
    try:
        version, cipher_id, kdf_id, flags, payload, kdf_params = deserialize(b64_data)
    except Exception as exc:
        _print_status(f"Error: cannot parse ciphertext header: {exc}", error=True)
        _print_status("  Make sure the input is valid MORPHEUS ciphertext (base64).", error=True)
        sys.exit(1)

    try:
        raw = base64.b64decode(b64_data, validate=True)
    except Exception:
        raw = b""

    is_v3 = version in (FORMAT_VERSION_3, FORMAT_VERSION_4)
    is_chained = bool(flags & FLAG_CHAINED)
    is_hybrid = bool(flags & FLAG_HYBRID_PQ)
    is_padded = bool(flags & FLAG_PADDED)

    # Version
    ver_str = _format_label(version)

    # Cipher
    if is_chained:
        cipher_str = "AES-256-GCM + ChaCha20-Poly1305 (chained)"
        nonce_count = 2
    else:
        cipher_cls = CIPHER_REGISTRY.get(cipher_id)
        cipher_str = cipher_cls.name if cipher_cls else f"unknown ({cipher_id:#04x})"
        nonce_count = 1

    # KDF
    kdf_cls = KDF_REGISTRY.get(kdf_id)
    kdf_str = kdf_cls.name if kdf_cls else f"unknown ({kdf_id:#04x})"
    params_str = ""
    if kdf_params and is_v3:
        if kdf_id == 0x02:  # Argon2id
            mem_mib = kdf_params[1] / 1024
            params_str = f" (t={kdf_params[0]}, m={mem_mib:.0f} MiB, p={kdf_params[2]})"
        elif kdf_id == 0x01:  # Scrypt
            params_str = f" (n={kdf_params[0]}, r={kdf_params[1]}, p={kdf_params[2]})"

    # Flags
    flag_parts = []
    if is_chained:
        flag_parts.append("chained")
    if is_hybrid:
        flag_parts.append("hybrid PQ")
    if is_padded:
        flag_parts.append("padded")
    flags_str = ", ".join(flag_parts) if flag_parts else "none"

    # Size breakdown
    header_size = HEADER_SIZE_V3 if is_v3 else HEADER_SIZE
    salt_size = 16
    nonce_size = 12 * nonce_count
    # v4 stores a 32-byte commitment where v3 stores an 8-byte check. Using
    # the v3 width for both misattributed 24 bytes of every v4 ciphertext,
    # understating Overhead and overstating Encrypted.
    if version == FORMAT_VERSION_4:
        key_check_size = COMMITMENT_SIZE
    elif is_v3:
        key_check_size = KEY_CHECK_SIZE
    else:
        key_check_size = 0
    # The KEM prefix is framing, not encrypted data. Omitting it from both
    # figures made a 19-byte hybrid plaintext report as ~1125 bytes "Encrypted".
    kem_size = 0
    if is_hybrid and len(payload) >= salt_size + nonce_size + 2:
        offset = salt_size + nonce_size
        kem_size = 2 + int.from_bytes(payload[offset:offset + 2], "big")

    payload_size = len(payload)
    # Overhead and Encrypted are disjoint and sum to the total. They used to
    # both include the AEAD tag, so the two printed lines exceeded the printed
    # total and read as an arithmetic error.
    overhead = header_size + salt_size + nonce_size + key_check_size + kem_size
    estimated_ct = max(
        0, payload_size - salt_size - nonce_size - key_check_size - kem_size
    )

    print("MORPHEUS Ciphertext Inspection")
    print("=" * 44)
    print(f"  Format:     {ver_str}")
    print(f"  Cipher:     {cipher_str}")
    print(f"  KDF:        {kdf_str}{params_str}")
    print(f"  Flags:      {flags_str}")
    print(f"  Total size: {len(raw)} bytes ({len(b64_data)} base64 chars)")
    print(f"  Header:     {header_size} bytes")
    print(f"  Payload:    {payload_size} bytes")
    label = "commitment" if version == FORMAT_VERSION_4 else "key-check"
    kem_note = "+kem" if kem_size else ""
    print(f"  Framing:    ~{overhead} bytes (header+salt+nonce+{label}{kem_note})")
    print(f"  Encrypted:  ~{estimated_ct} bytes (ciphertext + AEAD tag)")
    if is_padded:
        print("  Note:       Plaintext was padded before encryption (exact length hidden)")
    if is_hybrid:
        print("  Note:       Requires --hybrid-pq --pq-secret-key to decrypt")
    if not is_v3:
        print("  Note:       v2 format — decrypter must match KDF parameters manually")
    print("=" * 44)


def _padding_hint(data_len: int, used_pad: bool, used_fixed: bool) -> str:
    """Return a one-line padding hint for the user after encryption."""
    if used_fixed:
        return ""  # already using max privacy
    if used_pad:
        # Show which bucket the data fell into
        bucket = _PAD_BUCKETS[-1]
        for b in _PAD_BUCKETS:
            if data_len < b:
                bucket = b
                break
        if bucket < 1024:
            bucket_str = f"{bucket}B"
        else:
            bucket_str = f"{bucket // 1024}K"
        return f"Tip: Padded to {bucket_str} bucket. Use --fixed-size for constant 64K output."
    # No padding at all
    return "Tip: Ciphertext length reveals approximate message size. Use --pad or --fixed-size for privacy."


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

    # --- Load persistent preferences (CLI args override) ---
    # set_defaults *before* parse_args, so argparse itself resolves the
    # precedence. Applying the config afterwards meant inferring "the user did
    # not pass this" by comparing against the parser default, which cannot
    # distinguish an unset flag from one explicitly set to the default value.
    saved = load_config()
    if saved:
        parser.set_defaults(**saved)
    args = parser.parse_args(argv)

    if saved:
        # Announced on stderr: a config that changes what the tool does while
        # saying nothing is indistinguishable from one someone else planted.
        _print_status(
            f"Using saved preferences from {config_path()} "
            f"({', '.join(f'{k}={v}' for k, v in sorted(saved.items()))}). "
            "CLI arguments override these.",
            error=True,
        )

    # --- Reject argument combinations decidable from argv alone ---
    # The pipeline constructor also rejects this, but it runs after the user
    # has typed and confirmed a password. parser.error() exits 2 immediately
    # with a usage message, costing nothing.
    if args.chain and args.cipher != "AES-256-GCM":
        parser.error(
            f"--chain uses a fixed cipher order (AES-256-GCM -> "
            f"ChaCha20-Poly1305) and cannot be combined with "
            f"--cipher {args.cipher}. Drop one of the two flags."
        )

    # pqcrypto is an optional extra and is deliberately absent from
    # requirements.txt, so this is the state a user lands in by following the
    # Quick Start and then reaching for the headline feature. Whether the
    # package is importable is known here, long before a password is worth
    # asking for.
    # Only pqcrypto and the local editable install are offered. An extra on
    # this project's own distribution name would be the natural second
    # suggestion, but that name on PyPI belongs to an unrelated project, so it
    # would fetch a stranger's package. Naming a distribution we do not own, in
    # the error a user hits at the exact moment they want post-quantum
    # encryption, is not a typo to leave lying around in a security tool.
    if args.hybrid_pq and not PQ_AVAILABLE:
        parser.error(
            "--hybrid-pq needs the optional pqcrypto package, which is not "
            "installed. Install it with `pip install pqcrypto`, or from a "
            "clone with `pip install -e \".[pq]\"`, and try again. Encrypting "
            "without it would produce ordinary password-only ciphertext."
        )

    # --- Resolve the ML-KEM secret key source ---
    # argv is readable by every local user through `ps` and
    # /proc/<pid>/cmdline, and it persists in shell history, so the file form
    # is preferred and the argv form warns. Resolving here means the rest of
    # the CLI only ever sees args.pq_secret_key.
    if args.pq_secret_key and args.pq_secret_key_file:
        _print_status(
            "Error: --pq-secret-key and --pq-secret-key-file are mutually "
            "exclusive.\n  Pass the key once. Prefer --pq-secret-key-file, "
            "which keeps the key out of argv.",
            error=True,
        )
        sys.exit(1)

    if args.pq_public_key and args.pq_public_key_file:
        _print_status(
            "Error: --pq-public-key and --pq-public-key-file are mutually "
            "exclusive.\n  Pass the key once.",
            error=True,
        )
        sys.exit(1)

    # Remember what the user actually typed. Both file variants are folded into
    # the non-file attribute below, so without this the "requires --hybrid-pq"
    # error names a flag the user never used.
    pq_flag_used = (
        "--pq-public-key-file" if args.pq_public_key_file else
        "--pq-public-key" if args.pq_public_key else
        "--pq-secret-key-file" if args.pq_secret_key_file else
        "--pq-secret-key" if args.pq_secret_key else None
    )

    if args.pq_public_key_file:
        args.pq_public_key = _read_pq_public_key_file(args.pq_public_key_file)

    if args.pq_secret_key_file:
        args.pq_secret_key = _read_pq_secret_key_file(args.pq_secret_key_file)
    elif args.pq_secret_key:
        _print_status(
            "Warning: --pq-secret-key puts your ML-KEM secret key in argv, "
            "where other local users can read it from `ps` and shell "
            "history.\n  Use --pq-secret-key-file instead.",
            error=True,
        )

    # --- Reject PQ keys without --hybrid-pq ---
    # The key arguments are only consumed inside the hybrid-PQ branch, so
    # accepting them here would silently produce password-only ciphertext
    # while the user believed it was quantum-resistant. Checked before the
    # password prompt so the failure costs nothing.
    if (args.pq_public_key or args.pq_secret_key) and not args.hybrid_pq:
        given = pq_flag_used or "--pq-public-key"
        _print_status(
            f"Error: {given} requires --hybrid-pq.\n"
            "  Without it the post-quantum layer is not applied and the output "
            "would be protected by the password alone.\n"
            "  Add --hybrid-pq to enable hybrid post-quantum encryption.",
            error=True,
        )
        sys.exit(1)

    # --- Save config ---
    if args.save_config:
        settings: dict[str, str | bool] = {}
        settings["cipher"] = args.cipher
        settings["kdf"] = args.kdf
        # check_leaks and passphrase are intentionally not persistable; see
        # the _BOOL_KEYS comment in core/config.py.
        for flag in ("chain", "pad", "fixed_size", "no_filename"):
            if getattr(args, flag, False):
                settings[flag] = True
        path = save_config(settings)
        _print_status(f"Preferences saved to {path}")
        return

    # --- Dice entropy ---
    #
    # Ahead of the password prompt on purpose. This reads nothing, writes
    # nothing and needs no key, so asking for a password first would be theatre
    # -- the same reason --version and --inspect resolve up here.
    if getattr(args, "check_network", False):
        _run_check_network()

    if args.dice_entropy is not None:
        _run_dice_entropy(args.dice_entropy, args.dice_sides)
        return

    # --- Inspect ---
    if args.inspect:
        if args.file:
            import os
            if not os.path.isfile(args.file):
                _print_status(f"Error: file not found: {args.file}", error=True)
                sys.exit(1)
            # utf-8-sig, not utf-8: a ciphertext saved by Notepad carries a BOM,
            # and left in place it makes base64 reject the whole payload.
            with open(args.file, "r", encoding="utf-8-sig") as f:
                inspect_data = f.read().strip()
        elif args.data:
            inspect_data = args.data
        else:
            inspect_data = input("Enter ciphertext to inspect: ").strip()
        _run_inspect(inspect_data)
        return

    # --- Benchmark ---
    if args.benchmark:
        _run_benchmark()
        return

    # --- Generate keypair ---
    if args.generate_keypair:
        if not PQ_AVAILABLE:
            _print_status("Error: pqcrypto not installed. Run: pip install pqcrypto", error=True)
            sys.exit(1)
        import base64

        from .core.pipeline import pq_generate_keypair
        pk, sk = pq_generate_keypair()

        # The secret key never goes to stdout: terminal scrollback, tmux
        # buffers and shell logging all outlive the command. It goes to a
        # 0600 file instead, which is also what --pq-secret-key-file wants.
        # The public key also goes to a file. It is 1,580 base64 characters, so
        # expecting anyone to select it out of a terminal and shell-substitute
        # it was the single worst step in the post-quantum flow. A path is
        # something a person can actually pass around.
        #
        # It goes through the same guarded open as the secret key. It used to
        # use a plain `open(pk_path, "w")`, which follows a symlink and
        # truncates its target regardless of --force. Since the path is derived
        # predictably from --output, anyone able to create a file in that
        # directory first could turn keypair generation into an arbitrary-file
        # overwrite that exited successfully (2026-08-02 review, F-06).
        #
        # Both handles are opened before either is written, and the secret key
        # is removed if the public key is refused. Otherwise a blocked .pub
        # leaves a secret key on disk whose public half was never saved, and
        # ML-KEM gives no way to recover one from the other.
        sk_path = args.output or "morpheus_pq_secret.key"
        pk_path = f"{sk_path}.pub"
        # Both are entered before either is written. If the public key path is
        # refused, the secret key's writer unwinds and removes what it had
        # reserved, so a blocked .pub cannot leave a secret key on disk whose
        # public half was never saved -- ML-KEM gives no way to recover one
        # from the other. The atomic writer makes that cleanup automatic.
        with _open_secure_output(sk_path, args.force) as sk_fh, \
             _open_secure_output(pk_path, args.force) as pk_fh:
            sk_fh.write(base64.b64encode(sk).decode() + "\n")
            pk_fh.write(base64.b64encode(pk).decode() + "\n")

        # Still printed too: stdout is pipeable and some callers want it.
        print(base64.b64encode(pk).decode())
        _print_status(
            f"ML-KEM-768 keypair generated.\n"
            f"  Public key: {pk_path} (share this; also printed above)\n"
            f"  Secret key: {sk_path} (mode 0600)\n"
            f"  Encrypt to it: --hybrid-pq --pq-public-key-file {pk_path}\n"
            f"  Decrypt with:  --hybrid-pq --pq-secret-key-file {sk_path}\n"
            "  Back the secret key up now. There is no way to regenerate it."
        )
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
            if getattr(args, "passphrase", False):
                strength = check_passphrase_strength(password)
            else:
                strength = check_password_strength(password)
            if not strength.is_acceptable:
                mode = "passphrase" if getattr(args, "passphrase", False) else "password"
                _print_status(
                    f"Error: {mode} too weak ({strength.label}). "
                    + "; ".join(strength.feedback),
                    error=True,
                )
                sys.exit(1)
        else:
            _print_status(
                "Warning: password strength check skipped (--no-strength-check).",
                error=True,
            )

        # Breach check (opt-in, requires network)
        if getattr(args, "check_leaks", False):
            import urllib.error
            try:
                is_leaked, count = check_password_leaked(password)
                if is_leaked:
                    _print_status(
                        f"WARNING: This password has appeared in {count:,} known "
                        f"data breaches (Have I Been Pwned). Choose a different password.",
                        error=True,
                    )
                    sys.exit(1)
            except (urllib.error.URLError, OSError) as exc:
                _print_status(
                    f"Warning: breach check failed (network error: {exc}). "
                    "Proceeding without breach check.",
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
        allow_expensive_kdf=getattr(args, "allow_expensive_kdf", False),
    )

    # --- File mode ---
    if args.file:
        _run_file_operation(args, operation, password, pipeline)
        return

    # --- Text mode ---
    try:
        if operation == "encrypt":
            _progress(f"Deriving key ({pipeline.kdf.name})...")
            result = pipeline.encrypt(data, password, pad=args.pad,
                                      fixed_size=args.fixed_size)
            # Banner to stderr, payload to stdout: keeps the pipe clean.
            _progress(f"\nEncrypted ({pipeline.description}):")
            print(result)
            hint = _padding_hint(len(data.encode("utf-8")), args.pad, args.fixed_size)
            if hint:
                _progress(hint)
        else:
            _progress("Deriving key and decrypting...")
            result = pipeline.decrypt(data, password)
            _progress("\nDecrypted:")
            print(result)
    except Exception as exc:
        if operation == "decrypt":
            diag = _diagnose_ciphertext(data)
            suggestion = _suggest_fix(exc, data)
            msg = f"Decryption failed: {exc}\n"
            if diag:
                msg += f"\nCiphertext details:\n{diag}"
            if suggestion:
                msg += suggestion
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


def _read_pq_public_key_file(path: str) -> str:
    """Read a base64 ML-KEM public key from *path*.

    No permission check, unlike the secret-key reader: a public key is meant to
    be shared, and warning about its mode would train people to ignore the
    warning that matters.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            key_b64 = fh.read().strip()
    except OSError as exc:
        _print_status(
            f"Error: cannot read --pq-public-key-file: {path}\n"
            f"  {exc.strerror}.",
            error=True,
        )
        sys.exit(1)

    if not key_b64:
        _print_status(
            f"Error: --pq-public-key-file is empty: {path}", error=True
        )
        sys.exit(1)

    return key_b64


def _read_pq_secret_key_file(path: str) -> str:
    """Read a base64 ML-KEM secret key from *path*.

    Warns when the file is readable by anyone but its owner, since a key that
    was kept out of argv only to sit in a world-readable file has gained
    nothing.
    """
    import os
    import stat

    try:
        with open(path, encoding="utf-8") as fh:
            key_b64 = fh.read().strip()
    except OSError as exc:
        _print_status(
            f"Error: cannot read --pq-secret-key-file: {path}\n"
            f"  {exc.strerror}.",
            error=True,
        )
        sys.exit(1)

    if not key_b64:
        _print_status(
            f"Error: --pq-secret-key-file is empty: {path}", error=True
        )
        sys.exit(1)

    try:
        mode = os.stat(path).st_mode
    except OSError:
        mode = 0
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        _print_status(
            f"Warning: {path} is readable by users other than its owner "
            f"(mode {stat.S_IMODE(mode):04o}).\n  Run: chmod 600 {path}",
            error=True,
        )
    return key_b64


@contextlib.contextmanager
def _open_secure_output(path: str, force: bool, binary: bool = False):
    """Open *path* for writing, owner-only, refusing to follow a symlink.

    Three problems close together here:

    * ``O_NOFOLLOW`` refuses a symlink at the final component. ``os.path.exists``
      reports False for a *dangling* link, so ``_check_overwrite`` cannot see
      one and the write would otherwise land on the link's target.
    * ``O_EXCL`` makes the existence check atomic rather than a TOCTOU window.
      ``--force`` swaps it for ``O_TRUNC`` so an intentional overwrite still
      works, and still refuses symlinks.
    * ``fchmod`` is applied unconditionally, so the mode depends on neither the
      umask nor whatever permissions an overwritten file happened to carry.
    """
    try:
        # Atomic: the bytes land in a temporary file in the same directory and
        # are fsynced before os.replace swaps them in, so an interrupted run
        # cannot leave a half-written output, and --force cannot destroy the
        # previous file without producing the new one (F-15).
        with atomic_secure_output(path, force=force, binary=binary) as handle:
            yield handle
        return
    except OSError as exc:
        _print_status(
            f"Error: cannot write output file: {path}\n"
            f"  {exc.strerror}.\n"
            "  If this path is a symlink or already exists, choose a "
            "different --output path (or pass --force to overwrite a "
            "regular file).",
            error=True,
        )
        sys.exit(1)


def _default_output_name(file_path: str) -> str:
    """Derive a decrypt output path that is never the input path itself.

    ``removesuffix('.enc')`` returns the path unchanged when the ciphertext is
    not named ``*.enc``, which would otherwise make output == input.
    """
    import os

    stripped = file_path.removesuffix(".enc")
    if stripped != file_path:
        return stripped
    base = os.path.basename(file_path) or "decrypted_output"
    return os.path.join(os.path.dirname(file_path), f"{base}.decrypted")


def _reject_output_over_input(out_path: str, in_path: str) -> None:
    """Abort if the output would be written over its own input file.

    Decrypting onto the ciphertext destroys the only copy of it, so this is
    refused outright rather than gated behind --force.
    """
    import os

    if os.path.realpath(out_path) == os.path.realpath(in_path):
        _print_status(
            f"Error: refusing to write output over the input file: {in_path}\n"
            "  This would destroy the ciphertext. Use --output to choose a "
            "different path.",
            error=True,
        )
        sys.exit(1)


def _run_file_operation(args, operation: str, password: str, pipeline) -> None:
    """Encrypt or decrypt a file."""
    import os

    file_path = args.file
    if not os.path.isfile(file_path):
        _print_status(f"Error: file not found: {file_path}", error=True)
        sys.exit(1)

    file_size = os.path.getsize(file_path)
    if operation == "encrypt":
        limit, what = _MAX_PLAINTEXT_BYTES, "file"
    else:
        limit, what = _MAX_CIPHERTEXT_BYTES, "ciphertext file"
    if file_size > limit:
        _print_status(
            f"Error: {what} too large ({file_size / 1024 / 1024:.1f} MiB, "
            f"max {limit / 1024 / 1024:.0f} MiB)",
            error=True,
        )
        sys.exit(1)

    if operation == "encrypt":
        # Read file bytes, base64 encode for the pipeline
        with open(file_path, "rb") as f:
            raw_data = f.read()

        # Wrap raw bytes in a versioned transport envelope

        envelope = envelope_encode(
            raw_data,
            None if getattr(args, "no_filename", False) else file_path,
        )

        _progress(f"Deriving key ({pipeline.kdf.name}) for {file_size} byte file...")
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
        with _open_secure_output(out_path, args.force) as f:
            f.write(encrypted)

        _print_status(
            f"Encrypted ({pipeline.description}): {file_path} -> {out_path} "
            f"({file_size} bytes -> {len(encrypted)} chars)"
        )
        hint = _padding_hint(file_size, args.pad, args.fixed_size)
        if hint:
            _progress(hint)

    else:
        # utf-8-sig strips a BOM if one is there and is identical to utf-8 when
        # it is not. Without it, a ciphertext round-tripped through a Windows
        # editor fails as "Invalid base64 encoding", which blames the payload.
        with open(file_path, "r", encoding="utf-8-sig") as f:
            encrypted_data = f.read().strip()

        _progress(f"Deriving key and decrypting {file_path}...")
        try:
            decrypted = pipeline.decrypt(encrypted_data, password)
        except Exception as exc:
            diag = _diagnose_ciphertext(encrypted_data)
            suggestion = _suggest_fix(exc, encrypted_data)
            msg = f"Decryption failed: {exc}\n"
            if diag:
                msg += f"\nCiphertext details:\n{diag}"
            if suggestion:
                msg += suggestion
            _print_status(msg, error=True)
            sys.exit(1)

        # Parsed by the shared strict decoder: it recognises an envelope only
        # when the whole schema holds, so ordinary JSON plaintext that happens
        # to carry a "data" key is returned to the user unharmed instead of
        # being written out as its own base64 payload.
        try:
            envelope = envelope_decode(decrypted)
        except FormatError as exc:
            _print_status(f"Error: {exc}", error=True)
            sys.exit(1)
        if envelope is not None:
            raw_data = envelope.data
            original_name = envelope.filename or _default_output_name(file_path)
            out_path = args.output or original_name
            _reject_output_over_input(out_path, file_path)
            _check_overwrite(out_path, args.force)
            with _open_secure_output(out_path, args.force, binary=True) as f:
                f.write(raw_data)
            # The name came from someone else's ciphertext, so it is escaped
            # rather than printed raw: an unescaped one can carry terminal
            # control sequences (2026-08-02 review, F-08).
            _print_status(
                f"Decrypted: {file_path} -> {out_path!r} ({len(raw_data)} bytes)"
            )
            return

        # Fallback: treat as plain text
        out_path = args.output or _default_output_name(file_path)
        _reject_output_over_input(out_path, file_path)
        _check_overwrite(out_path, args.force)
        with _open_secure_output(out_path, args.force) as f:
            f.write(decrypted)
        _print_status(f"Decrypted: {file_path} -> {out_path}")
