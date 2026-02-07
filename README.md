# SecureDataEncryption v2.0

A modern, quantum-resistant, multi-cipher encryption tool with a terminal GUI.

Encrypt and decrypt arbitrary blocks of text — documents, credentials, notes,
code snippets, configuration files — using modern, standards-based cryptography with an
intuitive interface. **No data is intentionally written to disk** (see
[Threat Model](#threat-model--limitations) for caveats). Encrypted output is
displayed once and then auto-cleared.

## What Makes This Different

| Feature | This Tool | Typical CLI Tools |
|---------|-----------|-------------------|
| **Hybrid post-quantum encryption** | ML-KEM-768 + AES/ChaCha via FIPS 203 | Not available |
| **Cipher chaining** | AES-256-GCM → ChaCha20-Poly1305 (two independent algorithms) | Single cipher |
| **One-time output** | Auto-clears after 60 seconds, wipes clipboard | Stays in scrollback forever |
| **Memory protection** | Best-effort `mlock()` + zeroing (see [limitations](#threat-model--limitations)) | None |
| **Modern terminal GUI** | Full TUI with dropdowns, strength meter, dark theme | Plain text prompts |
| **File encryption** | Encrypt any file type (text, binary, images, archives) up to 100 MiB | Usually text-only |
| **Self-describing format** | Versioned binary header identifies cipher, KDF, and flags | Ad-hoc formats |

## Quick Start

```bash
# Clone and install
git clone https://github.com/404securitynotfound/SecureDataEncryption.git
cd SecureDataEncryption
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Launch the GUI
python secure_data_encryption.py

# Or use CLI mode
python secure_data_encryption.py --cli
```

## Encryption Modes

### 1. Single Cipher (Password Only)
```
AES-256-GCM   — NIST standard, hardware-accelerated on modern CPUs
ChaCha20-Poly1305 — Constant-time, ideal when AES-NI is unavailable
```
Both are **already quantum-safe** for symmetric encryption (Grover's algorithm
reduces AES-256 to ~128-bit equivalent security, which remains unbreakable).

### 2. Cipher Chaining (Defense-in-Depth)
Encrypts with AES-256-GCM **then** ChaCha20-Poly1305 using independent keys.
If a vulnerability is found in one algorithm, the other still protects your data.

### 3. Hybrid Post-Quantum (ML-KEM-768)
Layers NIST FIPS 203 ML-KEM-768 key encapsulation on top of password-based
encryption. The final encryption key combines:
- Your password (via Argon2id/Scrypt)
- An ML-KEM-768 shared secret

An attacker must break **both** the password **and** ML-KEM to decrypt.
This provides defense-in-depth against future quantum computers that could
break the KEM, but overall security is still bounded by password entropy —
a weak password remains the weakest link regardless of PQ layers.

### 4. Maximum Security (Chained + Hybrid PQ)
All layers combined: ML-KEM-768 + AES-256-GCM + ChaCha20-Poly1305.

## Key Derivation Functions

| KDF | Default | Description |
|-----|---------|-------------|
| **Argon2id** (recommended) | `t=3, m=64MiB, p=4` | OWASP/IETF recommended (RFC 9106). Memory-hard, resists GPU attacks. |
| **Scrypt** | `n=2^17, r=8, p=1` | RFC 7914. Also memory-hard, well-established. |

## GUI Usage

Launch with no arguments to open the terminal GUI:

```bash
python secure_data_encryption.py
```

The GUI provides:
- **Mode toggle**: Encrypt / Decrypt
- **Cipher selection**: AES-256-GCM or ChaCha20-Poly1305
- **KDF selection**: Argon2id or Scrypt
- **Chain ciphers checkbox**: Enable defense-in-depth chaining
- **Hybrid PQ checkbox**: Enable ML-KEM-768 (with key generation)
- **Multi-line text area**: Paste or type any block of text
- **Password field**: With real-time strength meter and match indicator
- **One-time output**: Auto-clears after 60 seconds with countdown
- **Copy button**: Copies to clipboard (auto-cleared with output)

**Keyboard shortcuts**: `Ctrl+E` Encrypt | `Ctrl+D` Decrypt | `Ctrl+L` Clear | `Ctrl+Q` Quit

## CLI Usage

```bash
# Interactive CLI
python secure_data_encryption.py --cli

# Encrypt with specific options
python secure_data_encryption.py -o encrypt --data "sensitive text" --cipher ChaCha20-Poly1305 --kdf Argon2id

# Encrypt with chaining
python secure_data_encryption.py -o encrypt --data "sensitive text" --chain

# Read from stdin
echo "my secret document" | python secure_data_encryption.py -o encrypt --data -

# Decrypt
python secure_data_encryption.py -o decrypt --data "AgEB..."

# Encrypt a file (any format — text, binary, images, archives)
python secure_data_encryption.py -o encrypt -f secret.pdf
# -> produces secret.pdf.enc

# Decrypt a file
python secure_data_encryption.py -o decrypt -f secret.pdf.enc
# -> restores secret.pdf with original filename

# Encrypt with explicit output path
python secure_data_encryption.py -o encrypt -f data.csv --output encrypted.dat

# Generate ML-KEM-768 keypair
python secure_data_encryption.py --generate-keypair

# Hybrid PQ encrypt
python secure_data_encryption.py -o encrypt --data "secret" --hybrid-pq --pq-public-key <base64-pk>
```

**Security note**: Passwords are always entered interactively (never as CLI
arguments) to prevent leaking via `ps`, shell history, or `/proc`.

## Running Tests

```bash
pip install pytest
python -m pytest tests/ -v
```

122 tests cover: cipher roundtrips, KDF derivation, format serialization,
password validation, pipeline chaining, hybrid PQ encryption, memory zeroing,
cross-compatibility, file encryption, NIST/RFC test vectors, and negative
cases (wrong password, tampered data, corrupted format).

## Project Structure

```
SecureDataEncryption/
├── secure_encryption/
│   ├── __init__.py          # Package version
│   ├── __main__.py          # Entry point (auto-detects GUI vs CLI)
│   ├── gui.py               # Textual TUI application
│   ├── cli.py               # Command-line interface
│   └── core/
│       ├── ciphers.py       # AES-256-GCM, ChaCha20-Poly1305
│       ├── kdf.py           # Argon2id, Scrypt
│       ├── pipeline.py      # Encryption orchestration, chaining, hybrid PQ
│       ├── formats.py       # Versioned binary ciphertext format
│       ├── memory.py        # mlock, secure zeroing
│       └── validation.py    # Password strength scoring, input checks
├── tests/                   # 122 tests
├── docs/
│   └── USAGE.md             # Full guide with plain-English explanations
├── secure_data_encryption.py  # Entry point script
├── requirements.txt
├── pyproject.toml
└── LICENSE
```

## Requirements

- Python 3.10+
- `cryptography` — AES-GCM, ChaCha20-Poly1305, Scrypt, HKDF
- `argon2-cffi` — Argon2id key derivation
- `textual` — Terminal GUI framework
- `pyperclip` — Clipboard access
- `pqcrypto` — ML-KEM-768 post-quantum key encapsulation (optional)

## Security Design

- **No intentional disk writes**: All data lives in memory. Output auto-clears.
  If `mlock()` fails, the OS may swap sensitive pages to disk (see Threat Model).
- **Memory locking**: Sensitive buffers are `mlock`'d to prevent swap (best-effort;
  logs a warning if locking fails due to `RLIMIT_MEMLOCK`).
- **Secure zeroing**: Key material is overwritten with zeros after use.
- **Contextual AAD**: The cipher ID, KDF ID, version, and flags are
  authenticated as Associated Data, preventing ciphertext reuse across contexts.
- **Versioned format**: Forward-compatible binary header enables future
  cipher additions without breaking existing ciphertexts.
- **Password hygiene**: Strong enforcement (12+ chars, mixed classes),
  interactive-only input, real-time strength feedback.

### Security Settings Rationale

| Setting | Value | Why |
|---------|-------|-----|
| **Argon2id** (default KDF) | `t=3, m=64 MiB, p=4` | Meets OWASP 2024 minimum recommendation. Memory-hardness resists GPU/ASIC attacks; the hybrid Argon2**id** variant resists both side-channel and brute-force attacks. |
| **Scrypt** (alternative KDF) | `n=2^17, r=8, p=1` | RFC 7914 parameters matching ~128 MiB memory. Offered for environments where Argon2 is unavailable. |
| **AES-256-GCM** (default cipher) | 256-bit key, 96-bit nonce | NIST standard; hardware-accelerated via AES-NI on x86/ARM. 256-bit key provides ~128-bit post-quantum security against Grover's algorithm. |
| **ChaCha20-Poly1305** (alternative) | 256-bit key, 96-bit nonce | Constant-time in software; preferred on devices without AES-NI. Same post-quantum security margin as AES-256. |
| **ML-KEM-768** (hybrid PQ) | FIPS 203, Category 3 | Balances post-quantum security (Category 3 ≈ AES-192 equivalent) with key size. Category 5 (ML-KEM-1024) was considered but doubles key sizes for marginal benefit. |
| **Salt size** | 16 bytes (128 bits) | Standard for Argon2id/Scrypt; 128 bits of entropy prevents rainbow table attacks and ensures unique key derivation per encryption. |
| **Nonce size** | 12 bytes (96 bits) | Standard for AES-GCM and ChaCha20-Poly1305. Random nonces are safe for the expected number of encryptions per key. |

### Threat Model & Limitations

**In scope — what this tool protects against:**
- Offline brute-force attacks on encrypted data (via memory-hard KDFs)
- Future quantum computers (via hybrid ML-KEM-768 layer)
- Single-algorithm compromise (via cipher chaining)
- Casual memory forensics (via `mlock` + secure zeroing)

**Out of scope — what this tool does NOT protect against:**
- **Compromised endpoint**: If your machine has malware, a keylogger, or a
  hostile root process, no user-space encryption tool can help. This tool
  assumes the OS and hardware are trustworthy.
- **Python string immutability**: Python `str` objects are immutable and
  cannot be reliably zeroed. The password exists as an immutable string
  briefly before conversion to `bytearray`. The GC may not collect it
  immediately. This is a fundamental language limitation.
- **Clipboard history managers**: The GUI clears the system clipboard after
  the auto-clear timer, but clipboard history managers (macOS Universal
  Clipboard, Windows Clipboard History, KDE Klipper) may retain copies in
  a separate history store beyond our control.
- **Swap/hibernation on systems without mlock**: If `mlock()` fails (e.g.,
  insufficient `RLIMIT_MEMLOCK`), sensitive buffers may be swapped to disk.
  The tool logs a warning but continues operating.
- **Side-channel attacks**: This tool does not implement constant-time
  comparisons for all paths. It relies on the `cryptography` library's
  constant-time primitives for AEAD operations.
- **KDF parameter storage**: KDF tuning parameters (time_cost, memory_cost)
  are NOT stored in the ciphertext format. The decrypting pipeline must use
  matching KDF parameters. Mismatched parameters silently derive wrong keys,
  producing an authentication failure (not a clear config error).

### Ciphertext Format

The binary format is self-describing — the header identifies the cipher, KDF,
and mode so any compatible tool can decrypt without out-of-band configuration.

```
Offset  Size  Field
──────  ────  ─────────────────────────────────
0       1     Version (0x02)
1       1     Cipher ID (0x01=AES-256-GCM, 0x02=ChaCha20, 0x03=Chained)
2       1     KDF ID (0x01=Scrypt, 0x02=Argon2id)
3       1     Flags (bit 0=chained, bit 1=hybrid PQ)
4-5     2     Reserved (0x0000)
6+      var   Payload (see below)
```

**Payload layout — single cipher:**
```
[16-byte salt][12-byte nonce][ciphertext + 16-byte auth tag]
```

**Payload layout — chained (AES-GCM → ChaCha20):**
```
[16-byte salt][12-byte AES nonce][12-byte ChaCha nonce][ciphertext + tags]
```

**Payload layout — hybrid PQ prefix (prepended before cipher payload):**
```
[2-byte KEM ciphertext length (big-endian)][KEM ciphertext]
```

All ciphertexts are base64-encoded for safe text transport. The header fields
are authenticated as Associated Data (AAD), binding the format metadata to the
ciphertext and preventing downgrade or context-switching attacks.

## License

MIT License

## Contributing

Contributions welcome. Please open an issue or submit a pull request.

## Contact

404securitynotfound@protonmail.ch
