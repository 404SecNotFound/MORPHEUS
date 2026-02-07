# SecureDataEncryption v2.0

A modern, quantum-resistant, multi-cipher encryption tool with a terminal GUI.

Encrypt and decrypt arbitrary blocks of text — documents, credentials, notes,
code snippets, configuration files — using military-grade cryptography with an
intuitive interface. **No data is ever written to disk.** Encrypted output is
displayed once and then auto-cleared.

## What Makes This Different

| Feature | This Tool | Typical CLI Tools |
|---------|-----------|-------------------|
| **Hybrid post-quantum encryption** | ML-KEM-768 + AES/ChaCha via FIPS 203 | Not available |
| **Cipher chaining** | AES-256-GCM → ChaCha20-Poly1305 (two independent algorithms) | Single cipher |
| **One-time output** | Auto-clears after 60 seconds, wipes clipboard | Stays in scrollback forever |
| **Memory protection** | `mlock()` prevents swap, buffers zeroed after use | None |
| **Modern terminal GUI** | Full TUI with dropdowns, strength meter, dark theme | Plain text prompts |
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

86 tests cover: cipher roundtrips, KDF derivation, format serialization,
password validation, pipeline chaining, hybrid PQ encryption, memory zeroing,
cross-compatibility, and negative cases (wrong password, tampered data,
corrupted format).

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
├── tests/                   # 86 tests
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

- **No disk writes**: All data lives in memory only. Output auto-clears.
- **Memory locking**: Sensitive buffers are `mlock`'d to prevent swap.
- **Secure zeroing**: Key material is overwritten with zeros after use.
- **Contextual AAD**: The cipher ID, KDF ID, version, and flags are
  authenticated as Associated Data, preventing ciphertext reuse across contexts.
- **Versioned format**: Forward-compatible binary header enables future
  cipher additions without breaking existing ciphertexts.
- **Password hygiene**: Strong enforcement (12+ chars, mixed classes),
  interactive-only input, real-time strength feedback.

## License

MIT License

## Contributing

Contributions welcome. Please open an issue or submit a pull request.

## Contact

404securitynotfound@protonmail.ch
