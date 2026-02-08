<p align="center">
  <h1 align="center">MORPHEUS</h1>
  <p align="center">
    Quantum-resistant encryption for text and files. No data touches the disk.<br>
    <strong>AES-256-GCM + ChaCha20-Poly1305 + ML-KEM-768 | Argon2id | Terminal GUI</strong>
  </p>
  <p align="center">
    <a href="#quick-start">Quick Start</a> &middot;
    <a href="docs/USAGE.md">Full Guide</a> &middot;
    <a href="SECURITY.md">Security Policy</a> &middot;
    <a href="CHANGELOG.md">Changelog</a> &middot;
    <a href="CONTRIBUTING.md">Contributing</a>
  </p>
</p>

---

## Why MORPHEUS?

Most encryption tools make you choose: easy to use *or* cryptographically
serious. MORPHEUS does both.

It ships **post-quantum protection today** (ML-KEM-768, FIPS 203) so your data
stays safe even when large-scale quantum computers arrive. It wraps everything
in a terminal GUI that anyone can operate — no cryptography degree required.

**Three things no other open-source CLI tool does at once:**

1. **Hybrid post-quantum encryption** — password + ML-KEM-768 lattice-based KEM
2. **Cipher chaining** — AES-256-GCM *then* ChaCha20-Poly1305 with independent keys
3. **Zero-disk, auto-clear workflow** — output self-destructs in 60 seconds, clipboard wiped

## At a Glance

| | MORPHEUS | age | gpg | openssl enc |
|---|---|---|---|---|
| Post-quantum layer | ML-KEM-768 (FIPS 203) | -- | -- | -- |
| Cipher chaining | AES + ChaCha | -- | -- | -- |
| Terminal GUI | Full TUI with strength meter | -- | -- | -- |
| File encryption | Up to 100 MiB (any type) | Yes | Yes | Yes |
| Memory protection | `mlock` + `ctypes.memset` zeroing | -- | pinentry | -- |
| Self-describing format | Versioned header with AAD | Yes | Yes | -- |
| Auto-clear output | 60 s countdown + clipboard wipe | -- | -- | -- |
| KDF | Argon2id / Scrypt | scrypt | S2K | PBKDF2 |

## Quick Start

```bash
git clone https://github.com/404securitynotfound/morpheus.git
cd morpheus && pip install -r requirements.txt

# Launch the GUI
python morpheus.py

# Or encrypt from the command line
python morpheus.py -o encrypt --data "sensitive text"

# Encrypt a file
python morpheus.py -o encrypt -f secret.pdf
```

> Post-quantum support: `pip install pqcrypto`

---

## How It Works

### The 30-Second Version

1. You provide **text or a file** and a **strong password**
2. The password is stretched through **Argon2id** (memory-hard, 64 MiB, ~1 s)
   into a 256-bit key
3. Your data is encrypted with **AES-256-GCM** (authenticated encryption)
4. The output is a single **base64 string** you can store anywhere

Every encryption produces different output — even for identical inputs —
because a fresh random salt and nonce are generated each time.

### Encryption Modes

Choose your protection level:

| Mode | What Happens | Best For |
|------|-------------|----------|
| **Single cipher** | AES-256-GCM *or* ChaCha20-Poly1305 | Everyday encryption |
| **Cipher chaining** | AES-256-GCM *then* ChaCha20 with independent keys | Defense against single-algorithm compromise |
| **Hybrid PQ** | Password key + ML-KEM-768 shared secret combined via HKDF | Protection against future quantum computers |
| **Maximum** | Chaining + Hybrid PQ (all layers) | Highest assurance |

<details>
<summary><strong>How cipher chaining works under the hood</strong></summary>

Your password derives a master key via Argon2id. That master key is expanded
through HKDF into two independent 256-bit subkeys — one for AES-256-GCM, one
for ChaCha20-Poly1305. Your data is encrypted with AES first, then the AES
ciphertext is encrypted again with ChaCha. An attacker must break *both*
algorithms to recover your data.

</details>

<details>
<summary><strong>How hybrid post-quantum works under the hood</strong></summary>

```
Password ──> Argon2id ──> password_key (32 bytes)
                                |
ML-KEM-768 encapsulate ──> kem_shared_secret (32 bytes)
                                |
              HKDF(password_key || kem_shared_secret) ──> final_key
                                                            |
                                                       AES-256-GCM
```

The encryption key is derived from *both* your password *and* a lattice-based
shared secret. An attacker must break Argon2id (brute-force your password)
**and** ML-KEM-768 (solve the Learning With Errors problem). Overall security
is bounded by the strongest factor, but a weak password remains the weakest link.

</details>

---

## Using the GUI

Launch with no arguments:

```bash
python morpheus.py
```

The terminal GUI provides:

- **Encrypt / Decrypt** toggle
- **Cipher** and **KDF** dropdowns
- **Chain ciphers** and **Hybrid PQ** checkboxes
- **Multi-line text area** for input
- **Password field** with real-time strength meter
- **Auto-clearing output** with 60-second countdown
- **One-click copy** to clipboard (wiped on clear)

| Shortcut | Action |
|----------|--------|
| `Ctrl+E` | Encrypt |
| `Ctrl+D` | Decrypt |
| `Ctrl+L` | Clear all |
| `Ctrl+Q` | Quit |

---

## Using the CLI

```bash
# Interactive mode
python morpheus.py --cli

# Encrypt text
python morpheus.py -o encrypt --data "sensitive text"

# Encrypt with chaining + Scrypt
python morpheus.py -o encrypt --data "text" --chain --kdf Scrypt

# Encrypt a file (any type: text, binary, images, archives)
python morpheus.py -o encrypt -f document.pdf
# -> document.pdf.enc

# Decrypt a file (restores original filename)
python morpheus.py -o decrypt -f document.pdf.enc

# Pipe from stdin
echo "secret" | python morpheus.py -o encrypt --data -

# Generate ML-KEM-768 keypair for hybrid PQ
python morpheus.py --generate-keypair

# Hybrid PQ encrypt
python morpheus.py -o encrypt --data "text" \
  --hybrid-pq --pq-public-key <base64-pk>

# Hybrid PQ decrypt
python morpheus.py -o decrypt --data "AgEB..." \
  --hybrid-pq --pq-secret-key <base64-sk>
```

Passwords are always entered interactively — never passed as arguments —
to prevent leaking via `ps`, shell history, or `/proc`.

<details>
<summary><strong>All CLI flags</strong></summary>

| Flag | Description |
|------|-------------|
| `-o, --operation` | `encrypt` or `decrypt` |
| `-d, --data` | Text to encrypt/decrypt. Use `-` for stdin |
| `-f, --file` | File to encrypt/decrypt |
| `--output` | Explicit output path (overrides defaults) |
| `--cipher` | `AES-256-GCM` (default) or `ChaCha20-Poly1305` |
| `--kdf` | `Argon2id` (default) or `Scrypt` |
| `--chain` | Enable cipher chaining |
| `--pad` | Pad plaintext to 256-byte blocks (hides exact length) |
| `--force` | Overwrite existing output files |
| `--no-strength-check` | Skip password strength validation |
| `--hybrid-pq` | Enable hybrid post-quantum |
| `--pq-public-key` | Base64 ML-KEM-768 public key |
| `--pq-secret-key` | Base64 ML-KEM-768 secret key |
| `--generate-keypair` | Generate and print an ML-KEM-768 keypair |
| `--cli` | Force CLI mode (skip GUI) |

</details>

---

## Security Design

### What We Protect Against

| Threat | Protection |
|--------|-----------|
| Offline password brute-force | Argon2id: 64 MiB memory, ~1 s per guess |
| Future quantum computers | Hybrid ML-KEM-768 layer (FIPS 203) |
| Single-algorithm compromise | Cipher chaining (two independent algorithms) |
| Memory forensics | `mlock()` + `ctypes.memset` zeroing of all key material |
| Ciphertext tampering | AEAD authentication tag (16 bytes) |
| Algorithm downgrade | Header authenticated as AAD (v3: 18-byte binding incl. KDF params) |

### What We Do Not Protect Against

| Limitation | Why |
|-----------|-----|
| Compromised endpoint (malware, keylogger) | No user-space tool can defend against a hostile OS |
| Python `str` immutability | Password briefly exists as immutable string before `bytearray` conversion; GC timing is unpredictable |
| Clipboard history managers | We restore the previous clipboard on clear, but history extensions (Klipper, macOS Universal Clipboard) may retain copies |
| Swap without `mlock` | If `RLIMIT_MEMLOCK` is insufficient, buffers may be swapped. The tool logs a warning |

### Why These Defaults?

| Setting | Value | Rationale |
|---------|-------|-----------|
| **Argon2id** | `t=3, m=64 MiB, p=4` | OWASP 2024 minimum. Memory-hard, resists GPU/ASIC. The *id* variant resists both side-channel and brute-force |
| **AES-256-GCM** | 256-bit key, 96-bit nonce | NIST standard, AES-NI accelerated. 256-bit key gives ~128-bit post-quantum margin via Grover |
| **ChaCha20-Poly1305** | 256-bit key, 96-bit nonce | Constant-time in software, preferred without AES-NI. Same quantum margin |
| **ML-KEM-768** | FIPS 203, Category 3 | Balances post-quantum security (~AES-192) with practical key sizes. Category 5 doubles sizes for marginal gain |
| **Scrypt** | `n=2^17, r=8, p=1` | RFC 7914, ~128 MiB. Offered where Argon2 is unavailable |
| **Salt** | 16 bytes | Standard for Argon2id/Scrypt. Prevents rainbow tables |
| **Nonce** | 12 bytes | Standard for AES-GCM and ChaCha20. Random nonces safe for expected use |

---

## Ciphertext Format

The format is **self-describing** — the header tells the decryptor exactly what
algorithms were used. No out-of-band configuration needed.

### Format v3 (default for new encryptions)

```
Offset  Size  Field
------  ----  ----------------------------------
0       1     Version        (0x03)
1       1     Cipher ID      (0x01=AES-256-GCM, 0x02=ChaCha20, 0x03=Chained)
2       1     KDF ID         (0x01=Scrypt, 0x02=Argon2id)
3       1     Flags          (bit 0=chained, bit 1=hybrid PQ, bit 2=padded)
4-5     2     Reserved       (0x0000, validated on read)
6-9     4     KDF param 1    (Argon2: time_cost, Scrypt: n)
10-13   4     KDF param 2    (Argon2: memory_cost, Scrypt: r)
14-17   4     KDF param 3    (Argon2: parallelism, Scrypt: p)
18+     var   Payload
```

v3 stores KDF parameters in the header, enabling decryption without
matching the original pipeline config. It also includes an 8-byte
key-check value in the payload for clear "wrong password" diagnostics.

**v3 payload:** `[salt][nonce(s)][KEM prefix if hybrid][8B key-check][ciphertext + tag(s)]`

### Format v2 (legacy, still supported for decryption)

```
Offset  Size  Field
------  ----  ----------------------------------
0       1     Version        (0x02)
1       1     Cipher ID
2       1     KDF ID
3       1     Flags          (bit 0=chained, bit 1=hybrid PQ)
4-5     2     Reserved       (0x0000)
6+      var   Payload
```

**v2 payload:** `[salt][nonce(s)][KEM prefix if hybrid][ciphertext + tag(s)]`

All header bytes are authenticated as AAD — modifying any byte causes
decryption to fail, preventing algorithm-downgrade attacks.

---

## Testing

```bash
pip install pytest
python -m pytest tests/ -v
```

**123 tests** across 7 test files:

| File | Scope |
|------|-------|
| `test_ciphers.py` | AES-GCM + ChaCha20 roundtrips, NIST SP 800-38D TC14 vector, RFC 8439 vector, indistinguishability, wrong key/AAD/tampered data |
| `test_kdf.py` | Argon2id + Scrypt derivation, determinism, bytearray returns, salt generation |
| `test_formats.py` | Serialize/deserialize, flag combinations, version/reserved byte validation, AAD collision resistance |
| `test_pipeline.py` | All mode roundtrips (single/chained/hybrid/both), wrong password (`InvalidTag`), cross-compatibility, payload truncation, KEM length=0 bypass, header tampering |
| `test_memory.py` | `secure_zero`, `SecureBuffer`, `secure_key` context manager |
| `test_validation.py` | Password scoring (0-100), minimum requirements, edge cases |
| `test_cli.py` | File encrypt/decrypt roundtrip (text + binary), path traversal prevention |

Tests include **NIST SP 800-38D** and **RFC 8439** reference vectors verified
against the `cryptography` library's validated implementations.

---

## Project Structure

```
morpheus/
├── morpheus/
│   ├── __init__.py            # Package version
│   ├── __main__.py            # Entry point (auto-detects GUI vs CLI)
│   ├── gui.py                 # Textual TUI application
│   ├── cli.py                 # CLI with file encryption support
│   └── core/
│       ├── ciphers.py         # AES-256-GCM, ChaCha20-Poly1305
│       ├── kdf.py             # Argon2id, Scrypt
│       ├── pipeline.py        # Orchestration: chaining, hybrid PQ, key lifecycle
│       ├── formats.py         # Versioned binary format with AAD
│       ├── memory.py          # mlock, ctypes.memset zeroing, SecureBuffer
│       └── validation.py      # Password scoring, input validation
├── tests/                     # 123 tests (NIST/RFC vectors included)
├── docs/USAGE.md              # Full guide for technical and non-technical readers
├── SECURITY.md                # Vulnerability disclosure policy
├── CHANGELOG.md               # Version history
├── CONTRIBUTING.md            # Contributor guide
├── .github/workflows/ci.yml   # CI: Python 3.10-3.13 test matrix
├── pyproject.toml
├── requirements.txt
└── LICENSE                    # MIT
```

## Requirements

| Package | Purpose | Required |
|---------|---------|----------|
| `cryptography` | AES-GCM, ChaCha20, Scrypt, HKDF | Yes |
| `argon2-cffi` | Argon2id key derivation | Yes |
| `textual` | Terminal GUI framework | Yes |
| `pyperclip` | Clipboard access (Linux: requires `xclip` or `xsel`) | Yes |
| `pqcrypto` | ML-KEM-768 post-quantum KEM (community binding to liboqs, not FIPS-validated) | Optional |

Python 3.10+

> **Linux clipboard**: Install `xclip` or `xsel` for clipboard support: `sudo apt install xclip`

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. We welcome:
- Bug reports and security disclosures (see [SECURITY.md](SECURITY.md))
- New cipher or KDF implementations
- Documentation improvements
- Test coverage expansion

## Disclaimer

MORPHEUS is provided **as-is** for educational and personal use. It has not
undergone formal FIPS 140-3 validation or independent third-party audit.
**Do not rely on it as your sole protection** for data subject to legal,
regulatory, or compliance requirements (HIPAA, GDPR, PCI-DSS, etc.).

The authors are not responsible for data loss, unauthorized disclosure, or
any damages resulting from the use of this software. **There is no password
recovery mechanism** — if you forget your password, your data is permanently
and irrecoverably lost.

Use of cryptographic software may be restricted or regulated in some
jurisdictions. You are responsible for compliance with all applicable laws.

## Privacy Notes

- **No telemetry or analytics**: MORPHEUS does not phone home, collect usage
  data, or make any network connections.
- **No data on disk**: Text-mode operations are entirely in-memory. File
  encryption writes only the ciphertext output.
- **Plaintext length**: Without `--pad`, ciphertext length reveals approximate
  plaintext length. Use `--pad` for length-hiding when privacy requires it.
- **Ciphertext is identifiable**: The versioned header (0x02/0x03) makes
  MORPHEUS ciphertexts recognizable. This tool does not provide plausible
  deniability or steganography — it is designed for **confidentiality**, not
  **undetectability**.
- **Password as signal**: A strong password (high entropy) may itself signal
  security awareness to an observer. This is inherent to password-based
  encryption.

## License

[MIT](LICENSE)

## Contact

404securitynotfound@protonmail.ch
