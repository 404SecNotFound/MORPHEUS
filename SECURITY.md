# Security Policy

## Supported Versions

| Version | Supported          |
|---------|--------------------|
| 2.0.x   | Yes                |
| < 2.0   | No                 |

## Reporting a Vulnerability

If you discover a security vulnerability in MORPHEUS, **please
report it responsibly**. Do not open a public GitHub issue for security bugs.

### How to Report

1. **Email**: Send a detailed report to
   [404securitynotfound@protonmail.ch](mailto:404securitynotfound@protonmail.ch)
2. **Subject line**: `[SECURITY] MORPHEUS — <brief description>`
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected version(s)
   - Impact assessment (what an attacker could achieve)
   - Suggested fix (if you have one)

### What to Expect

- **Acknowledgement** within 48 hours
- **Status update** within 7 days
- **Fix or mitigation** for confirmed vulnerabilities within 30 days
- Credit in the changelog and release notes (unless you prefer anonymity)

### Scope

The following are **in scope**:

- Cryptographic weaknesses (key derivation, cipher usage, nonce handling)
- Authentication bypasses (AEAD tag manipulation, format parsing bugs)
- Memory safety issues (key material leaking to swap, inadequate zeroing)
- Information leaks (plaintext length, timing side-channels)
- Key material lifecycle issues (shared secrets not zeroed, intermediate leaks)
- Format vulnerabilities (header downgrade, reserved byte manipulation)
- Dependency vulnerabilities in `cryptography`, `argon2-cffi`, `pqcrypto`

The following are **out of scope** (documented in the Threat Model):

- Compromised endpoints (malware, keyloggers, hostile root)
- Python `str` immutability (fundamental language limitation)
- Clipboard history managers retaining data beyond our control
- Denial of service via resource exhaustion (KDF is intentionally slow)

## Security Audit History

| Date       | Scope                          | Findings                              |
|------------|--------------------------------|---------------------------------------|
| 2026-02-06 | Full code review (v2.0)        | 17 findings (2 critical, 2 medium, 3 low, 3 info, 7 positive) — all remediated |
| 2026-02-07 | Cryptographic deep review      | 7 findings (2 high, 3 medium, 2 low) — all remediated |
| 2026-02-08 | External review + independent audit | 4 external findings + 21 audit findings — remediated in v2.0.2 |
| 2026-02-08 | Privacy/crypto/ethics review + security hardening | 12 findings (4 crypto, 5 privacy, 3 ethical) + 6 hardening findings — remediated in v2.0.3 |

### Remediation Summary (v2.0.1)

**Review 1** — Full code review of v2.0 architecture:
- [CRITICAL] `secure_zero()` operated on immutable copies, not actual key material
- [CRITICAL] Password remained as immutable `str` through the pipeline
- [MEDIUM] `secure_key` context manager yielded immutable `bytes` copy
- [MEDIUM] Payload length not validated before slicing (index errors)
- All key paths now use mutable `bytearray` with `ctypes.memset` zeroing

**Review 2** — Cryptographic deep review by domain expert:
- [HIGH] KEM shared secret (`kem_ss`) was never zeroed after HKDF combination
- [HIGH] `_combine_with_kem` leaked concatenated key material as immutable `bytes`
- [MEDIUM] Reserved header bytes (4-5) excluded from AAD, not validated
- [MEDIUM] HKDF info strings lacked application-specific domain separation
- [MEDIUM] No file encryption capability
- [LOW] `secure_zero` used Python byte-by-byte loop instead of `ctypes.memset`
- [LOW] KEM ciphertext length=0 not rejected (potential PQ bypass)

## Cryptographic Primitives

| Primitive | Standard | Implementation |
|-----------|----------|----------------|
| AES-256-GCM | NIST SP 800-38D | `cryptography` (OpenSSL) |
| ChaCha20-Poly1305 | RFC 8439 | `cryptography` (OpenSSL) |
| Argon2id | RFC 9106, OWASP 2024 | `argon2-cffi` |
| Scrypt | RFC 7914 | `cryptography` (OpenSSL) |
| HKDF-SHA256 | RFC 5869 | `cryptography` |
| ML-KEM-768 | FIPS 203 | `pqcrypto` (optional) |

## Known Limitations

### Immutable `bytes` copies at library boundaries

The pipeline manages all key material as mutable `bytearray` buffers and
zeroes them via `ctypes.memset` after use. However, several underlying
library APIs require immutable `bytes` arguments, creating short-lived
copies that **cannot be zeroed** by the application:

| Call site | Library API | Copy created |
|-----------|------------|--------------|
| `Argon2idKDF.derive()` | `hash_secret_raw(secret=bytes(...))` | Password copy |
| `ScryptKDF.derive()` | `Scrypt.derive(bytes(...))` | Password copy |
| `AES256GCM.encrypt/decrypt()` | `AESGCM(bytes(key))` | Key copy |
| `ChaCha20Poly1305Cipher.encrypt/decrypt()` | `ChaCha20Poly1305(bytes(key))` | Key copy |
| `_derive_keys()` | `HKDFExpand.derive(bytes(master))` | Master key copy |

These copies persist on the Python heap until garbage collection. This is a
fundamental limitation of Python and the `cryptography` library's API design.
For absolute memory safety, a C or Rust implementation operating directly on
mutable buffers would be required.

### ML-KEM-768 implementation provenance

The ML-KEM-768 post-quantum layer is provided by the `pqcrypto` community
package, which binds to `liboqs` (Open Quantum Safe). This implementation:

- Has **not** undergone FIPS 140-3 validation
- Has **not** been independently audited by a third party
- Is maintained by a small open-source community

The hybrid design ensures that overall security is **never weaker** than the
password-based symmetric layer alone. ML-KEM-768 is an additional
defense-in-depth layer, not the sole protection mechanism.

### Key-check oracle (v3 format, intentional design)

Format v3 includes an 8-byte key-check value: `HMAC-SHA256(key, "morpheus-key-check")[:8]`.
This is verified **before** attempting AEAD decryption, providing a clear
"incorrect password" error instead of a generic `InvalidTag`.

**Security implications**: The key-check creates a distinguishing oracle —
an attacker can tell whether a password guess is wrong (key-check mismatch)
vs. whether the ciphertext is tampered (AEAD failure). This is an intentional
UX tradeoff:

- **Brute-force impact**: Negligible. The key-check is computed from the
  KDF-derived key, so an attacker must still complete the full KDF
  computation for each guess. The key-check adds no shortcut.
- **Truncation**: 8 bytes (64 bits) provides 2^{-64} false-positive rate —
  effectively zero for password-checking purposes.
- **Information leakage**: Reveals only pass/fail, same as any AEAD scheme.
  The truncated HMAC is a PRF output and does not leak key material.

For deployments requiring indistinguishable error behavior (e.g., plausible
deniability use cases), v2 format can be used — it returns `InvalidTag`
for both wrong password and tampering.

### File envelope metadata

When encrypting files, the encrypted envelope includes the original filename
(basename only) by default. This is encrypted alongside the file data, so it
is not visible without the password. However, once decrypted, the filename
is revealed. Use `--no-filename` to omit the original filename from the
envelope for maximum privacy.

### Padding and length hiding

The `--pad` flag pads plaintext to discrete size buckets (256B, 1K, 4K, 16K,
64K, then 64K multiples). This hides the exact plaintext length but still
reveals which bucket the data falls into.

For maximum privacy, the `--fixed-size` flag pads all ciphertexts to exactly
64 KiB regardless of input length. This eliminates length-based traffic
analysis entirely — all messages are indistinguishable by size. Inputs larger
than ~64 KiB cannot use fixed-size mode (use `--pad` instead).

### Breach detection (`--check-leaks`)

The `--check-leaks` flag uses the [Have I Been Pwned](https://haveibeenpwned.com/)
Pwned Passwords API with **k-anonymity**:

1. Your password is SHA-1 hashed locally
2. Only the **first 5 characters** of the hash (out of 40) are sent to the API
3. The API returns all hash suffixes matching that prefix (~500 results)
4. Your client checks locally whether your full hash is in the returned set

**Privacy**: The actual password never leaves your machine. The 5-character
prefix maps to ~10 million possible passwords, providing strong k-anonymity.
The API operator cannot determine which password you checked.

**Network**: This is the only feature that makes network connections. It is
strictly **opt-in** — never enabled by default. If the network is unavailable,
encryption proceeds with a warning.

### Passphrase mode (`--passphrase`)

Standard password validation requires mixed character classes (uppercase,
lowercase, digits, special characters). The `--passphrase` flag switches
to word-based validation instead:

- Requires at least **4 words** separated by spaces, hyphens, or underscores
- Requires at least **20 characters** total length
- Does **not** require digits, uppercase, or special characters
- Scores based on word count, uniqueness, and average word length

This accepts high-entropy passwords like `correct horse battery staple` that
the standard checker would reject. The entropy of a 4-word passphrase from
a 7776-word diceware list is ~51 bits; 6 words yields ~77 bits.

### Persistent preferences (`~/.morpheus/config.toml`)

The `--save-config` flag writes user preferences to `~/.morpheus/config.toml`
with file permissions `0600` (owner read/write only). The config file stores
only non-sensitive settings (cipher choice, KDF choice, boolean flags). It
never stores passwords, keys, or ciphertext.

CLI arguments always override saved preferences. The config is loaded at
startup and applied as defaults only for unset arguments.

### GCM nonce collision probability

AES-256-GCM uses a random 96-bit nonce. Under the birthday bound, the
probability of a nonce collision reaches 2^{-32} (~1 in 4 billion) after
approximately 2^{32} encryptions with the same key. Since each encryption
in MORPHEUS uses a fresh random salt (producing a unique derived key), the
effective nonce space resets per message. A collision only matters if the
**same derived key** is reused with the **same nonce**, which requires
both the same password AND the same salt — a probability of 2^{-128}.

**Bottom line**: For the expected use case (interactive encryption of individual
messages/files), nonce collision risk is negligible. If you need to encrypt
more than ~4 billion messages with the same password, use cipher chaining
or a different nonce scheme.

### Additional limitations

See the [Security Design](README.md#security-design) section in the README
for the full threat model, including what this tool does and does not protect
against.
