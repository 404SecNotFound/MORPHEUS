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

See the [Security Design](README.md#security-design) section in the README
for the full threat model, including what this tool does and does not protect
against.
