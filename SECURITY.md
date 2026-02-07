# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 2.0.x   | Yes       |
| < 2.0   | No        |

## Reporting a Vulnerability

If you discover a security vulnerability in SecureDataEncryption, **please
report it responsibly**. Do not open a public GitHub issue for security bugs.

### How to Report

1. **Email**: Send a detailed report to
   [404securitynotfound@protonmail.ch](mailto:404securitynotfound@protonmail.ch)
2. **Subject line**: `[SECURITY] SecureDataEncryption — <brief description>`
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

The following are in scope:

- Cryptographic weaknesses (key derivation, cipher usage, nonce handling)
- Authentication bypasses (AEAD tag manipulation, format parsing bugs)
- Memory safety issues (key material leaking to swap, inadequate zeroing)
- Information leaks (plaintext length, timing side-channels)
- Dependency vulnerabilities in `cryptography`, `argon2-cffi`, `pqcrypto`

The following are **out of scope** (documented in the Threat Model):

- Compromised endpoints (malware, keyloggers, hostile root)
- Python `str` immutability (fundamental language limitation)
- Clipboard history managers retaining data beyond our control
- Denial of service via resource exhaustion (KDF is intentionally slow)

## Security Audit History

| Date       | Scope               | Findings                              |
|------------|---------------------|---------------------------------------|
| 2026-02    | Full code review v2 | 17 findings (2 critical, 2 medium, 3 low, 3 info, 7 positive) — all remediated |

## Known Limitations

See the [Threat Model & Limitations](README.md#threat-model--limitations) section
in the README for a full list of what this tool does and does not protect against.
