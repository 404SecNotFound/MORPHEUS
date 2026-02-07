# Changelog

All notable changes to SecureDataEncryption are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [2.0.1] - 2026-02-07

### Security
- **CRITICAL**: Fixed key zeroing — `secure_zero()` now operates on actual
  key material (mutable `bytearray` throughout), not immutable copies
- **CRITICAL**: Password is now converted to `bytearray` at the API boundary
  and zeroed in `finally` blocks after use
- Fixed `secure_key` context manager yielding immutable `bytes` copy instead
  of mutable `bytearray` (the zeroed copy was discarded, not the real key)
- Added payload length validation in `decrypt()` — truncated ciphertexts now
  produce clear `ValueError` messages instead of index errors
- Added KEM ciphertext length=0 rejection to prevent hybrid PQ bypass
- Added ML-KEM-768 public/secret key size validation in CLI (1184/2400 bytes)
- Added base64 validation with `validate=True` for PQ key inputs
- Added `mlock()` failure warning via `logging.warning()` when memory locking
  fails (previously silent)
- Removed deprecated `backend=default_backend()` from Scrypt KDF
- Added `warnings.warn()` when cipher chaining silently overrides cipher choice
- Added `_libc_loaded` sentinel to prevent repeated `dlopen` attempts

### Added
- Threat Model & Limitations section in README
- Security Settings Rationale section in README (Argon2id, AES-GCM, ML-KEM-768)
- Ciphertext binary format documentation in README
- SECURITY.md with vulnerability disclosure policy
- CHANGELOG.md
- GitHub Actions CI workflow (test matrix: Python 3.10–3.13)
- NIST/RFC test vectors for AES-256-GCM and ChaCha20-Poly1305
- Edge case tests: KEM length=0 bypass, PQ key size validation, specific
  exception types (`InvalidTag` vs `ValueError`), format flag combinations
- Clipboard history limitation documented in GUI

### Fixed
- README test count updated from 86 to match actual count
- README "no disk writes" claim qualified with mlock caveat
- README hybrid PQ claim clarified as defense-in-depth, not absolute

## [2.0.0] - 2026-02-06

### Added
- Complete v2.0 rewrite with modular architecture
- Multi-cipher support: AES-256-GCM, ChaCha20-Poly1305
- Cipher chaining (AES-256-GCM -> ChaCha20-Poly1305) for defense-in-depth
- Hybrid post-quantum encryption via ML-KEM-768 (FIPS 203)
- Memory-hard KDFs: Argon2id (default) and Scrypt
- Self-describing versioned binary ciphertext format
- Textual-based terminal GUI with strength meter, auto-clear, clipboard
- Full CLI with backward compatibility
- Secure memory handling: mlock, secure zeroing, SecureBuffer
- Password strength scoring with real-time feedback
- 86 unit tests covering all components

### Changed
- Replaced monolithic script with `secure_encryption/` package
- Passwords entered interactively only (removed insecure CLI argument)

## [1.0.0] - 2024-01-01

### Added
- Initial release with basic AES encryption
- Simple CLI interface
