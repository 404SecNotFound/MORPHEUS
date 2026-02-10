# Changelog

All notable changes to MORPHEUS are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [2.1.0] - 2026-02-10

### Changed
- **Wizard GUI overhaul**: Replaced the single-page scrollable form with a
  6-step guided wizard (Mode → Settings → Input → Password → Review → Output).
  2-pane layout: left sidebar with step completion markers (✓ done, ▸ current,
  dim locked) and right panel for the active step
- **Professional dark theme**: New palette — `#0F1115` background, `#5B8CFF`
  accent, muted greens/ambers/reds. Replaces the neon color scheme
- **Clipboard robustness**: Copy now uses Textual OSC 52 (terminal-native) as
  primary method, with pyperclip and subprocess (xclip/xsel/wl-copy) fallbacks.
  Paste buttons added to both password fields for password-manager workflows
- **Step validation**: Next button disabled until the current step is valid;
  Review step summarises all choices and shows password-strength warnings before
  the Run action
- **New shortcuts**: `←/→` switch steps, `Esc` returns to sidebar, `F1` shows
  help overlay. Existing `Ctrl+E/D/L/Q` shortcuts preserved
- **New `ui/` package**: `theme.py`, `state.py`, `sidebar.py`, `app.py`,
  `steps/` — decoupled from crypto core
- Test count: 241 → 266 (25 state-validation + 10 wizard integration tests)

## [2.0.6] - 2026-02-10

### Added
- **`--inspect` command**: Examine ciphertext metadata without decrypting —
  shows format version, cipher, KDF (with params), flags, payload/overhead
  sizes, and actionable notes. No password required. Works with `--data` or
  `--file` input
- **Progress feedback**: KDF derivation and encrypt/decrypt now print status
  messages to stderr (e.g., "Deriving key (Argon2id)...") so users know
  the tool is working during slow KDF computation
- **Intelligent error diagnosis**: Decryption failures now include actionable
  suggestions based on error type — wrong password hints, truncation advice,
  PQ key requirements, format mismatch guidance
- **Padding advisor**: After encryption, a one-line hint recommends `--pad`
  or `--fixed-size` if no padding was used; when padding is active, shows
  which size bucket was selected
- Test count: 222 -> 241

## [2.0.5] - 2026-02-10

### Added
- **`--passphrase` mode**: Word-based password validation that evaluates
  passphrases by word count (4+) and total length (20+) instead of requiring
  digits/uppercase/special characters. Accepts `correct horse battery staple`
  style passwords that the standard checker would reject
- **`--check-leaks` flag**: Opt-in breach detection via Have I Been Pwned
  k-anonymity API. Only the first 5 characters of the SHA-1 hash are sent;
  the full password never leaves the machine. Blocks encryption if the
  password appears in known breaches; gracefully degrades on network failure
- **`--save-config` and persistent preferences**: Saves preferred cipher, KDF,
  and flag settings to `~/.morpheus/config.toml` (mode 0600). Loaded
  automatically on startup; CLI arguments always override saved preferences
- Test count: 191 -> 222

## [2.0.4] - 2026-02-10

### Added
- **`--benchmark` command**: Times cipher and KDF performance on current hardware,
  recommends optimal cipher (AES-256-GCM vs ChaCha20-Poly1305 based on AES-NI
  availability) and KDF tuning (Argon2id time_cost guidance)
- **`--fixed-size` flag**: Constant-size 64 KiB padding for maximum privacy —
  all ciphertexts are identical length regardless of input size
- **Rich decryption error context**: Failed decryptions now display parsed
  ciphertext header details (format version, cipher, KDF with params, flags)
  in both CLI and GUI, replacing generic "incorrect password" messages
- **Structured error types** (`morpheus.core.errors`): `FormatError`,
  `PaddingError`, `KDFParameterError`, `ConfigurationError`, `DecryptionError`,
  `WrongPasswordError` — all inherit from `ValueError` for backward compat
- Formal padding invariant proof documented in `_pad_plaintext()` docstring
- Test count: 185 -> 191

### Changed
- Padding bucket mode now uses exponential buckets (256B, 1K, 4K, 16K, 64K)
  instead of fixed 256-byte blocks for stronger length hiding
- `--pad` flag description updated to reflect bucket mode behavior

## [2.0.2] - 2026-02-08

### Security
- **HIGH**: Fixed path traversal vulnerability in file decryption — malicious
  envelope filenames (e.g., `../../.ssh/authorized_keys`) are now sanitized
  via `os.path.basename()` before writing output
- **MEDIUM**: Fixed CLI password reading when stdin is consumed by `--data -`.
  Now uses `getpass.getpass()` which opens `/dev/tty` directly on Unix,
  preventing empty/missing passwords when piping data

### Fixed
- Documentation vs. implementation mismatch for hybrid PQ payload layout:
  docs incorrectly stated KEM prefix appears before nonces; corrected to
  show actual layout (salt → nonce(s) → KEM prefix → ciphertext)
- Decryption error messages now hint at KDF parameter mismatch as a possible
  cause when authentication fails with correct password
- Test count: 122 -> 123 (added path traversal prevention test)

### Changed
- Version bumped to 2.0.2

## [2.0.1] - 2026-02-07

### Security
- **HIGH**: KEM shared secret (`kem_ss`) now wrapped in `bytearray` and zeroed
  via `secure_zero()` after HKDF combination — previously leaked in memory
- **HIGH**: `_combine_with_kem()` now uses mutable `bytearray` for the
  concatenated intermediate and zeros it in a `finally` block
- **CRITICAL**: `secure_zero()` now operates on actual key material (mutable
  `bytearray` throughout), not immutable copies
- **CRITICAL**: Password is now converted to `bytearray` at the API boundary
  and zeroed in `finally` blocks after use
- Fixed `secure_key` context manager yielding immutable `bytes` copy instead
  of mutable `bytearray`
- Added payload length validation in `decrypt()` — truncated ciphertexts now
  produce clear `ValueError` messages instead of index errors
- Added KEM ciphertext length=0 rejection to prevent hybrid PQ bypass
- Added ML-KEM-768 public/secret key size validation in CLI (1184/2400 bytes)
- Added base64 validation with `validate=True` for PQ key inputs
- Reserved header bytes (4-5) now included in AAD and validated on read
- HKDF info strings now include application-specific domain separation
  (`morpheus-v2-key-{i}` + salt binding)
- `secure_zero()` now uses `ctypes.memset` with Python fallback
- Added `mlock()` failure warning via `logging.warning()`
- Removed deprecated `backend=default_backend()` from Scrypt KDF
- Added `warnings.warn()` when cipher chaining silently overrides cipher choice

### Added
- File encryption via `-f/--file` flag (any file type, up to 100 MiB)
- `--output` flag for explicit output file paths
- JSON envelope format preserving original filenames during file encryption
- NIST SP 800-38D TC14 test vector for AES-256-GCM
- RFC 8439 Section 2.8.2 test vector for ChaCha20-Poly1305
- Ciphertext indistinguishability tests
- Edge case tests: KEM length=0 bypass, unknown cipher ID, header tampering,
  payload truncation, format flag combinations, AAD collision resistance
- File encryption roundtrip tests (text and binary)
- SECURITY.md with vulnerability disclosure policy and audit history
- CHANGELOG.md
- CONTRIBUTING.md
- GitHub Actions CI workflow (test matrix: Python 3.10-3.13)
- Full usage guide at docs/USAGE.md

### Fixed
- README: Corrected test count, qualified no-disk-writes claim with mlock
  caveat, clarified hybrid PQ as defense-in-depth
- README: Complete rewrite with competitive comparison, streamlined structure
- docs/USAGE.md: Added file encryption section, corrected all test counts,
  removed stale "not designed for binary files" claim

### Changed
- Test count: 86 -> 122 (across 7 test files)
- AAD now authenticates full 6-byte header (was 4 bytes)
- `build_aad()` returns `struct.pack(HEADER_FORMAT, ...)` instead of
  partial header
- Version bumped to 2.0.1

## [2.0.0] - 2026-02-06

### Added
- Complete v2.0 rewrite with modular architecture
- Multi-cipher support: AES-256-GCM, ChaCha20-Poly1305
- Cipher chaining (AES-256-GCM -> ChaCha20-Poly1305) for defense-in-depth
- Hybrid post-quantum encryption via ML-KEM-768 (FIPS 203)
- Memory-hard KDFs: Argon2id (default) and Scrypt
- Self-describing versioned binary ciphertext format with AAD
- Textual-based terminal GUI with strength meter, auto-clear, clipboard
- Full CLI with backward compatibility
- Secure memory handling: mlock, secure zeroing, SecureBuffer
- Password strength scoring with real-time feedback
- 86 unit tests covering all components

### Changed
- Replaced monolithic script with `morpheus/` package
- Passwords entered interactively only (removed insecure CLI argument)

## [1.0.0] - 2024-01-01

### Added
- Initial release with basic AES encryption
- Simple CLI interface
