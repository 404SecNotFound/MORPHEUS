# Changelog

All notable changes to MORPHEUS are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

Findings from the pre-publication UAT programme. Defect IDs refer to that
programme's register.

### Added
- **`--version`** prints the version and exits (DEF-002). It previously exited
  2 with "unrecognized arguments", which is the first thing an issue reporter
  is asked to supply. A test pins the reported string to the packaged version,
  so the two cannot drift apart unnoticed.

### Changed
- **Hybrid post-quantum is now command-line only** (DEF-006). The wizard
  offered a "Hybrid Post-Quantum" checkbox while having no keypair generation,
  no key entry and no key display, so ticking it walked the user through four
  more steps, took a password and a confirmation, and then failed out of the
  pipeline. The control is gone and the Settings step signposts
  `--generate-keypair` and `--hybrid-pq` instead.
- `docs/USAGE.md` no longer tells GUI users to click a "Generate Keypair"
  button. No such button ever existed.

### Fixed
- **`--hybrid-pq` without `pqcrypto` is refused at parse time** (DEF-001).
  It used to prompt for a password, ask again to confirm it, and only then
  report the missing package. Availability is known from argv, so the prompt
  was wasted work on the documented first-contact path.
- **The wizard refuses invalid cipher combinations at the Settings step**
  (DEF-005), where the choice is made, rather than after a password has been
  typed and confirmed. A sweep of all 64 reachable Settings combinations found
  40 that the wizard accepted and the engine then rejected; a regression test
  sweeps the same space and fails if any accepted combination cannot be built.

### Documentation
- Corrected the test count in `README.md` and `CONTRIBUTING.md`, which still
  said 308.
- **`SECURITY.md`'s unzeroable-copy table was incomplete** (DEF-007). Its
  *Known Limitations* section enumerates the library boundaries where key
  material is copied into an immutable `bytes` that cannot be zeroed, and read
  as exhaustive while omitting `_combine_with_kem()` — the hybrid PQ path,
  holding the password key concatenated with the ML-KEM shared secret. No
  behaviour change and no new weakness: that buffer's mutable `bytearray` is
  zeroed correctly, and the immutable copies are the same documented Python
  limitation as the five sites already listed. The table now names all six.

### Security
- **CI actions are pinned to commit SHAs** instead of floating major tags.
  `actions/checkout@v4` and `actions/setup-python@v5` resolved to whatever
  those tags pointed at on the day a job ran, so a compromised or retagged
  release would have entered CI silently. All 8 references now pin a SHA with
  the version in a trailing comment.
- **Dependabot enabled** for GitHub Actions and pip. Pinning without something
  raising the pins deliberately just rots into running a version with known
  advisories; Dependabot rewrites the SHA and its version comment together so
  the two cannot drift. Dev tooling is grouped into one PR, while
  `cryptography`, `argon2-cffi` and `pqcrypto` stay ungrouped so each is
  reviewed on its own merits.
- **CodeQL static analysis added**, running on push, pull request and weekly,
  with the `security-extended` query suite. Weekly matters because it catches
  an old commit with a newly published query. Note this is the advanced
  workflow setup and conflicts with GitHub's default setup if that is ever
  enabled. Code scanning is free on public repositories; while this repository
  is private the runs require GitHub Advanced Security and will fail without
  it.

## [2.1.0] - 2026-02-10

### Documentation
- **Corrected three security claims that the code does not implement.** A
  pre-publication review found the README and USAGE describing protections that
  were never wired into the encrypt/decrypt path. Earlier changelog entries
  (2.0.0, 2.0.1) still mention these as shipped; they describe the intent at the
  time, not current behaviour. Specifically:
  - **Memory locking**: `mlock_buffer`, `SecureBuffer`, and `secure_key` exist in
    `core/memory.py` but have no call sites in the pipeline. Key buffers are
    zeroed with `ctypes.memset`, and are **not** `mlock`ed. The documented
    "logs a warning on `RLIMIT_MEMLOCK` failure" behaviour cannot occur. Docs now
    say best-effort zeroing only.
  - **Clipboard wiping**: no clipboard-clearing code exists. Docs no longer claim
    the clipboard is wiped or the previous value restored.
  - **"No data touches the disk"**: the TUI writes a temporary file when no
    clipboard backend is available. Replaced with a per-path table of exactly what
    is written to disk.
- Corrected the documented `--cli` flag, which does not exist. Passing any flag
  runs the CLI; no arguments launches the GUI.
- Corrected test counts and the `Argon2id ~1 s per guess` figure, which measured
  at roughly 30 ms. The brute-force defence is memory-hardness (64 MiB per guess),
  not wall-clock time, and the docs now say so.

### Fixed
- `import tkinter` in `ui/clipboard.py` is now guarded. It was unconditional, so
  the GUI failed to start on any Python built without Tk (Homebrew, slim Docker
  images, Debian without `python3-tk`) and the collection error aborted the whole
  test suite.
- **Password-strength labels now agree across the app, and the weakest band is
  named.** The threshold ladder was duplicated: the wizard's strength bar had
  five bands and called anything under 20 "Very weak", while
  `check_password_strength` had four and called the same password "Weak". One
  password therefore read differently on the password step and the review step.
  `validation.strength_label()` is now the single owner and every caller uses
  it. **CLI-visible:** `morpheus encrypt` with a password scoring under 20 now
  reports `too weak (Very weak)` where it previously said `too weak (Weak)`.
  Only the label changed; the score, the acceptance threshold and the exit code
  are untouched, so nothing that passed before now fails. The disagreement had
  been masked by colour until both sub-40 bands were restyled to the same red,
  which left the label as the only thing separating them.

### Changed
- **Wizard GUI overhaul**: Replaced the single-page scrollable form with a
  6-step guided wizard (Mode → Settings → Input → Password → Review → Output).
  2-pane layout: left sidebar with step markers (`[+]` done, `[>]` current,
  step number when still locked) and right panel for the active step. A locked
  step renders at `TEXT_3`, not a dimmed tier — it is keyboard-focusable and
  carries a name and description, so it has to stay above AA
- **Terminal visual system**: Warm-graphite palette replacing the Matrix
  black-and-green theme. Amber `#f4b23e` is reserved for exposed secret
  material and marks exactly three places: the output pane while it holds
  ciphertext or plaintext, that pane's auto-clear countdown, and a password
  field the user has chosen to unmask. Selection and focus use near-white
  `#ecebe6`; text runs in tiers so data reads brighter than chrome. Every token
  used for text clears WCAG AA against the background, verified by
  `tests/test_theme.py` and re-runnable via `scripts/check_contrast.py`. See
  `docs/design/2026-07-28-terminal-visual-system.md`.
- **Clipboard robustness**: Copy tries pyperclip first, then the system
  utilities (xclip/xsel/wl-copy/pbcopy), then tkinter. Paste buttons added to
  both password fields for password-manager workflows. MORPHEUS does not clear
  the system clipboard afterwards
- **Step validation**: Next button disabled until the current step is valid;
  Review step summarises all choices and shows password-strength warnings before
  the Run action
- **New shortcuts**: `←/→` switch steps, `Esc` returns to sidebar, `F1` shows
  help overlay. Existing `Ctrl+E/D/L/Q` shortcuts preserved
- **New `ui/` package**: `theme.py`, `state.py`, `sidebar.py`, `app.py`,
  `steps/` — decoupled from crypto core
- Test count: 241 → 308 (state-validation, wizard integration, clipboard
  fallback, and palette/contrast tests)

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
