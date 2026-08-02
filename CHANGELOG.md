# Changelog

All notable changes to MORPHEUS are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/).

## [2.2.0] - 2026-08-02

### Security

Response to the end-to-end security review of 2026-08-02. Thirteen of sixteen
findings closed. No ciphertext format change: everything v2.1.0 and earlier
produced still decrypts.

- **Wizard results can no longer describe inputs they never used.** The worker
  read live state and stamped the result against the state as it was on
  completion, so changing the password mid-run produced a ciphertext under the
  old password, marked as current. Execute now freezes an immutable request and
  publishes only if the inputs still match it. (F-01)
- **The wizard enforces the CLI's password policy.** It previously accepted a
  one-character password for encryption while the CLI refused it. Decryption is
  unaffected, so existing ciphertexts stay openable, and the CLI's two
  overrides gained wizard equivalents. (F-02)
- **Encrypt and decrypt have separate size ceilings.** One 100 MiB limit applied
  to plaintext going in and to base64 ciphertext coming back, so files above
  ~56 MiB encrypted and were then refused for decryption. (F-04)
- **Wizard file decryption restores the file.** It returned the internal
  transport envelope as text instead of writing the recovered bytes. (F-05)
- **Keypair generation no longer follows a symlink at the `.pub` path**, which
  allowed an arbitrary-file overwrite that exited successfully. (F-06)
- **The envelope parser is strict.** Recognition now requires the whole schema,
  so ordinary JSON containing a `data` key is returned as plaintext rather than
  unpacked over the user's document, and base64 is validated. (F-07)
- **Filenames from third-party ciphertexts are sanitised** of control
  characters, both separator styles and reserved device names, and are printed
  escaped. (F-08)
- **Auto-clear survives leaving the Output step.** The timer belonged to the
  widget, so navigating away left the plaintext in memory indefinitely. (F-09)
- **KDF cost from an unauthenticated header is bounded.** Memory was capped but
  the product was not, so a hostile ciphertext could demand minutes of CPU
  before authenticity could be checked. `--allow-expensive-kdf` opts back in.
  (F-10)
- **Password and KEM buffers are wiped on every decrypt error path**, not only
  on the paths that reached the inner cleanup scope. (F-11)
- **A hung clipboard helper is killed and reaped** instead of being left
  running with the plaintext. (F-14)
- **Output writes are atomic.** Temporary file in the destination directory,
  fsync, rename, fsync the directory, so an interrupted run cannot leave a
  partial result and `--force` cannot destroy the old file without producing
  the new. (F-15)

### Added

- `--allow-expensive-kdf`, to decrypt ciphertexts whose headers ask for
  unusually costly KDF settings.
- Passphrase mode and an explicit strength-check override in the wizard,
  matching `--passphrase` and `--no-strength-check`.

### Fixed

- `--fixed-size` is documented as what it does: it pads the plaintext to 64 KiB
  and produces an 87,508-character base64 output in default mode, not a 64 KiB
  ciphertext. (F-13)
- Hybrid post-quantum is documented as a second factor rather than
  recipient-only encryption. The ML-KEM secret key alone does not decrypt; the
  sender's password is required as well. (F-03)
- The source distribution ships `tests/vectors/*.json` and `tests/support.py`,
  so the compatibility vectors can be run from the archive. CI now installs
  each built artifact into a clean environment and tests that, rather than
  only testing the checkout. (F-12)

### Known limitations

- File handling still buffers whole files in both interfaces; streaming is
  planned for the next format version. (F-16, partial)
- There is no recipient-only post-quantum mode. `--hybrid-pq` is two-factor.

## [Unreleased]

Findings from the pre-publication UAT programme. Defect IDs refer to that
programme's register.

### Added
- **Ciphertext format v4**, now the default. v2 and v3 still decrypt. Three
  changes, each traced to published guidance:
  - The key check becomes a real **32-byte key commitment** (~128-bit
    committing security, against ~32 for v3's 8-byte value by the size relation
    in Bellare–Hoang, CRYPTO 2024). Neither AES-GCM nor ChaCha20-Poly1305
    commits, and RFC 9771 §4.3.3 names password-based encryption as an
    application that needs it. It binds **key material only** — both subkeys
    when chained — because the AEAD tag already authenticates the nonce, header,
    salt and KEM ciphertext. Binding those here as well would collapse
    tampering into "incorrect password", which is exactly what an adversarial
    review caught in the first draft of this change.
  - The **hybrid combiner binds the KEM ciphertext, encapsulation key and AAD**.
    v3's `HKDF(salt, pw_key ‖ ss, "hybrid-pq-v1")` is verbatim the construction
    NIST SP 800-227 §4.6.3 (final, September 2025) says does not preserve
    IND-CCA security regardless of the KDF. The encapsulation key costs zero
    wire bytes: ML-KEM-768 embeds it in the secret key.
  - **AAD extended over the salt and KEM ciphertext**, which in v3 sat in the
    payload outside the tag.

  There was no live attack on v3 — this tool is offline with no decapsulation
  oracle. The reasons to change were conformance, and that zero release tags
  meant the break was free exactly once.

  Not fixed, and not claimed: salt or KEM-ciphertext tampering is detected but
  still reports as a wrong password, because altering either changes the derived
  key.
- **Known-answer test vectors** for v3 and v4 in `tests/vectors/`. None existed;
  every crypto test round-tripped in-process, so any rename of an HKDF label or
  reorder of a payload field would have kept the suite green while making every
  archived ciphertext undecryptable. The v3 vectors were generated *before* the
  v4 work and are what proves v3 still decrypts.
- **A declared minimum terminal of 100x30**, with a "terminal too small" screen
  below it naming both the requirement and the current size. Every TUI test ran
  at 120x50 and the screenshots at 110x40, so nothing exercised a small
  terminal, and at the standard 80x24 default the sidebar dropped step 6 and the
  labels truncated. Nothing was unreachable, which is why it read as cramped
  rather than broken and survived this long.

  Implemented as an overlay on its own CSS layer, not a pushed screen: the
  wizard stays mounted underneath, so shrinking the window and restoring it
  loses neither input nor a finished result. That is the derived-staleness
  property from the S5 fix restated for a new trigger — resizing is not a user
  edit. The nav buttons are disabled while the overlay is up, because the wizard
  below still holds the keyboard and Execute's outcome lands in a pane the user
  cannot see. Seven tests, two of them mutation-proven, including the
  resize-down-and-back round trip.

  One bug found while building it, worth recording because it would have shipped
  as "the warning only appears if you resize twice": inside `on_resize`,
  `self.size` still reports the *previous* dimensions. The handler now takes the
  size off the event.
- **`--dice-entropy`**, which reports how much entropy a number of fair dice
  rolls carries, against a 128-bit floor and a 256-bit target, and exits 1 when
  short so a script can gate on it. `--dice-sides` covers coins and other dice.

  Prompted by the COLDCARD disclosure of 2026-07-30: a firmware bug routed seed
  generation through MicroPython's software PRNG rather than the device's
  hardware RNG, leaving Mk3 seeds at roughly 40 bits of effective search space
  against an intended 128, and Mk4/Q/Mk5 at roughly 72. Around 594 BTC moved in
  a 25-minute sweep. Users who had added at least 50 private dice rolls were not
  considered at risk, because the firmware hashed those rolls in alongside the
  device's output. Physical dice survived a total failure of the vendor's
  generator, which is the argument for counting them properly.

  **It takes a count, never the rolls**, generates nothing and stores nothing. A
  test asserts the output contains no hex blob, no base64 payload and no mention
  of seeds or mnemonics, because a tool that accepted the sequence would be
  asking the user to type key material into a networked computer — the exact
  thing a dice procedure exists to avoid. Seed generation belongs on an
  air-gapped device and deliberately does not live here.

  Two details worth recording. `math.ceil(target / bits_per_roll)` is the obvious
  implementation of "how many rolls do I need" and it is wrong: the product and
  the quotient do not round-trip in binary floating point, so asking for exactly
  the bits that *n* rolls produce returns n+1. Measured across d2 to d64 over the
  first 400 roll counts, plain ceil errs on 1205 of them, including d6 at 50 and
  100 rolls — the two figures from the advisory. Every error demands a roll
  nobody needs, in a procedure tedious enough that a spurious instruction is one
  a person ignores. And the output reports 99 d6 rolls as 255.9 bits rather than
  the advisory's "approximately 256", because this prints measured figures and a
  reader holding both documents should find the 0.09-bit gap explained rather
  than rounded into agreement.
- **A release workflow**, tag-driven, publishing to PyPI over **Trusted
  Publishing (OIDC)**. No API token exists in this repository, in an environment
  variable, or on a laptop: GitHub mints a short-lived identity token per run and
  PyPI verifies it against the publisher configured for this repository. A
  long-lived token was the single recorded objection to publishing at all, and it
  stopped applying once the repo went public and Actions started working, since
  OIDC needs both.

  The distributions are built once and every later job consumes that artefact, so
  what is verified is what is published. Before anything is uploaded the job runs
  the full suite, `twine check`, and three assertions: the tag matches the
  packaged version (PyPI versions are immutable, so a mismatched tag is
  unrecoverable), `py.typed` and the subpackages are present, and **the wheel
  contains no top-level `morpheus`** — the collision the rename exists to
  prevent, now enforced at the point of publication. That last guard is
  mutation-proven: injecting a `morpheus/__init__.py` into a built wheel makes it
  exit 1 naming the offending path.

  `workflow_dispatch` publishes to TestPyPI so the first upload of a name can be
  rehearsed somewhere recoverable; the real index refuses a re-used version even
  after a deletion.
- **A CI job that runs the known-answer vectors at every commit in a push**,
  not just at its tip. `d6e4374` changed one character of a v4 domain separator,
  swept in by a broad `git add` inside a commit titled "docs:"; a checkout of it
  fails its own vector tests, and CI never noticed because it only ever tested
  the tip. Verified by replaying the shipped job script over
  `f521fa7..756a90c`: it fails at `d6e4374` with 8 vector errors and passes at
  the two commits after it. Bounded to the newest 20 commits and it says so in
  an annotation when it truncates, rather than reporting a partial sweep as a
  clean one.
- **`--version`** prints the version and exits (DEF-002). It previously exited
  2 with "unrecognized arguments", which is the first thing an issue reporter
  is asked to supply. A test pins the reported string to the packaged version,
  so the two cannot drift apart unnoticed.

### Changed
- **Renamed: the distribution is `morpheus-crypt` and the import package is
  `morpheus_crypt`.** The command you type is still `morpheus`, and nothing about
  the ciphertext format, the config file or the CLI changes.

  `morpheus` on PyPI is an unrelated abandoned package (a dict schema helper,
  v0.0.4), and it also ships a top-level `morpheus` import package. Renaming only
  the distribution was considered and rejected: it would have left this project's
  directory as `morpheus/`, so installing both put two different `morpheus`
  packages at the same site-packages path with whichever installed second
  winning — inside a cryptography tool's trust boundary. Both names had to move.

  What deliberately did **not** move, because a blanket find-and-replace on the
  string "morpheus" would have taken all of it:
  - The five frozen wire-format literals in `pipeline.py` — `morpheus-v2-key-`,
    `morpheus-v4-key-`, `morpheus-hybrid-v4`, `morpheus-key-check` and
    `morpheus-cmt-v4`. Changing any one of them orphans every ciphertext ever
    written. Verified identical before and after, and the v2, v3 and v4 vector
    files are byte-for-byte unchanged.
  - `~/.morpheus/config.toml`. That is user state keyed to the command, which is
    unchanged, so moving it would have silently orphaned existing preferences.
  - The `morpheus` command itself, `prog="morpheus"`, and the CLI help that
    tells users to run `morpheus --generate-keypair`.

  Verified by building the wheel and installing it into a clean interpreter: the
  distribution reports as `morpheus-crypt`, site-packages contains only
  `morpheus_crypt`, `py.typed` survives, the `morpheus` command works, and a
  round trip succeeds. Then, with a stand-in for the stranger's package
  installed alongside, both import independently from separate directories and
  the tool still round-trips — which is the collision this rename existed to
  prevent, demonstrated rather than asserted.

  The install-instruction guard had to get sharper rather than looser. It used
  to flag the substring `morpheus` anywhere in a `pip install` line, so it would
  have failed the build on the correct new instruction. It now parses out each
  requirement and compares its PEP 503 normalised name, so `morpheus-crypt` and
  `morpheus_crypt` pass while `morpheus`, `Morpheus` and `MORPHEUS` are still
  refused. Writing that surfaced a bug in the parser itself: `-r
  requirements.txt` was being read as a package named `requirements-txt`.

  Not published to PyPI. Reserving the name is a separate step, and the
  standing decision is not to publish a wheel before a tag and a release
  workflow exist.
- **Hybrid post-quantum is now command-line only** (DEF-006). The wizard
  offered a "Hybrid Post-Quantum" checkbox while having no keypair generation,
  no key entry and no key display, so ticking it walked the user through four
  more steps, took a password and a confirmation, and then failed out of the
  pipeline. The control is gone and the Settings step signposts
  `--generate-keypair` and `--hybrid-pq` instead.
- `docs/USAGE.md` no longer tells GUI users to click a "Generate Keypair"
  button. No such button ever existed.

### Fixed
- **Text file reads and writes now name their encoding and their newlines.**
  Three defects from one cause — `open(path, "r")` and `os.fdopen(fd, "w")` take
  `locale.getpreferredencoding()`, which is UTF-8 on the macOS and Linux CI legs
  and cp1252 on the Windows one:
  - **A ciphertext file carrying a UTF-8 BOM failed to decrypt** with "Invalid
    base64 encoding", which blames the payload rather than the codec. Notepad
    writes a BOM by default, so this is the obvious Windows way to save a
    ciphertext someone sent you. Reproduced on macOS too, so it was never
    Windows-specific. The three ciphertext readers now use `utf-8-sig`, which
    strips a BOM when present and is identical to `utf-8` when it is not.
  - **The plain-text decrypt fallback rewrote line endings on Windows.** Text
    mode translates `\n` to `\r\n`, so a multi-line payload came back with
    different bytes than went in. `_open_secure_output` — the single writer every
    CLI output path goes through — now passes `newline=""`. The file-envelope
    decrypt path was already binary and was never affected.
  - **The Windows CI leg was failing on a decode error, not on anything it
    asserts.** `TestNoInstallInstructionNamesADistributionWeDoNotOwn` read the
    shipped docs with the locale codec, and `README.md` holds a byte cp1252
    cannot map. This was invisible for four pushes because Actions was
    billing-blocked and every job died in about two seconds before running.

  A guard test walks the AST of every module under `morpheus_crypt/` and fails on
  text-mode `open` or `os.fdopen` without an explicit `encoding`. ruff has this
  as `PLW1514`, but in the pinned 0.16.0 it is preview-only and enabling preview
  to reach one rule would activate every other unstable rule in a gate that was
  pinned specifically to stop drifting. The guard also covers `os.fdopen`, which
  ruff's rule does not — and which is where the newline defect lived.
- **`bandit`'s `nosec` markers carried their explanation on the same line**, so
  bandit parsed the prose as a list of test IDs and printed sixteen "Test in
  comment: ... is not a test name or id" warnings on every scan. Exit status was
  always 0 and the one load-bearing suppression still applied, so nothing was
  broken — but sixteen lines of noise is where a real warning goes unnoticed.
  The prose moved to its own comment line; the scan is now silent.
- **The GUI test helper `settle()` waited for the wrong condition.** It
  returned as soon as focus stopped changing, which is also true while focus
  is still on the sidebar and the step's `call_after_refresh` handoff has not
  fired. That is a transient stable state, not the end state, and the Windows
  runner hit the window: `TestStepContentTakesFocus` failed there
  intermittently while passing on every other platform. It now waits for the
  postcondition its callers actually depend on — focus has left the sidebar
  *and then* stopped moving. Two tests drive the helper with a fake app to pin
  both branches, since a real app cannot be held on the sidebar long enough to
  reproduce the race by hand.
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
- **Corrected the AES-256-GCM test vector's case number.** `test_ciphers.py`
  disagreed with itself: the class docstring said Test Case 16, the method name
  and its comment said 14. The vector is neither. It is Test Case 15, pinned by
  four features that each rule out a neighbour: a 256-bit key (so cases 13-18),
  a non-zero key (rules out 13 and 14), a 64-byte plaintext with no AAD (rules
  out 16, which truncates to 60 bytes and adds AAD), and a 96-bit IV (rules out
  17 and 18). The name was already provably wrong on the file's own evidence,
  since its comment described a 512-bit plaintext while Test Case 14 encrypts
  128 bits of zeroes. The vector, and therefore what is verified, is unchanged;
  the 2.0.0 entry below is relabelled for the same reason.
- Corrected the test count in `README.md` and `CONTRIBUTING.md`, which still
  said 308.
- Removed "No data touches the disk" from the **GitHub repository
  description**. `CHANGELOG` 2.1.0 records that claim being retracted from the
  docs, because the TUI writes a temporary file when no clipboard backend is
  available — but it survived on the repo page, which is the most-read surface
  the project has.
- **`SECURITY.md`'s unzeroable-copy table was incomplete** (DEF-007). Its
  *Known Limitations* section enumerates the library boundaries where key
  material is copied into an immutable `bytes` that cannot be zeroed, and read
  as exhaustive while omitting `_combine_with_kem()` — the hybrid PQ path,
  holding the password key concatenated with the ML-KEM shared secret. No
  behaviour change and no new weakness: that buffer's mutable `bytearray` is
  zeroed correctly, and the immutable copies are the same documented Python
  limitation as the five sites already listed. The table now names all six.

### Security
- **Documented that `0600` file modes are POSIX-only** (DEF-008). Eight places
  across `README.md`, `SECURITY.md` and `docs/USAGE.md` promised a "0600 file"
  or "owner read/write only" for the ML-KEM secret key, the config and output
  files, with no platform qualification — while Windows is a supported CI
  platform. On Windows `os.chmod(path, 0o600)` toggles only the read-only
  attribute: the files report `0o666` and are protected by whatever NTFS ACL
  they inherit, which MORPHEUS neither sets nor verifies. No code changed and
  nothing regressed; the claim was simply untrue on one supported platform.
  `SECURITY.md` now carries the full limitation with guidance, and the other
  seven sites point at it. Found because the Windows CI leg was failing on the
  two mode assertions, which are now skipped there rather than weakened.

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
  enabled.

  The analysis is **gated on the repository being public**. Code scanning is
  free on public repositories, but on a private one it needs GitHub Advanced
  Security: the scan itself succeeds and then the upload fails with "Code
  scanning is not enabled for this repository", and enabling it returns 422
  "Advanced security has not been purchased". Rather than carry a permanently
  red check, the job skips while private and starts by itself when visibility
  changes, with no edit required at the switch. Visibility is read through the
  API rather than the event payload, so scheduled runs gate correctly too.

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
- NIST SP 800-38D Test Case 15 test vector for AES-256-GCM
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
