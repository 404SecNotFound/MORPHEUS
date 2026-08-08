# Contributing to MORPHEUS

Thank you for your interest in contributing. This document explains how to
get started, what we expect from contributions, and how to submit your work.

## Getting Started

### 1. Fork and Clone

```bash
git clone https://github.com/<your-username>/Morpheus.git
cd Morpheus
```

### 2. Set Up Your Environment

```bash
python -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate          # Windows

pip install -r requirements.txt
pip install pqcrypto             # For post-quantum tests
```

### 3. Run the Test Suite

```bash
python -m pytest tests/ -v
# 605 tests should pass (1 skips off Linux: the sysfs check --check-network reads)
```

## What We Welcome

- **Bug reports** — open an issue with steps to reproduce
- **Security disclosures** — see [SECURITY.md](SECURITY.md) (do NOT open
  public issues for security bugs)
- **New cipher or KDF implementations** — must include test vectors from
  published standards (NIST, IETF)
- **Documentation improvements** — typos, clarity, new examples
- **Test coverage expansion** — especially edge cases and known-answer tests
- **Performance improvements** — that do not weaken security guarantees

## Contribution Guidelines

### Code Style

- Follow PEP 8 for Python code
- Use type annotations for function signatures
- Keep functions focused and under ~50 lines where practical
- Use `from __future__ import annotations` for forward references

### Security Requirements

This is a cryptographic tool. All contributions must:

1. **Never weaken security defaults** — don't lower KDF parameters, remove
   validation, or skip authentication tags
2. **Zero all key material** — use `bytearray` (not `bytes`) for keys and
   call `secure_zero()` in `finally` blocks
3. **Use established primitives** — no custom ciphers, no custom KDFs, no
   custom random number generators
4. **Include test vectors** — new ciphers/KDFs must include vectors from
   their specification (NIST, IETF RFC, etc.)
5. **Authenticate headers** — any format changes must update `build_aad()`
   to prevent downgrade attacks

### Tests

- Every change should include tests
- Run the full suite before submitting: `python -m pytest tests/ -v`
- Test files go in `tests/` and follow the `test_<module>.py` convention
- Use `pytest.raises` for expected exceptions
- Include both positive (roundtrip) and negative (wrong key, tampered data)
  test cases

### Commit Messages

- Use the imperative mood: "Add cipher chaining" not "Added cipher chaining"
- First line: concise summary (under 72 characters)
- Body (optional): explain the *why*, not the *what*

## Submitting a Pull Request

1. Create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-improvement
   ```

2. Make your changes and ensure all tests pass

3. Push and open a PR against `main`

4. In the PR description, include:
   - What the change does
   - Why it's needed
   - How to test it
   - Any security implications

## Architecture Overview

Understanding the codebase before contributing:

```
morpheus_crypt/
├── core/
│   ├── ciphers.py      # Cipher implementations (AES-GCM, ChaCha20)
│   ├── kdf.py          # Key derivation (Argon2id, Scrypt)
│   ├── pipeline.py     # Orchestration: chaining, hybrid PQ, key lifecycle
│   ├── formats.py      # Versioned binary format with AAD
│   ├── memory.py       # ctypes.memset zeroing of key buffers
│   ├── validation.py   # Password scoring, input validation
│   ├── entropy.py      # Dice-roll entropy arithmetic (--dice-entropy)
│   └── netcheck.py     # Passive link-state reading (--check-network)
├── cli.py              # The CLI: this project's only interface
├── __init__.py         # Package version
└── __main__.py         # Entry point; a bare invocation prints the help
```

Note the package is `morpheus_crypt`, not `morpheus`, since the 2026-07-30
rename: `morpheus` on PyPI is an unrelated abandoned package that also ships a
top-level `morpheus` import package.

The terminal GUI was removed on 2026-08-08. It is in the history if you need
it, but do not reintroduce one here. This repository's job is to be the
specification and the reference implementation, and the interface work belongs
in the native client instead.

### What this repository is for

Read [docs/FORMAT.md](docs/FORMAT.md) before changing anything under `core/`.
It is the normative specification of the ciphertext format, and it is what
other implementations get built against. The CLI is the reference
implementation, meaning it is what the specification is checked against, not
the product.

Three rules follow from that, and they are not negotiable:

1. **The frozen wire constants in FORMAT.md section 2 never change.** Six
   literal strings determine every key ever derived. Changing one makes every
   archived ciphertext undecryptable while the entire test suite stays green,
   because every other crypto test round-trips in-process.
2. **`tests/vectors/` is never regenerated.** Those files are the only thing
   that can catch the above. If they go red, compatibility broke; re-recording
   them destroys the evidence. A format change gets a new version byte and new
   vectors, and the old vectors keep decrypting untouched.
3. **A format change updates FORMAT.md in the same commit.**
   `tests/test_spec_conformance.py` is a second decryptor written from that
   document alone, importing nothing from `morpheus_crypt`, so a change that
   never reaches the specification fails there.

**Key design principle**: the ciphertext format is self-describing. The header
tells the decryptor which algorithms were used, and Decrypt reads its
configuration from there rather than from the pipeline config. v3 and v4 store
the KDF tuning parameters too, so they no longer have to match by convention;
the legacy v2 format is 6 bytes and does not carry them. The whole header is
authenticated as AEAD associated data, so none of it can be tampered with.

## Questions?

Open a discussion or reach out at 404securitynotfound@protonmail.ch.
