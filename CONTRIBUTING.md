# Contributing to MORPHEUS

Thank you for your interest in contributing. This document explains how to
get started, what we expect from contributions, and how to submit your work.

## Getting Started

### 1. Fork and Clone

```bash
git clone https://github.com/<your-username>/MORPHEUS.git
cd morpheus
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
# All 123 tests should pass
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
morpheus/
├── core/
│   ├── ciphers.py      # Cipher implementations (AES-GCM, ChaCha20)
│   ├── kdf.py          # Key derivation (Argon2id, Scrypt)
│   ├── pipeline.py     # Orchestration: chaining, hybrid PQ, key lifecycle
│   ├── formats.py      # Versioned binary format with AAD
│   ├── memory.py       # mlock, ctypes.memset zeroing, SecureBuffer
│   └── validation.py   # Password scoring, input validation
├── gui.py              # Textual TUI application
├── cli.py              # CLI with text + file encryption
├── __init__.py          # Package version
└── __main__.py          # Entry point (auto-detects GUI vs CLI)
```

**Key design principle**: The ciphertext format is self-describing. The
6-byte header tells the decryptor which algorithms were used. Decrypt reads
configuration from the header, not from the pipeline config (except KDF
tuning parameters, which are not stored in the format).

## Questions?

Open a discussion or reach out at 404securitynotfound@protonmail.ch.
