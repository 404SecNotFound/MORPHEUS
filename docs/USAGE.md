# SecureDataEncryption — Full Usage Guide

This document explains everything about the tool: what it does, how it works
under the hood, how to use every feature, and how to verify it's working
correctly. Written for both technical and non-technical readers.

---

## Table of Contents

1. [What This Tool Does (Plain English)](#what-this-tool-does-plain-english)
2. [How Encryption Works — Explained Simply](#how-encryption-works--explained-simply)
3. [Installation](#installation)
4. [Using the GUI](#using-the-gui)
5. [Using the CLI](#using-the-cli)
6. [Encryption Modes Explained](#encryption-modes-explained)
7. [Post-Quantum Encryption Explained](#post-quantum-encryption-explained)
8. [Password Requirements](#password-requirements)
9. [The Ciphertext Format](#the-ciphertext-format)
10. [Testing and Verification](#testing-and-verification)
11. [Security Guarantees and Limitations](#security-guarantees-and-limitations)
12. [Troubleshooting](#troubleshooting)

---

## What This Tool Does (Plain English)

Imagine you have a private note, a password list, a configuration file, or any
block of text that you need to protect. This tool lets you:

1. **Type or paste your text** into the application
2. **Choose a password** that only you know
3. **Get back scrambled text** (the encrypted version) that looks like random
   characters
4. **Later, paste that scrambled text back** and enter your password to get
   the original back

**The key guarantees:**

- **Nobody can read your text** without your password — not even us, not even
  someone who has the scrambled version
- **If anyone changes even one character** of the scrambled text, the tool
  will detect it and refuse to decrypt (tamper protection)
- **Your text is never saved to a file** — it lives only in the application
  window, and the output automatically disappears after 60 seconds
- **The scrambled output is different every time** — even if you encrypt the
  same text with the same password twice, you get different output (this
  prevents pattern analysis)

### What Can I Encrypt?

Anything that's text:
- Passwords and credentials
- Private notes or messages
- Configuration files with secrets
- API keys and tokens
- Code snippets
- Multi-line documents
- Any text up to 10 MB

This is **not** designed for encrypting binary files (images, PDFs, executables).
It's a **text encryption tool**.

---

## How Encryption Works — Explained Simply

### The Lock-and-Key Analogy

Think of encryption like a special lockbox:

1. **Your text** is the item you put inside
2. **Your password** is the key to the lock
3. **The encrypted output** is the locked box — anyone can hold it, but
   nobody can see inside without the key
4. **The salt** is like a unique serial number on the lock — even if two
   people use the same key (password), their locks are different

### What Happens Step by Step

When you hit "Encrypt":

```
Your text: "Meet me at the park at noon"
Your password: "MyStr0ng!Pass#2024"

Step 1 — Key Derivation (making the lock)
   Your password + a random salt → run through Argon2id (a deliberately
   slow process that takes about 1 second) → produces a 256-bit key
   This slowness is intentional — it means an attacker trying millions
   of passwords would take years instead of seconds.

Step 2 — Encryption (locking the box)
   Your text + the 256-bit key → AES-256-GCM → scrambled ciphertext
   A random nonce (number-used-once) ensures the output is unique every time.

Step 3 — Packaging
   The salt + nonce + ciphertext are bundled together and encoded as a
   base64 string (safe for copy/paste):
   "AgECAADE3f7a...long string..."

Step 4 — Tamper Tag
   AES-GCM automatically appends a 16-byte authentication tag.
   If anyone modifies even one bit of the ciphertext, decryption will
   fail with "incorrect password or corrupted data."
```

When you hit "Decrypt":

```
Step 1 — Unpack the base64 string → extract salt, nonce, ciphertext
Step 2 — Derive the same key from your password + the extracted salt
Step 3 — Decrypt and verify the authentication tag
Step 4 — If the tag checks out → show your original text
         If the tag fails → "incorrect password or corrupted data"
```

### Why Can't Attackers Just Try Every Password?

Because of **key derivation** (Step 1 above). Argon2id is designed to be:
- **Slow**: Each attempt takes ~1 second
- **Memory-hungry**: Each attempt uses 64 MB of RAM
- **Non-parallelizable**: You can't easily split the work across thousands of GPUs

An attacker trying 1 billion passwords would need ~31 years of continuous
computation. With a strong password (16+ characters, mixed types), it would
take longer than the age of the universe.

### What About Quantum Computers?

See [Post-Quantum Encryption Explained](#post-quantum-encryption-explained) below.

---

## Installation

### Prerequisites
- Python 3.10 or newer
- A terminal that supports colors (most modern terminals do)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/404securitynotfound/SecureDataEncryption.git
cd SecureDataEncryption

# 2. Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate        # macOS/Linux
# venv\Scripts\activate          # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Optional) Install post-quantum support
pip install pqcrypto
```

### Verify Installation

```bash
# Run the test suite
python -m pytest tests/ -v

# You should see: "86 passed"
```

---

## Using the GUI

### Launching

```bash
python secure_data_encryption.py
```

This opens the terminal GUI (TUI). It works in any modern terminal — no
web browser or desktop environment needed.

### Encrypting Text

1. Make sure **Encrypt** is selected (top radio buttons)
2. Choose your **Cipher** (AES-256-GCM recommended for most users)
3. Choose your **KDF** (Argon2id recommended)
4. Optionally check **Chain ciphers** for extra protection
5. Optionally check **Hybrid Post-Quantum** if you need PQ protection
6. Type or paste your text into the **Input** area
7. Enter your password in the **Password** field
8. Enter it again in the **Confirm** field
9. Click **ENCRYPT** (or press `Ctrl+E`)
10. The encrypted output appears in the **Output** area

**Important**: The output auto-clears after 60 seconds! Copy it before it
disappears (use the **Copy** button or `Ctrl+C` to copy from the output area).

### Decrypting Text

1. Switch to **Decrypt** mode
2. Paste the encrypted string into the **Input** area
3. Enter the password used during encryption
4. Click **DECRYPT** (or press `Ctrl+D`)
5. Your original text appears in the **Output** area

### Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Ctrl+E` | Encrypt |
| `Ctrl+D` | Decrypt |
| `Ctrl+L` | Clear all fields |
| `Ctrl+Q` | Quit |
| `Tab` | Move to next field |
| `Shift+Tab` | Move to previous field |

### Password Strength Meter

As you type your password, a strength meter shows:
- **Red (Weak)**: Too short or missing character types
- **Yellow (Fair)**: Meets some requirements
- **Cyan (Strong)**: Good password
- **Green (Excellent)**: Very strong password

The tool requires a **minimum acceptable** password:
- At least 12 characters
- Uppercase letters (A-Z)
- Lowercase letters (a-z)
- Digits (0-9)
- Special characters (!@#$%^&*...)

---

## Using the CLI

### Interactive Mode

```bash
python secure_data_encryption.py --cli
```

Prompts you step by step for operation, text, and password.

### Non-Interactive Mode

```bash
# Encrypt a short string
python secure_data_encryption.py -o encrypt --data "my secret text"
# (password entered interactively — never as a flag)

# Encrypt with ChaCha20 and chaining
python secure_data_encryption.py -o encrypt --data "secret" --cipher ChaCha20-Poly1305 --chain

# Encrypt from stdin (pipe a file's contents)
cat my_secret_notes.txt | python secure_data_encryption.py -o encrypt --data -

# Decrypt
python secure_data_encryption.py -o decrypt --data "AgECAADE3f7a..."
```

### All CLI Options

```
-o, --operation    encrypt | decrypt
-d, --data         Text to encrypt, or base64 ciphertext to decrypt. Use '-' for stdin.
--cipher           AES-256-GCM | ChaCha20-Poly1305
--kdf              Argon2id | Scrypt
--chain            Enable cipher chaining (AES + ChaCha)
--hybrid-pq        Enable hybrid post-quantum (ML-KEM-768)
--pq-public-key    Base64-encoded ML-KEM-768 public key (for hybrid encrypt)
--pq-secret-key    Base64-encoded ML-KEM-768 secret key (for hybrid decrypt)
--generate-keypair Generate and display an ML-KEM-768 keypair
--cli              Force CLI mode (skip GUI)
```

---

## Encryption Modes Explained

### Mode 1: AES-256-GCM (Default)

**What it is**: The gold standard for symmetric encryption. Used by the US
government, banks, and virtually every secure protocol (TLS, SSH, etc.).

**How it works**: Splits your text into blocks, encrypts each block using a
256-bit key and a unique counter, then generates an authentication tag that
proves the ciphertext hasn't been tampered with.

**When to use**: This is the default and right choice for most people.

### Mode 2: ChaCha20-Poly1305

**What it is**: A newer cipher designed by Daniel J. Bernstein. Used by
Google, Cloudflare, and WireGuard VPN.

**How it works**: Uses a stream cipher (ChaCha20) for encryption and a
polynomial authenticator (Poly1305) for tamper detection.

**When to use**: If your computer doesn't have AES hardware acceleration
(AES-NI), ChaCha20 runs faster in software. Also preferred in some
high-security contexts because it runs in constant time (no timing attacks).

### Mode 3: Cipher Chaining

**What it is**: Encrypts your text with AES-256-GCM first, then encrypts the
result with ChaCha20-Poly1305. Two independent algorithms, two independent keys.

**Why**: Defense-in-depth. If a catastrophic flaw is ever found in AES, your
data is still protected by ChaCha20, and vice versa. This is the "belt and
suspenders" approach.

**How keys work**: Your password is run through the KDF to produce a master key.
That master key is then expanded (via HKDF) into two separate 256-bit keys —
one for AES, one for ChaCha20. Knowing one key doesn't help you find the other.

**When to use**: When you want maximum confidence that your data will remain
secure even if one algorithm is broken in the future.

### Mode 4: Hybrid Post-Quantum

See the [next section](#post-quantum-encryption-explained).

---

## Post-Quantum Encryption Explained

### What Are Quantum Computers and Why Should I Care?

Regular computers process information as bits (0 or 1). Quantum computers use
**qubits** that can be 0, 1, or both at once (superposition). This lets them
try many solutions simultaneously.

**The threat**: A sufficiently powerful quantum computer could break certain
types of encryption that rely on mathematical problems being hard to solve
(like factoring large numbers). This primarily affects:
- RSA encryption
- Elliptic curve cryptography (ECDH, ECDSA)
- Traditional key exchange

**What's NOT at risk**: Symmetric encryption like AES-256 is already safe. A
quantum computer using Grover's algorithm would reduce AES-256 to the
equivalent of AES-128, which is still unbreakable (2^128 operations).

### So Why Add Post-Quantum to This Tool?

While AES-256 is quantum-safe on its own, we add ML-KEM-768 as an **extra
layer** for two reasons:

1. **Harvest Now, Decrypt Later**: Adversaries may be recording your encrypted
   data today, planning to decrypt it when quantum computers mature. The hybrid
   approach adds a layer that's specifically designed to resist quantum attacks.

2. **Two-Party Encryption**: If you're encrypting data for someone else, ML-KEM
   provides a quantum-safe way to establish a shared secret without exchanging
   passwords over insecure channels.

### What Is ML-KEM-768?

ML-KEM (Module-Lattice Key Encapsulation Mechanism) is the algorithm NIST
selected in 2024 as the standard for post-quantum key exchange (FIPS 203).
It's based on the mathematical hardness of the **Learning With Errors** problem
in lattice cryptography — a problem that even quantum computers can't solve
efficiently.

- **ML-KEM-512**: 128-bit security
- **ML-KEM-768**: 192-bit security (what we use — the recommended level)
- **ML-KEM-1024**: 256-bit security

### How Hybrid Mode Works

```
Your password ─→ Argon2id ─→ password_key (32 bytes)
                                     │
ML-KEM-768 ─→ encapsulate ─→ kem_shared_secret (32 bytes)
                                     │
                   HKDF(password_key + kem_shared_secret) ─→ final_key
                                                                │
                                                          AES-256-GCM encrypt
```

The final encryption key is derived from **both** your password **and** the
ML-KEM shared secret. An attacker needs to break **both** to read your data:
- Break Argon2id (brute-force your password)  **AND**
- Break ML-KEM-768 (solve the lattice problem)

### Using Hybrid Mode

**Step 1: Generate a keypair**
```bash
python secure_data_encryption.py --generate-keypair
```
This prints a public key and a secret key. The public key is safe to share.
The secret key must be kept private.

**Step 2: Encrypt (you or someone else)**
Use the public key to encrypt. The encrypted output includes a KEM ciphertext
that can only be decapsulated by the corresponding secret key.

**Step 3: Decrypt**
Use the secret key + the password to decrypt.

In the GUI, check the "Hybrid Post-Quantum" checkbox and click "Generate
Keypair" to create keys. Copy them before closing the app — they exist
in memory only and are never saved to disk.

---

## Password Requirements

### Minimum Requirements
- 12 characters long
- At least one uppercase letter (A-Z)
- At least one lowercase letter (a-z)
- At least one digit (0-9)
- At least one special character (!@#$%^&*...)

### Recommendations
- **16+ characters** for strong security
- **24+ characters** for excellent security
- Use a passphrase: "Correct-Horse-Battery-Staple!42" is better than "P@ssw0rd123!"
- Don't reuse passwords from other services
- Consider a password manager

### Scoring System

The tool scores passwords 0-100:

| Score | Label | Description |
|-------|-------|-------------|
| 0-39 | Weak | Missing requirements, too short, or predictable |
| 40-59 | Fair | Meets basics but could be stronger |
| 60-79 | Strong | Good password |
| 80-100 | Excellent | Very strong password |

**Bonus points for**: Long length, high character diversity, no repeated
characters (aaa), no sequential patterns (123, abc).

---

## The Ciphertext Format

### What the Encrypted Output Looks Like

When you encrypt text, you get a base64-encoded string like:

```
AgECAACYm3Kx8dE4R2Fk...long string...
```

This is not random — it has structure. Here's what's inside:

### Binary Layout (Version 2)

```
Byte 0:     Version (0x02)
Byte 1:     Cipher ID
              0x01 = AES-256-GCM
              0x02 = ChaCha20-Poly1305
              0x03 = Chained (AES → ChaCha)
Byte 2:     KDF ID
              0x01 = Scrypt
              0x02 = Argon2id
Byte 3:     Flags
              Bit 0 = Cipher chaining enabled
              Bit 1 = Hybrid PQ enabled
Bytes 4-5:  Reserved (0x0000)
Bytes 6+:   Payload (varies by mode)
```

### Payload Layout — Single Cipher

```
[16 bytes: salt][12 bytes: nonce][variable: ciphertext + 16-byte auth tag]
```

### Payload Layout — Chained

```
[16 bytes: salt][12 bytes: nonce_aes][12 bytes: nonce_chacha][ciphertext + tag]
```

### Payload Layout — Hybrid PQ

```
[2 bytes: KEM ciphertext length][KEM ciphertext][standard cipher payload]
```

### Why This Matters

The format is **self-describing**: the header tells the decryptor exactly which
algorithms were used. This means:
- You don't need to remember what settings you used when encrypting
- Future versions can add new ciphers without breaking old ciphertexts
- The cipher choice is **authenticated** (part of the AAD), preventing
  an attacker from tricking the decryptor into using a weaker algorithm

---

## Testing and Verification

### Running the Full Test Suite

```bash
python -m pytest tests/ -v
```

Expected output: **86 passed**

### What the Tests Cover

| Test File | What It Tests | Count |
|-----------|---------------|-------|
| `test_ciphers.py` | AES-GCM and ChaCha20 encrypt/decrypt, wrong keys, tampered data, empty input, large input | 18 |
| `test_kdf.py` | Argon2id and Scrypt key derivation, same inputs → same output, different inputs → different output | 12 |
| `test_formats.py` | Binary format serialization, flag handling, version checking, invalid input rejection | 9 |
| `test_validation.py` | Password strength scoring, edge cases (empty, short, missing char types), text validation | 14 |
| `test_pipeline.py` | End-to-end roundtrips for all modes, chaining, hybrid PQ, wrong password, wrong keys, cross-compatibility | 28 |
| `test_memory.py` | Secure zeroing, buffer management | 5 |

### Manual Verification — Encrypt/Decrypt Roundtrip

```bash
# CLI roundtrip test
python secure_data_encryption.py -o encrypt --data "The quick brown fox jumps over the lazy dog"
# Enter a strong password, e.g.: Test!P@ssw0rd#2024

# Copy the encrypted output, then:
python secure_data_encryption.py -o decrypt --data "<paste encrypted output>"
# Enter the same password

# Verify you get back: "The quick brown fox jumps over the lazy dog"
```

### Manual Verification — Wrong Password Fails

```bash
python secure_data_encryption.py -o encrypt --data "secret"
# Use password: MyStr0ng!Pass#01

python secure_data_encryption.py -o decrypt --data "<encrypted output>"
# Use WRONG password: MyStr0ng!Pass#02

# Should see: "Decryption failed: incorrect password or corrupted data"
```

### Manual Verification — Tamper Detection

```bash
python secure_data_encryption.py -o encrypt --data "secret"
# Copy the encrypted output

# Change one character in the middle of the encrypted string
# Try to decrypt the modified string

# Should see: "Decryption failed: incorrect password or corrupted data"
```

### Manual Verification — Chained Mode

```bash
python secure_data_encryption.py -o encrypt --data "test chaining" --chain
# Enter password

python secure_data_encryption.py -o decrypt --data "<encrypted output>"
# Enter same password — works because format is self-describing
```

### Manual Verification — Hybrid Post-Quantum

```bash
# Generate keypair
python secure_data_encryption.py --generate-keypair
# Save the public key and secret key

# Encrypt with hybrid PQ
python secure_data_encryption.py -o encrypt --data "quantum safe data" --hybrid-pq --pq-public-key "<public key>"
# Enter password

# Decrypt with hybrid PQ
python secure_data_encryption.py -o decrypt --data "<encrypted output>" --hybrid-pq --pq-secret-key "<secret key>"
# Enter same password
```

### Verifying Output Uniqueness

```bash
# Run the same encryption twice with the same text and password
python secure_data_encryption.py -o encrypt --data "same text"
# Password: SameP@ssw0rd!XX

python secure_data_encryption.py -o encrypt --data "same text"
# Password: SameP@ssw0rd!XX

# The two encrypted outputs should be DIFFERENT
# (random salt and nonce ensure this)
```

---

## Security Guarantees and Limitations

### What We Guarantee

1. **Confidentiality**: Without the correct password (and ML-KEM secret key
   if hybrid mode was used), the encrypted data is computationally
   indistinguishable from random noise.

2. **Integrity**: Any modification to the ciphertext — even a single bit
   flip — is detected by the authentication tag. Decryption fails cleanly.

3. **No data on disk**: The tool never writes sensitive data to files. The
   GUI output auto-clears after 60 seconds. Clipboard is wiped on clear.

4. **Memory protection**: Key material is stored in `mlock`'d buffers
   (prevents the OS from swapping to disk) and explicitly zeroed after use.

5. **Forward uniqueness**: Every encryption produces unique output (random
   salt + nonce), even for identical inputs.

### Limitations (Be Honest About These)

1. **Python memory model**: Python strings are immutable. While we zero
   `bytearray` buffers, the original password string may linger in Python's
   heap until garbage collection. For absolute memory security, a C/Rust
   implementation would be needed.

2. **Terminal scrollback**: While the GUI auto-clears, some terminals may
   retain content in their scrollback buffer. We recommend using the GUI
   in a terminal that supports secure erase or clearing scrollback.

3. **Clipboard security**: We clear the clipboard on output clear, but
   clipboard managers (e.g., macOS Paste, Windows clipboard history) may
   retain copies.

4. **Password via --password flag**: The legacy `-p` flag is supported for
   backward compatibility but prints a warning. Passwords passed as CLI
   arguments are visible in `ps` output and shell history.

5. **No file encryption**: This tool encrypts text, not binary files.
   For file encryption, consider `age`, `gpg`, or `7z` with AES-256.

6. **Single-user focus**: The hybrid PQ mode supports two-party encryption,
   but there's no built-in key distribution or PKI. You need to exchange
   ML-KEM public keys through a separate secure channel.

---

## Troubleshooting

### "pqcrypto not installed"

The hybrid post-quantum feature requires the `pqcrypto` package:
```bash
pip install pqcrypto
```

### "Password too weak"

Your password must meet all minimum requirements. Check the strength meter
for specific feedback (e.g., "Add uppercase letters").

### GUI looks broken

Make sure your terminal supports Unicode and 256+ colors. Recommended
terminals: iTerm2, Windows Terminal, Alacritty, Kitty, GNOME Terminal.

### "Unsupported ciphertext version"

You're trying to decrypt data encrypted with a different version of the tool.
Version 2 (current) can only decrypt version 2 ciphertexts. Version 1
ciphertexts (from the original tool) are not compatible.

### "Ciphertext was created with KDF X, but pipeline is configured with Y"

The encrypted data was created with a different KDF. In CLI mode, specify the
matching KDF with `--kdf`. In GUI mode, the format is self-describing and
this is handled automatically.

### Encryption is slow

Key derivation is intentionally slow (~1 second with Argon2id). This is a
security feature, not a bug. If you need faster operation for testing, this
is not something that should be reduced in production.
