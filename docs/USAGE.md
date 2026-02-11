# MORPHEUS — Full Usage Guide

Everything you need to know: what the tool does, how each feature works,
how to use it from the GUI and CLI, and how to verify it's working correctly.
Written for both technical and non-technical readers.

---

## Table of Contents

1. [What This Tool Does (Plain English)](#what-this-tool-does-plain-english)
2. [How Encryption Works — Explained Simply](#how-encryption-works--explained-simply)
3. [Installation](#installation)
4. [Using the GUI](#using-the-gui)
5. [Using the CLI](#using-the-cli)
6. [File Encryption](#file-encryption)
7. [Encryption Modes Explained](#encryption-modes-explained)
8. [Post-Quantum Encryption Explained](#post-quantum-encryption-explained)
9. [Password Requirements](#password-requirements)
10. [The Ciphertext Format](#the-ciphertext-format)
11. [Testing and Verification](#testing-and-verification)
12. [Security Guarantees and Limitations](#security-guarantees-and-limitations)
13. [Troubleshooting](#troubleshooting)

---

## What This Tool Does (Plain English)

Imagine you have a private note, a password list, a configuration file, or any
text or file that you need to protect. This tool lets you:

1. **Type or paste your text** into the application (or point it at a file)
2. **Choose a password** that only you know
3. **Get back scrambled output** that looks like random characters
4. **Later, paste that scrambled text back** (or decrypt the file) and enter
   your password to get the original back

**The key guarantees:**

- **Nobody can read your data** without your password — not even us, not even
  someone who has the scrambled version
- **If anyone changes even one character** of the encrypted output, the tool
  will detect it and refuse to decrypt (tamper protection)
- **Your text is never saved to a file** — in text mode, data lives only in the
  application window and the output automatically disappears after 60 seconds
- **The scrambled output is different every time** — even if you encrypt the
  same text with the same password twice, you get different output (this
  prevents pattern analysis)

### What Can I Encrypt?

**Text** — anything you can type or paste:
- Passwords and credentials
- Private notes or messages
- Configuration files with secrets
- API keys and tokens
- Code snippets
- Multi-line documents (up to 10 MB)

**Files** — any type, any format:
- Documents (PDF, DOCX, TXT)
- Images (PNG, JPG, BMP)
- Archives (ZIP, TAR, 7Z)
- Databases, binaries, executables
- Any file up to 100 MiB

---

## How Encryption Works — Explained Simply

### The Lock-and-Key Analogy

Think of encryption like a special lockbox:

1. **Your data** is the item you put inside
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
   slow process that takes about 1 second) → produces a 256-bit key.
   This slowness is intentional — it means an attacker trying millions
   of passwords would take years instead of seconds.

Step 2 — Encryption (locking the box)
   Your text + the 256-bit key → AES-256-GCM → scrambled ciphertext.
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
- **Non-parallelizable**: You can't easily split the work across thousands
  of GPUs

An attacker trying 1 billion passwords would need ~31 years of continuous
computation. With a strong password (16+ characters, mixed types), it would
take longer than the age of the universe.

### What About Quantum Computers?

See [Post-Quantum Encryption Explained](#post-quantum-encryption-explained)
below.

---

## Installation

### Prerequisites
- Python 3.10 or newer
- A terminal that supports colors (most modern terminals do)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/404securitynotfound/morpheus.git
cd morpheus

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
python -m pytest tests/ -v
# You should see: "268 passed"
```

---

## Using the GUI

### Launching

```bash
python morpheus.py
```

This opens the terminal dashboard (TUI). It works in any modern terminal — no
web browser or desktop environment needed.

### Dashboard Layout

The GUI is a **single-screen dashboard** inspired by
[Sampler](https://github.com/sqshq/sampler). All panels are visible at once —
no wizard steps, no hidden content, no clicking through pages.

```
┏━ MODE ━━━━┓ ┏━ CIPHER & KDF ━━━━━━━━━┓ ┏━ STATUS ━━━━━━┓
┃ ● ENCRYPT  ┃ ┃ Cipher [AES-256-GCM ▼] ┃ ┃  ● Mode       ┃
┃ ○ DECRYPT  ┃ ┃ KDF    [Argon2id    ▼] ┃ ┃  ● Settings   ┃
┗━━━━━━━━━━━━┛ ┃ □ Chain  □ PQ  □ Pad   ┃ ┃  ○ Input      ┃
               ┗━━━━━━━━━━━━━━━━━━━━━━━━┛ ┃  ○ Password   ┃
                                           ┃ [▶ ENCRYPT]  ┃
┏━ INPUT ━━━━━━━━━━━━━━━━━┓ ┏━ PASSWORD ━━┛━━━━━━━━━━━━━━━┓
┃ ● Text  ○ File          ┃ ┃ Key [●●●●●●●●●]             ┃
┃ ┌───────────────────────┐┃ ┃ Cfm [●●●●●●●●●] ✓ Match    ┃
┃ │ Enter plaintext...    │┃ ┃ □ Show password              ┃
┃ └───────────────────────┘┃ ┃ ████████░░ Strong 78/100     ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━┛ ┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
┏━ OUTPUT ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ [Copy] [Save] [Clear] [Stop timer]            ⏱ 60s       ┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┛
```

**Six bordered panels**, each with a title in the border frame:

| Panel | What It Does |
|-------|-------------|
| **MODE** | Select Encrypt or Decrypt (radio buttons) |
| **CIPHER & KDF** | Choose algorithm (AES-256-GCM / ChaCha20-Poly1305), KDF (Argon2id / Scrypt), toggle chaining, post-quantum, and padding |
| **STATUS** | Live readiness checklist — green ● when a section is valid, grey ○ when incomplete. The Execute button enables only when everything is ready |
| **INPUT** | Type or paste text, or switch to File mode and enter a path |
| **PASSWORD** | Password entry + confirmation (encryption only) + real-time strength meter with color-coded bar (0-100 score) |
| **OUTPUT** | Read-only result area with Copy, Save, Clear buttons and a 60-second auto-clear countdown |

Panels glow brighter when focused (border changes from dark green to bright
green). The STATUS panel updates in real time as you fill in fields.

**Important**: The output auto-clears after 60 seconds! Copy it before it
disappears (use the **Copy** button or select text and `Ctrl+Shift+C`).

### Keyboard Navigation

| Key | Action |
|-----|--------|
| `Tab` | Move to next field |
| `Shift+Tab` | Move to previous field |
| `Enter` | Select / activate focused element |
| `Up/Down` | Navigate options in selection lists |
| `Space` | Toggle checkboxes (chaining, hybrid PQ, padding) |
| `Ctrl+E` | Set Encrypt mode |
| `Ctrl+D` | Set Decrypt mode |
| `Ctrl+L` | Clear all fields and reset |
| `Ctrl+Q` | Quit |
| `F1` | Show keyboard help |

### Password Strength Meter

As you type your password in the PASSWORD panel, a color-coded bar updates:
- **Red (Very weak / Weak)**: Too short or missing character types
- **Orange (Weak)**: Meets some but not all requirements
- **Gold (Fair)**: Meets basics, could be stronger
- **Green (Strong)**: Good password
- **Bright green (Excellent)**: Very strong password

The score (0-100) is shown alongside the bar with specific feedback hints.

---

## Using the CLI

### Interactive Mode

```bash
python morpheus.py --cli
```

Prompts you step by step for operation, text, and password.

### Non-Interactive Mode

```bash
# Encrypt a short string
python morpheus.py -o encrypt --data "my secret text"
# (password entered interactively — never as a flag)

# Encrypt with ChaCha20 and chaining
python morpheus.py -o encrypt --data "secret" \
  --cipher ChaCha20-Poly1305 --chain

# Encrypt from stdin (pipe a file's contents as text)
cat my_secret_notes.txt | python morpheus.py -o encrypt --data -

# Decrypt
python morpheus.py -o decrypt --data "AgECAADE3f7a..."
```

### All CLI Flags

| Flag | Description |
|------|-------------|
| `-o, --operation` | `encrypt` or `decrypt` |
| `-d, --data` | Text to encrypt, or base64 ciphertext to decrypt. Use `-` for stdin |
| `-f, --file` | Path to file to encrypt or decrypt |
| `--output` | Explicit output file path (overrides default naming) |
| `--cipher` | `AES-256-GCM` (default) or `ChaCha20-Poly1305` |
| `--kdf` | `Argon2id` (default) or `Scrypt` |
| `--chain` | Enable cipher chaining (AES + ChaCha) |
| `--hybrid-pq` | Enable hybrid post-quantum (ML-KEM-768) |
| `--pq-public-key` | Base64-encoded ML-KEM-768 public key (for hybrid encrypt) |
| `--pq-secret-key` | Base64-encoded ML-KEM-768 secret key (for hybrid decrypt) |
| `--generate-keypair` | Generate and display an ML-KEM-768 keypair |
| `--cli` | Force CLI mode (skip GUI) |
| `--pad` | Enable PKCS#7 padding to hide plaintext length |
| `--fixed-size SIZE` | Pad plaintext to a fixed size in bytes before encryption |
| `--no-filename` | Omit the original filename from the encrypted file envelope |
| `--inspect` | Print parsed header fields from a ciphertext without decrypting |
| `--benchmark` | Run KDF benchmark (measures Argon2id/Scrypt iterations per second) |
| `--passphrase` | Read the password from stdin non-interactively (for scripting) |
| `--check-leaks` | Scan the ciphertext for known plaintext patterns (sanity check) |
| `--save-config PATH` | Save the current cipher/KDF/options to a JSON config file |
| `--no-strength-check` | Skip the password strength validation (use with caution) |
| `--force` | Overwrite output files without prompting |

---

## File Encryption

Encrypt any file type — documents, images, binaries, archives — up to 100 MiB.

### Encrypt a File

```bash
python morpheus.py -o encrypt -f document.pdf
# Enter password interactively
# -> Creates document.pdf.enc
```

### Decrypt a File

```bash
python morpheus.py -o decrypt -f document.pdf.enc
# Enter password interactively
# -> Restores document.pdf (original filename preserved)
```

### Custom Output Path

```bash
# Encrypt to specific location
python morpheus.py -o encrypt -f secret.docx --output /tmp/backup.enc

# Decrypt to specific location
python morpheus.py -o decrypt -f /tmp/backup.enc --output ~/restored.docx
```

### File Encryption with Advanced Modes

```bash
# Encrypt a file with cipher chaining
python morpheus.py -o encrypt -f database.sqlite --chain

# Encrypt a file with hybrid post-quantum
python morpheus.py -o encrypt -f classified.pdf \
  --hybrid-pq --pq-public-key <base64-pk>

# Decrypt the hybrid PQ file
python morpheus.py -o decrypt -f classified.pdf.enc \
  --hybrid-pq --pq-secret-key <base64-sk>
```

### How File Encryption Works

1. The file is read as raw bytes
2. The bytes are wrapped in a JSON envelope that preserves the original
   filename: `{"filename": "secret.pdf", "data": "<base64-encoded bytes>"}`
3. The envelope is encrypted through the same pipeline as text
4. On decryption, the envelope is parsed and the original file is restored
   with its original name (unless `--output` overrides it)

**Supported file types**: Any. Text, binary, images, archives — the tool
treats all files as raw byte streams. The 100 MiB limit prevents excessive
memory use during in-memory encryption.

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

**What it is**: A modern cipher designed by Daniel J. Bernstein. Used by
Google, Cloudflare, and WireGuard VPN.

**How it works**: Uses a stream cipher (ChaCha20) for encryption and a
polynomial authenticator (Poly1305) for tamper detection.

**When to use**: If your computer doesn't have AES hardware acceleration
(AES-NI), ChaCha20 runs faster in software. Also preferred in some
high-security contexts because it runs in constant time (no timing attacks).

### Mode 3: Cipher Chaining

**What it is**: Encrypts your data with AES-256-GCM first, then encrypts the
result with ChaCha20-Poly1305. Two independent algorithms, two independent keys.

**Why**: Defense-in-depth. If a catastrophic flaw is ever found in AES, your
data is still protected by ChaCha20, and vice versa.

**How keys work**: Your password is run through the KDF to produce a master key.
That master key is expanded through HKDF into two separate 256-bit subkeys —
one for AES, one for ChaCha20. Each subkey uses domain-separated HKDF info
strings bound to the application context and salt. Knowing one key doesn't
help you find the other.

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

**What's NOT at risk**: Symmetric encryption like AES-256 is already quantum-
resistant. A quantum computer using Grover's algorithm would reduce AES-256
to the equivalent of AES-128, which is still computationally infeasible
(2^128 operations).

### So Why Add Post-Quantum to This Tool?

While AES-256 is quantum-resistant on its own, we add ML-KEM-768 as a
**defense-in-depth layer** for two reasons:

1. **Harvest Now, Decrypt Later**: Adversaries may be recording your encrypted
   data today, planning to decrypt it when quantum computers mature. The hybrid
   approach adds a layer that's specifically designed to resist quantum attacks.

2. **Two-Party Encryption**: If you're encrypting data for someone else, ML-KEM
   provides a quantum-resistant way to establish a shared secret without
   exchanging passwords over insecure channels.

**Important**: The overall security of hybrid mode is bounded by the strongest
factor, but a weak password remains the weakest link. ML-KEM protects against
quantum attacks on the key exchange, not against password brute-forcing.

### What Is ML-KEM-768?

ML-KEM (Module-Lattice Key Encapsulation Mechanism) is the algorithm NIST
selected in 2024 as the standard for post-quantum key exchange (FIPS 203).
It's based on the mathematical hardness of the **Learning With Errors** problem
in lattice cryptography — a problem that even quantum computers can't solve
efficiently.

- **ML-KEM-512**: Category 1 (~AES-128 equivalent)
- **ML-KEM-768**: Category 3 (~AES-192 equivalent — what we use)
- **ML-KEM-1024**: Category 5 (~AES-256 equivalent)

We chose ML-KEM-768 as the best balance of security and practical key sizes.
Category 5 doubles key sizes for marginal gain.

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
python morpheus.py --generate-keypair
```
This prints a public key and a secret key (base64-encoded). The public key
is safe to share. The secret key must be kept private.

**Step 2: Encrypt (you or someone else)**
```bash
python morpheus.py -o encrypt --data "sensitive text" \
  --hybrid-pq --pq-public-key <base64-pk>
```
The encrypted output includes a KEM ciphertext that can only be decapsulated
by the corresponding secret key.

**Step 3: Decrypt**
```bash
python morpheus.py -o decrypt --data "AgEB..." \
  --hybrid-pq --pq-secret-key <base64-sk>
```

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
- Use a passphrase: `Correct-Horse-Battery-Staple!42` is better than
  `P@ssw0rd123!`
- Don't reuse passwords from other services
- Consider a password manager

### Non-Interactive Password Input (`--passphrase`)

For scripting and automation, use the `--passphrase` flag to read the password
from stdin instead of the interactive prompt:

```bash
echo "MyStr0ng!Pass#2024" | python morpheus.py -o encrypt --data "secret" --passphrase
```

When `--passphrase` is used, the password is read as a single line from stdin.
The strength check still applies by default -- use `--no-strength-check` to
bypass it if your pipeline manages password policy externally. Note that passing
passwords via shell commands may expose them in process listings; prefer piping
from a file or a secrets manager:

```bash
cat /run/secrets/encryption_pw | python morpheus.py -o encrypt -f data.bin --passphrase
```

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

When you encrypt data, you get a base64-encoded string like:

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
Bytes 4-5:  Reserved (0x0000, validated on read)
Bytes 6+:   Payload (varies by mode)
```

### Payload Layout — Single Cipher

```
[16 bytes: salt][12 bytes: nonce][variable: ciphertext + 16-byte auth tag]
```

### Payload Layout — Chained

```
[16 bytes: salt][12 bytes: nonce_aes][12 bytes: nonce_chacha][ciphertext + tags]
```

### Payload Layout — Hybrid PQ (Single Cipher)

```
[16 bytes: salt][12 bytes: nonce][2 bytes: KEM-ct length (big-endian)][KEM ciphertext][ciphertext + tag]
```

### Payload Layout — Hybrid PQ (Chained)

```
[16 bytes: salt][12 bytes: nonce_aes][12 bytes: nonce_chacha][2 bytes: KEM-ct length (big-endian)][KEM ciphertext][ciphertext + tags]
```

### Why This Matters

The format is **self-describing**: the header tells the decryptor exactly which
algorithms were used. This means:
- You don't need to remember what settings you used when encrypting
- Future versions can add new ciphers without breaking old ciphertexts
- The full 6-byte header is **authenticated as AAD** — modifying any header
  byte (including reserved bytes) causes decryption to fail, preventing
  algorithm-downgrade attacks

---

## Testing and Verification

### Running the Full Test Suite

```bash
python -m pytest tests/ -v
```

Expected output: **268 passed**

### What the Tests Cover

| Test File | What It Tests | Count |
|-----------|---------------|-------|
| `test_ciphers.py` | AES-GCM and ChaCha20 roundtrips, NIST SP 800-38D test vector, RFC 8439 test vector, ciphertext indistinguishability, wrong key/AAD/tampered data, bytearray keys | 26 |
| `test_kdf.py` | Argon2id and Scrypt key derivation, determinism, bytearray returns, salt generation, length validation | 17 |
| `test_formats.py` | Binary format serialization, flag combinations, version/reserved byte validation, AAD collision resistance, empty/large payloads | 18 |
| `test_pipeline.py` | End-to-end roundtrips for all modes (single/chained/hybrid/both), wrong password detection, cross-compatibility, payload truncation, KEM length=0 bypass, header tampering | 35 |
| `test_memory.py` | Secure zeroing with ctypes.memset, SecureBuffer, secure_key context manager | 7 |
| `test_validation.py` | Password strength scoring (0-100), minimum requirements, edge cases, input text validation | 17 |
| `test_cli.py` | File encrypt/decrypt roundtrip (text and binary files), path traversal prevention | 3 |
| `test_config.py` | Config file save/load, schema validation, option merging, invalid config rejection | 12 |
| `test_fuzz.py` | Fuzz testing with random inputs, malformed headers, truncated payloads, random byte sequences | 30 |
| `test_gui.py` | Dashboard panel mounting, keyboard shortcuts, encrypt/decrypt roundtrip, strength meter, clipboard fallbacks | 22 |
| `test_wizard_state.py` | State validation per section, step unlocking rules, edge cases | 18 |

Tests include **NIST SP 800-38D** (AES-256-GCM) and **RFC 8439** (ChaCha20-Poly1305) reference vectors verified against the `cryptography` library's validated implementations.

### Manual Verification — Encrypt/Decrypt Roundtrip

```bash
# CLI roundtrip test
python morpheus.py -o encrypt --data "The quick brown fox"
# Enter a strong password, e.g.: Test!P@ssw0rd#2024

# Copy the encrypted output, then:
python morpheus.py -o decrypt --data "<paste encrypted output>"
# Enter the same password

# Verify you get back: "The quick brown fox"
```

### Manual Verification — File Roundtrip

```bash
# Create a test file
echo "Sensitive document content" > /tmp/test.txt

# Encrypt the file
python morpheus.py -o encrypt -f /tmp/test.txt
# -> Creates /tmp/test.txt.enc

# Decrypt the file
python morpheus.py -o decrypt -f /tmp/test.txt.enc
# -> Restores /tmp/test.txt with original content
```

### Manual Verification — Wrong Password Fails

```bash
python morpheus.py -o encrypt --data "secret"
# Use password: MyStr0ng!Pass#01

python morpheus.py -o decrypt --data "<encrypted output>"
# Use WRONG password: MyStr0ng!Pass#02

# Should see: "Decryption failed: incorrect password or corrupted data"
```

### Manual Verification — Tamper Detection

```bash
python morpheus.py -o encrypt --data "secret"
# Copy the encrypted output

# Change one character in the middle of the encrypted string
# Try to decrypt the modified string

# Should see: "Decryption failed: incorrect password or corrupted data"
```

### Manual Verification — Chained Mode

```bash
python morpheus.py -o encrypt --data "test chaining" --chain
# Enter password

python morpheus.py -o decrypt --data "<encrypted output>"
# Enter same password — works because format is self-describing
```

### Manual Verification — Hybrid Post-Quantum

```bash
# Generate keypair
python morpheus.py --generate-keypair
# Save the public key and secret key

# Encrypt with hybrid PQ
python morpheus.py -o encrypt --data "quantum safe data" \
  --hybrid-pq --pq-public-key "<public key>"
# Enter password

# Decrypt with hybrid PQ
python morpheus.py -o decrypt --data "<encrypted output>" \
  --hybrid-pq --pq-secret-key "<secret key>"
# Enter same password
```

### Verifying Output Uniqueness

```bash
# Run the same encryption twice with the same text and password
python morpheus.py -o encrypt --data "same text"
# Password: SameP@ssw0rd!XX

python morpheus.py -o encrypt --data "same text"
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
   flip — is detected by the AEAD authentication tag. Decryption fails cleanly.

3. **Memory protection**: Key material is stored in `mlock`'d buffers
   (prevents the OS from swapping to disk) and zeroed after use via
   `ctypes.memset`. KEM shared secrets and intermediate key material are
   also zeroed.

4. **Forward uniqueness**: Every encryption produces unique output (random
   salt + nonce), even for identical inputs.

5. **Header authentication**: The full 6-byte header (including reserved bytes)
   is authenticated as AEAD additional data, preventing algorithm-downgrade
   attacks.

### Limitations (Honest About These)

1. **Python memory model**: Python strings are immutable. While we zero
   `bytearray` buffers via `ctypes.memset`, the original password string may
   linger in Python's heap until garbage collection. For absolute memory
   security, a C/Rust implementation would be needed.

2. **Terminal scrollback**: While the GUI auto-clears, some terminals may
   retain content in their scrollback buffer. We recommend using the GUI
   in a terminal that supports secure erase or clearing scrollback.

3. **Clipboard security**: We clear the clipboard on output clear, but
   clipboard managers (e.g., macOS Paste, Windows clipboard history) may
   retain copies.

4. **`mlock` availability**: If `RLIMIT_MEMLOCK` is insufficient, buffers
   may be swapped to disk. The tool logs a warning when this happens, but
   cannot guarantee all key material stays in RAM.

5. **KDF parameter mismatch**: KDF tuning parameters (time_cost, memory_cost)
   are not stored in the ciphertext format. If you change KDF parameters
   between encrypt and decrypt, the authentication tag will fail with a
   generic error rather than a specific parameter mismatch message.

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

The encrypted data was created with a different KDF than you're using now.
In CLI mode, specify the matching KDF with `--kdf`. In GUI mode, the cipher
and KDF are auto-detected from the header — only KDF parameters need to match.

### "Reserved header bytes must be zero"

The ciphertext header contains non-zero reserved bytes. This typically means
the data has been corrupted or was created by a different tool. Version 2
strictly validates that bytes 4-5 are `0x0000`.

### Encryption is slow

Key derivation is intentionally slow (~1 second with Argon2id). This is a
security feature, not a bug. The slowness makes password brute-forcing
computationally expensive.

### File too large

File encryption supports files up to 100 MiB. For larger files, consider
splitting them first or using a streaming encryption tool.
