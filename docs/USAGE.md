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
- **Nothing is written to disk behind your back.** In text mode the data lives
  in the application window, and the output display clears itself after 60
  seconds. Two exceptions are things you ask for: **Save to file** writes the
  output, and **Copy** falls back to a temporary file when the system has no
  clipboard backend available. The countdown clears the display; it does not
  clear your clipboard, and it cannot reach a copy that already left
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
   expensive process: every attempt costs 64 MiB of RAM) → produces a
   256-bit key. That memory cost is the point. It is what stops an attacker
   from testing millions of passwords in parallel on GPUs, because each
   guess needs its own 64 MiB rather than just raw arithmetic.

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
- **Memory-hungry**: Each attempt uses 64 MiB of RAM. This is the main defence
- **Costly to parallelize**: That memory requirement is what makes running
  thousands of guesses at once on GPUs or ASICs expensive
- **Tunable**: Raise `time_cost` if you want a higher per-guess cost

A single derivation takes roughly 30 ms on a 2024-class laptop, so do not rely
on wall-clock time alone. A weak password is still weak. Password strength and
the memory cost work together.

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
- A terminal at least **100 columns by 30 rows** for the GUI. Below that,
  MORPHEUS shows a "terminal too small" screen naming your current size instead
  of a clipped wizard; resize and it returns exactly as you left it, including
  any finished result. The CLI has no size requirement.

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/404SecNotFound/Morpheus.git
cd Morpheus

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
# You should see: "757 passed"
```

---

## Using the GUI

```bash
python morpheus.py
```

Running with no arguments opens the terminal wizard. It works in any modern
terminal, with no web browser or desktop environment needed, and needs at least
**100 columns by 30 rows**.

The wizard walks through six steps: Mode, Settings, Input, Password, Review and
Output. It is documented step by step, with a screenshot of each, in the
[README](../README.md#using-the-gui), along with the full keyboard map. That is
not duplicated here so the two cannot drift apart again.

Two things worth knowing before you start:

- **Hybrid post-quantum is not offered in the wizard**, because it needs an
  ML-KEM keypair the wizard has no way to hold. Your data is quantum-resistant
  regardless; see
  [Post-Quantum Encryption Explained](#post-quantum-encryption-explained).
- **The output auto-clears after 60 seconds.** Copy or save it before then, or
  press **Stop timer**.

## Using the CLI

### Interactive Mode

```bash
python morpheus.py -o encrypt
```

Prompts you step by step for the remaining input and the password. Passing any
flag runs the CLI; running `python morpheus.py` with no arguments launches the GUI.

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
| `--pq-public-key-file` | Path to a file holding the base64 public key. `--generate-keypair` writes one as `<secret-key-path>.pub` |
| `--pq-secret-key` | Base64-encoded ML-KEM-768 secret key (for hybrid decrypt). Discouraged: argv is readable by other local users via `ps` and shell history |
| `--pq-secret-key-file` | Path to a file holding the base64 secret key. Preferred over `--pq-secret-key` |
| `--generate-keypair` | Generate an ML-KEM-768 keypair: public key to stdout, secret key to a 0600 file (path from `--output`). POSIX only; on Windows the mode is not applied — see SECURITY.md |
| `--dice-entropy` | Report how much entropy a number of fair dice rolls carries. Takes a **count**, not the rolls. Exits 1 below 128 bits |
| `--dice-sides` | Faces on the die used with `--dice-entropy` (default 6) |
| `--check-network` | List which interfaces currently report a live link. Reads kernel link state only: no packets, no sockets. Exits 0 when nothing could carry traffic, 1 when something could, 2 where it cannot be read. Linux only |
| `--inspect` | Inspect a ciphertext header without decrypting. Shows format version, cipher, KDF, flags and sizes. No password needed. Use with `--data` or `--file` |
| `--benchmark` | Benchmark KDF and cipher performance on this hardware, then print a recommended configuration |
| `--force` | Overwrite the output file if it already exists |
| `--passphrase` | Use passphrase-mode strength checking (word-based, no digit or special-character requirement). Requires 4+ words and 20+ characters |
| `--no-strength-check` | Skip password strength validation. Use with caution |
| `--check-leaks` | Check the password against the Have I Been Pwned breach database. k-anonymity: only 5 characters of the SHA-1 hash are sent. **Requires network access**, so not for an air-gapped machine |
| `--pad` | Pad the plaintext to hide its exact length |
| `--fixed-size` | Pad every ciphertext to 64 KiB (constant-size mode). Implies `--pad`; input must be under 64 KiB |
| `--no-filename` | Leave the original filename out of the encrypted envelope |
| `--allow-expensive-kdf` | Permit decrypting a ciphertext whose header asks for unusually expensive KDF settings. Off by default: the header is not authenticated until the work is already done, so a hostile file can otherwise spend minutes of CPU and hundreds of MiB |
| `--save-config` | Save the current cipher/KDF/flag preferences to `~/.morpheus/config.toml` for future sessions |
| `--version` | Print the version and exit |

`-h, --help` prints the same list from the tool itself. One flag is deliberately absent
above: `-p, --password` accepts a password as an argument and is hidden and deprecated,
because `argv` is readable by other local users through `ps` and is kept in shell
history. Let MORPHEUS prompt instead.

---

## Counting Dice Entropy

If you generate wallet seeds or other long-lived keys with physical dice, this
tells you when you have rolled enough:

```bash
python morpheus.py --dice-entropy 50            # 50 rolls of a six-sided die
python morpheus.py --dice-entropy 99
python morpheus.py --dice-entropy 128 --dice-sides 2   # coin flips
```

It reports bits, gives a verdict against a 128-bit floor and a 256-bit target,
and exits 1 when you are short — so a script can gate on it.

Each verdict also says what it means in ordinary words, because the arithmetic
alone does not help the reader most at risk: the one who rolls twenty times,
reads "51.7 bits", cannot tell whether that is good, and stops.

```
  Verdict:    Strong. Clears 256 bits.
              Nobody can guess this, at any budget.
```

```
  Verdict:    OK. Clears the 128-bit floor.
              126.8 bits short of 256; 100 rolls reaches it.
              Safe to use, but not the strongest a seed can hold.
```

```
  Verdict:    NOT ENOUGH. Below the 128-bit floor.
              Roll 30 more (50 total) to clear it.
              An attacker with money could search this. Keep rolling.
```

### Rolling more than you need

Past the target, extra rolls are discarded by the format rather than adding
strength, so the strong verdict says where the useful rolling stopped:

```bash
python morpheus.py --dice-entropy 300
```

```
  Verdict:    Strong. Clears 256 bits.
              Nobody can guess this, at any budget.
              100 rolls was enough; the other 200 added nothing,
              because a 24-word seed holds only 256 bits.
```

300 rolls really does carry 775.5 bits. A 24-word seed holds 256, and SHA-256
cannot return more than 256 bits of output, so the remainder goes nowhere. The
mirror of this is the dangerous case: 50 rolls into a 24-word phrase gives 256
bits of container carrying 129 bits of entropy. Both are mismatches; only one
costs you anything.

### How to roll

1. Take **one** die. Casino dice are ideal: sharp edges, flat faces and flush
   pips make them fair, where cheap rounded dice are slightly biased.
2. Roll it, write the number down, roll again, write it down.
3. Stop at 100 numbers, recorded in the order you rolled them.
4. Enter them into your air-gapped hardware wallet's dice entry, and nowhere
   else. Not every wallet offers this. It usually appears during new-wallet
   setup, under a name like "dice rolls" or "add entropy". If yours does not
   have it, stop here: converting the rolls yourself on a general-purpose
   computer is worse than not using dice at all.
5. **Destroy the paper** once the wallet has shown you the seed phrase and you
   have written that down. Until then those 100 numbers *are* your seed, and
   anyone who reads them can rebuild your wallet. Shred or burn it. Do not
   photograph it, and do not keep it as a backup: the seed phrase is the backup.

Never re-roll a result you dislike, never throw a handful and read them
together, and never let the sequence be seen, filmed or typed into a networked
machine. Each of those silently reduces the real figure below what the tool
reports.

**It takes a count, never the rolls themselves.** The sequence is key material.
Typing it into a networked computer defeats the entire reason for using dice.
MORPHEUS generates nothing here, derives nothing and stores nothing; the command
does arithmetic and prints it.

The rule of thumb for a fair six-sided die, since each roll carries
log₂(6) ≈ 2.585 bits:

| Rolls | Entropy | |
|---|---|---|
| 49 | 126.7 bits | short of the floor |
| **50** | **129.2 bits** | clears 128 bits |
| 99 | 255.9 bits | just short of 256 |
| **100** | **258.5 bits** | clears 256 bits |

### What the number cannot tell you

The figure is an upper bound, and it holds only if the rolls were fair,
independent, ordered and private. Software counting rolls cannot check any of
those. A weighted or shaved die carries less per roll. Re-rolling a result you
disliked throws away the entropy you kept. Reading a handful of dice thrown
together in sorted order loses most of it, because order is most of the
information. A sequence anyone saw, filmed, or typed into a networked machine is
spent.

Hashing does not add entropy. SHA-256 over 50 rolls returns 256 bits of output
carrying 129 bits of entropy.

### Why this exists

On 30 July 2026 roughly 594 BTC moved out of about 500 addresses in 25 minutes.
A COLDCARD firmware bug had routed seed generation through a software PRNG
instead of the device's hardware RNG: Mk2 and Mk3 seeds ended up with roughly 40
bits of effective search space against an intended 128, and Mk4, Q and Mk5 with
roughly 72.

Users who had added at least 50 private dice rolls were not considered at risk,
because the firmware hashed those rolls in alongside the device's own output.
The advisory puts 50 to 98 rolls at 128 bits or more from the dice alone, and 99
or more at about 256, which is the same arithmetic this tool reports. Physical
dice survived a total failure of the vendor's generator, and that is the
argument for counting them, and for counting them correctly.

The cause was not a weak algorithm. Coinkite had written their own hardware
generator and set `MICROPY_HW_ENABLE_RNG = 0` to turn MicroPython's path off,
but the guard reading it tested whether the name was defined rather than what it
was set to. Setting it to zero therefore enabled the very thing it was meant to
disable, and that shipped in firmware 4.0.0 in March 2021 and stood for five
years. Worth remembering next time a review checks that a good primitive was
chosen and stops there.

**What has changed since.** Fixed firmware exists for every affected model:
Mk2/Mk3 4.2.0 or later, Mk4/Mk5 standard 5.6.0 or later, Q standard 1.5.0Q or
later, Mk4/Mk5 Edge 6.6.0X or later, Q Edge 6.6.0QX or later. Standard and Edge
are separate release tracks, so a higher Edge number is not automatically a
fixed one. Updating does not repair a seed already generated, so affected users
have to migrate. The 594 BTC was the first sweep only: Galaxy Research put the
confirmed total near 1,367 BTC across roughly 4,585 addresses by 2 August.

Sources: [Coinkite advisory](https://blog.coinkite.com/coldcard-mk3-seed-generation-warning/)
and [technical backgrounder](https://blog.coinkite.com/entropy-technical-backgrounder/);
[CoinDesk on the first sweep](https://www.coindesk.com/tech/2026/07/31/major-bitcoin-wallet-flaw-drains-594-btc-in-25-minute-sweep).

**This tool does not generate seeds, and should not.** Seed generation belongs on
an air-gapped device with a screen you trust. Doing it on a general-purpose
machine beside a browser trades a known weakness for a worse one.

---

## Checking What Is Still Connected

The step before rolling dice is unplugging the machine. The usual way to confirm
that is to open a browser and see whether a page loads, which on this particular
machine is the wrong move.

```bash
python morpheus.py --check-network
```

```
MORPHEUS Network Check
============================================
  eth0         ethernet  no carrier  down
  lo           loopback  CARRIER     unknown
  wlan0        wireless  no carrier  down

  No interface currently reports a carrier.
```

The full output continues with the caveat below, printed every run.

### What it reads

`/sys/class/net`, and nothing else. It opens no sockets, resolves no names and
starts no subprocesses. Probing the network sends the packet an air-gapped user
must not send, and announces that MORPHEUS is running, when, and from which
address. The question is narrowed to one the kernel can answer locally: is any
interface in a state where traffic could leave.

A test parses the module and fails the build if it ever imports `socket`,
`urllib`, `subprocess` or similar, because this property erodes quietly during
a refactor.

Loopback reports a carrier and is never counted, since it goes nowhere. Bridges,
tunnels and taps are labelled `virtual` but **are** counted: `docker0` with a
carrier is a route off the machine like any other.

### What it cannot tell you

That the machine is air-gapped. Nothing can, from inside. It does not see a
phone about to be tethered, a Bluetooth connection, a hypervisor's host bridge,
or a cable pushed back in a minute from now. It cannot see whether the machine
was online earlier, which is usually the part that matters: an air gap stops
data leaving over the wire, not something that arrived before the gap.

The output says so in place rather than in a footnote, and there is no green
light meaning "you are safe". A false sense of security is at its most expensive
in the minutes someone is generating a seed.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | No interface was observed carrying traffic |
| `1` | At least one interface could carry traffic |
| `2` | Link state could not be read on this platform |

`2` is separate from `0` so a setup script cannot read "unsupported" as a clean
result. Treat it as its own case rather than folding it into failure:

```bash
python morpheus.py --check-network
case $? in
  0) echo "Nothing observed carrying traffic." ;;
  1) echo "Still connected. Not ready." ;;
  2) echo "Cannot read link state here. Check by hand." ;;
esac
```

Link state comes from `/sys/class/net`, which only Linux provides. On macOS and
Windows the check declines rather than guessing, and you disconnect the cable
and turn off Wi-Fi by hand.

---

## File Encryption

Encrypt any file type — documents, images, binaries, archives — up to 100 MiB.

### Encrypt a File

```bash
python morpheus.py -o encrypt -f document.pdf
# Enter password interactively
# -> Creates morpheus_ab12cd34ef56.enc
#
# The name is random on purpose. A file called document.pdf.enc announces both
# that it is encrypted and what it holds; this one announces only the former.
# The real filename travels inside the authenticated ciphertext. Use --output
# to choose the name yourself, or --no-filename to drop it from the envelope.
```

### Decrypt a File

```bash
python morpheus.py -o decrypt -f morpheus_ab12cd34ef56.enc
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
  --hybrid-pq --pq-secret-key-file my_pq_secret.key
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

**This is two-factor, not recipient-only encryption.** The final key is derived
from the password key *and* the ML-KEM shared secret, so holding the secret key
is not enough: the recipient also needs the password the sender used, shared
over some other channel. Encrypting to a public key with no shared password is
a different mode that MORPHEUS does not currently have.

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
python morpheus.py --generate-keypair --output my_pq_secret.key
```
The public key (base64) is printed to stdout and is safe to share. The secret
key is written to `my_pq_secret.key` with mode 0600 rather than printed,
because terminal scrollback and shell logs outlive the command. Back that file
up: it cannot be regenerated.

On Windows the 0600 mode is **not** applied — `os.chmod` only sets the
read-only attribute there, and the file is protected by inherited NTFS ACLs
instead. Write it inside your user profile rather than a shared location, and
see *File permissions are POSIX-only (Windows)* in `SECURITY.md`.

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
  --hybrid-pq --pq-secret-key-file my_pq_secret.key
```

Hybrid post-quantum is **command-line only**. The wizard has no key
management — no keypair generation, no key entry, no key display — so its
Settings step points at these flags rather than offering a control it cannot
honour. `--generate-keypair` prints the public key to stdout and writes the
secret key to a file with `0600` permissions on POSIX (not on Windows — see
`SECURITY.md`).

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

Expected output: **757 passed**

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
# -> Creates morpheus_<random>.enc in the current directory

# Decrypt the file (substitute the actual name printed above)
python morpheus.py -o decrypt -f morpheus_<random>.enc
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
python morpheus.py --generate-keypair --output my_pq_secret.key
# Public key is printed; secret key lands in my_pq_secret.key (0600 on POSIX;
# on Windows the mode is not applied — see SECURITY.md)

# Encrypt with hybrid PQ
python morpheus.py -o encrypt --data "quantum safe data" \
  --hybrid-pq --pq-public-key "<public key>"
# Enter password

# Decrypt with hybrid PQ
python morpheus.py -o decrypt --data "<encrypted output>" \
  --hybrid-pq --pq-secret-key-file my_pq_secret.key
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

3. **Memory hygiene**: Key buffers are zeroed after use via `ctypes.memset`,
   in `finally` blocks so it runs on the error path too. KEM shared secrets and
   intermediate key material are also zeroed. This is best-effort, not a
   guarantee: see the limitations below.

4. **Forward uniqueness**: Every encryption produces unique output (random
   salt + nonce), even for identical inputs.

5. **Header authentication**: The full header is authenticated as AEAD
   additional data: 6 bytes in format v2, and all 18 bytes in v3 including the
   KDF parameters and reserved field. This prevents algorithm downgrade and
   parameter tampering.

### Limitations (Honest About These)

1. **Python memory model**: Python strings are immutable. While we zero
   `bytearray` buffers via `ctypes.memset`, the original password string may
   linger in Python's heap until garbage collection. For absolute memory
   security, a C/Rust implementation would be needed.

2. **Terminal scrollback**: While the GUI auto-clears, some terminals may
   retain content in their scrollback buffer. We recommend using the GUI
   in a terminal that supports secure erase or clearing scrollback.

3. **Clipboard security**: MORPHEUS does **not** clear or restore your system
   clipboard. Anything you copy stays there until you or another application
   overwrites it, and clipboard managers (macOS Paste, Windows clipboard
   history, KDE Klipper) may retain their own copies. Clear it yourself after
   pasting a password or a decrypted secret.

4. **No memory locking**: Key buffers are **not** `mlock`ed. On a machine under
   memory pressure they may be paged to swap and persist on disk after the
   process exits. Use full-disk encryption if this is in your threat model.

5. **Immutable copies inside crypto bindings**: `secure_zero` clears the
   `bytearray` buffers MORPHEUS owns, but OpenSSL and the argon2 bindings
   receive immutable `bytes` copies of key material that cannot be zeroed and
   persist until garbage collection.

6. **KDF parameter mismatch (format v2 only)**: In the legacy v2 format, KDF
   tuning parameters are not stored in the ciphertext. If you change KDF
   parameters between encrypt and decrypt, the authentication tag will fail with a
   generic error rather than a specific parameter mismatch message.

7. **Single-user focus**: The hybrid PQ mode supports two-party encryption,
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
Formats v2, v3 and v4 all decrypt; v4 is what new encryptions produce. Version
1 ciphertexts (from the original tool) are not compatible.

### "Ciphertext was created with KDF X, but pipeline is configured with Y"

The encrypted data was created with a different KDF than you're using now.
In CLI mode, specify the matching KDF with `--kdf`. In GUI mode, the cipher
and KDF are auto-detected from the header — only KDF parameters need to match.

### "Reserved header bytes must be zero"

The ciphertext header contains non-zero reserved bytes. This typically means
the data has been corrupted or was created by a different tool. Version 2
strictly validates that bytes 4-5 are `0x0000`.

### Encryption is slow

Key derivation is intentionally expensive: Argon2id allocates 64 MiB and runs
three passes over it for every derivation. This is a security feature, not a
bug. It is what makes large-scale password brute-forcing costly. If it is too
slow on your hardware, lower `memory_cost` only if you understand that you are
trading away brute-force resistance.

### File too large

File encryption supports files up to 100 MiB. For larger files, consider
splitting them first or using a streaming encryption tool.
