# MORPHEUS Ciphertext Format

**Status:** Normative. **Spec version:** 1.1. **Covers wire formats:** v2, v3, v4.
**Draft, not implemented:** v5 (see [section 17](#17-key-files-v5-draft)).

> **v5 is a draft.** Nothing writes it, nothing reads it, and there are no
> vectors for it yet. It is specified here first, deliberately, so that all
> three implementations build the same thing from the same document rather than
> one of them inventing it and the others copying. Until vectors exist and at
> least two implementations agree on them, treat every v5 statement below as a
> proposal.

This document defines the MORPHEUS ciphertext format completely enough to write
an independent implementation without reading the reference source. Where this
document and the Python implementation disagree, that is a bug in one of them
and must be resolved, not worked around: the stored vectors in `tests/vectors/`
are the tiebreaker, because they are what real archived ciphertexts look like.

The reference implementation is `morpheus_crypt/` in this repository. The
conformance suite is `tests/vectors/`. See [Conformance](#12-conformance).

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are to be interpreted
as described in RFC 2119.

---

## 1. Notation

| Notation | Meaning |
|---|---|
| `u8`, `u16`, `u32` | Unsigned integer, **big-endian** (network byte order) |
| `a \|\| b` | Concatenation |
| `LP(x)` | Length-prefixed field: `u16(len(x)) \|\| x`. `len(x)` MUST be <= 65535 |
| `0x..` | Hexadecimal literal |
| `b"..."` | Literal ASCII bytes, no terminator, no length prefix unless wrapped in `LP()` |

All multi-byte integers in this format are big-endian without exception.

`LP()` exists so that a concatenation of variable-length fields is injective.
Without it, a shorter salt followed by a longer KEM ciphertext could produce the
same byte string as a longer salt followed by a shorter one, and the value being
authenticated would be ambiguous.

---

## 2. Frozen constants

These values are part of the wire format. Changing any of them makes every
ciphertext ever written under the affected version permanently undecryptable,
and does so silently: a round-trip test suite stays entirely green. They MUST
NOT be changed. A new behaviour requires a new version byte.

| Constant | Value | Used by | Section |
|---|---|---|---|
| Chained subkey label (v2, v3) | `b"morpheus-v2-key-"` | HKDF-Expand `info` | [7.2](#72-subkey-derivation-chained-mode-only) |
| Chained subkey label (v4) | `b"morpheus-v4-key-"` | HKDF-Expand `info` | [7.2](#72-subkey-derivation-chained-mode-only) |
| Hybrid combiner label (v2, v3) | `b"hybrid-pq-v1"` | HKDF `info` | [7.3](#73-hybrid-pq-combiner) |
| Hybrid combiner label (v4) | `b"morpheus-hybrid-v4"` | HKDF `info` | [7.3](#73-hybrid-pq-combiner) |
| Key-check message (v3) | `b"morpheus-key-check"` | HMAC-SHA256 message | [8.1](#81-v3-key-check-8-bytes) |
| Commitment label (v4, v5) | `b"morpheus-cmt-v4"` | SHA-256 prefix | [8.2](#82-v4-and-v5-key-commitment-32-bytes) |
| Key-file digest label (v5, draft) | `b"morpheus-keyfile-digest-v5"` | SHA-256 prefix | [7.4](#74-key-file-combiner-v5-draft) |
| Key-file combiner label (v5, draft) | `b"morpheus-keyfile-v5"` | HKDF `info` | [7.4](#74-key-file-combiner-v5-draft) |

Note that the v3 label is the literal string `morpheus-v2-key-`. That was
probably not intended when v3 was introduced, but it is what v3 ciphertexts were
written with, so it is now part of v3's wire format and is frozen at that value.

---

## 3. Envelope

A MORPHEUS ciphertext is transported as a single-line **base64** string.

- Encoders MUST use the standard base64 alphabet (RFC 4648 section 4, with `+`
  and `/`) and MUST include `=` padding.
- Decoders MUST validate strictly and reject any character outside the alphabet.
  A decoder that silently discards unknown characters will accept corrupted
  input and produce a confusing downstream error.
- No line wrapping is applied. No URL-safe variant is defined.

After base64 decoding, the byte string is:

```
header || payload
```

Plaintext is UTF-8 encoded text. The format carries no charset field and no
declaration of plaintext length outside the padding scheme in
[section 10](#10-padding).

Because the format is text-oriented, encrypting a *file* requires one more
layer: the bytes and the original filename are wrapped in a small JSON object
which is then encrypted as ordinary UTF-8 plaintext. That layer is specified in
[section 16](#16-file-transport-envelope). It sits above everything described
here and does not change any of it.

---

## 4. Header

The first byte is always the version. A parser MUST read it before assuming any
header size.

### 4.1 v2 header (6 bytes)

```
offset  size  field
0       1     version      = 0x02
1       1     cipher_id
2       1     kdf_id
3       1     flags
4       2     reserved     = 0x0000
```

### 4.2 v3, v4 and v5 header (18 bytes)

v4 and v5 reuse the v3 header layout unchanged. Only the version byte, the
width of the key-check field, the AAD construction and (for v5) the key
derivation differ. Keeping one header layout across three versions means a
parser needs no new branch for any of them.

```
offset  size  field
0       1     version      = 0x03 (v3), 0x04 (v4) or 0x05 (v5, draft)
1       1     cipher_id
2       1     kdf_id
3       1     flags
4       2     reserved     = 0x0000
6       4     kdf_param1   u32
10      4     kdf_param2   u32
14      4     kdf_param3   u32
```

### 4.3 Parsing rules

A decoder MUST:

1. Reject input shorter than 6 bytes.
2. Reject a version byte not in {`0x02`, `0x03`, `0x04`}. Once v5 ships, add
   `0x05`.
3. Reject v3, v4 or v5 input shorter than 18 bytes.
4. Reject a non-zero `reserved` field. This keeps the two bytes genuinely
   available for a future version instead of quietly becoming a channel for
   unauthenticated data.

The header is not authenticated at the point it is read. Everything a decoder
does before verifying the AEAD tag is done on attacker-chosen values. That is
why [section 11](#11-kdf-parameter-bounds) puts hard bounds on the KDF
parameters: they are read from this header and drive a memory-hard allocation.

---

## 5. Registries

### 5.1 cipher_id

| ID | Meaning | Key size | Nonce size | Tag size |
|---|---|---|---|---|
| `0x01` | AES-256-GCM | 32 | 12 | 16 |
| `0x02` | ChaCha20-Poly1305 (RFC 8439) | 32 | 12 | 16 |
| `0x03` | Chained AES-256-GCM then ChaCha20-Poly1305 | 32 each | 12 each | 16 each |

`0x03` is a header marker only, not a cipher object. When it appears, the
`FLAG_CHAINED` flag MUST also be set, and the chain order is fixed at
AES-256-GCM as primary followed by ChaCha20-Poly1305 as secondary. The order is
not negotiable and is not carried on the wire.

### 5.2 kdf_id

| ID | Meaning | Salt size | `kdf_param1` | `kdf_param2` | `kdf_param3` |
|---|---|---|---|---|---|
| `0x01` | Scrypt (RFC 7914) | 16 | `n` | `r` | `p` |
| `0x02` | Argon2id (RFC 9106) | 16 | `time_cost` | `memory_cost` (KiB) | `parallelism` |

Both KDFs produce a 32-byte output. Salt size is 16 bytes for both.

**Reference defaults for new ciphertexts** (v4):

| KDF | Parameters |
|---|---|
| Argon2id | `time_cost=3`, `memory_cost=65536` (64 MiB), `parallelism=4` |
| Scrypt | `n=131072` (2^17), `r=8`, `p=1` |

Argon2id is the default KDF. These defaults are the single largest porting risk
for a non-Python implementation: Argon2id is not in the Swift standard library
or in CryptoKit, so an implementation MUST supply its own and MUST match these
parameters and the Argon2 **id** variant exactly. A mismatch in any one of them
produces a different key and nothing decrypts, with no diagnostic beyond
"incorrect password". See [section 12](#12-conformance).

### 5.3 flags

| Bit | Mask | Name | Introduced |
|---|---|---|---|
| 0 | `0x01` | `FLAG_CHAINED` | v2 |
| 1 | `0x02` | `FLAG_HYBRID_PQ` | v2 |
| 2 | `0x04` | `FLAG_PADDED` | v3 |

Bits 3 to 7 are unassigned. This version of the spec does not require a decoder
to reject them, and the reference implementation does not, but they are covered
by the AAD in every version, so an attacker cannot set one without invalidating
the tag.

---

## 6. Payload layout

The payload field order is identical across all three versions. Only the
presence and width of the key-check field varies.

```
salt            16 bytes           always
nonce1          12 bytes           always (primary cipher)
nonce2          12 bytes           only if FLAG_CHAINED
kem_len         2 bytes  (u16)     only if FLAG_HYBRID_PQ
kem_ct          kem_len bytes      only if FLAG_HYBRID_PQ
key_check       0 / 8 / 32 bytes   v2: absent, v3: 8, v4 and v5: 32
body            remainder          AEAD output(s) including tag(s)
```

`kem_prefix` denotes `kem_len || kem_ct` taken together, and is `b""` when
`FLAG_HYBRID_PQ` is clear. It is referenced by that name in
[section 9](#9-additional-authenticated-data-aad).

`body` is the output of the primary cipher, or for chained mode the output of
the secondary cipher applied to the output of the primary. It always includes
the AEAD tag or tags, so for a single cipher `len(body) == len(padded_plaintext)
+ 16` and for chained mode `len(body) == len(padded_plaintext) + 32`.

A decoder MUST reject a payload that is too short for the fields the flags
require, MUST reject `kem_len == 0` when `FLAG_HYBRID_PQ` is set, and MUST
reject an empty `body`.

### 6.1 ML-KEM-768 sizes

Hybrid mode uses ML-KEM-768 (FIPS 203, k = 3).

| Object | Size |
|---|---|
| Encapsulation key (public), `ek` | 1184 bytes |
| Decapsulation key (secret), `dk` | 2400 bytes |
| KEM ciphertext, `kem_ct` | 1088 bytes |
| Shared secret | 32 bytes |

`kem_len` is a `u16` field rather than a constant so that the format is not
pinned to one KEM parameter set. An encoder MUST reject a `kem_ct` longer than
65533 bytes, because what gets length-prefixed into the v4 AAD is `kem_prefix`
(which is 2 bytes longer than `kem_ct`), and `LP()` tops out at 65535.

`dk` embeds its own `ek` at `dk[1152:2336]`, and `SHA3-256(ek)` at
`dk[2336:2368]`. The v4 hybrid combiner relies on the first of these to recover
the encapsulation key locally at zero cost in wire bytes.

### 6.2 Worked size examples

Taken from the stored vectors. `pt` is the UTF-8 plaintext length.

| Case | Payload composition | Bytes |
|---|---|---|
| v2, single cipher, `pt`=19 | 16 + 12 + 0 + (19+16) | 63 |
| v3, single cipher, `pt`=19 | 16 + 12 + 8 + (19+16) | 71 |
| v4, single cipher, `pt`=19 | 16 + 12 + 32 + (19+16) | 95 |
| v4, chained, `pt`=20 | 16 + 12 + 12 + 32 + (20+32) | 124 |
| v4, padded, `pt`=19 | 16 + 12 + 32 + (256+16) | 332 |
| v4, hybrid, `pt`=19 | 16 + 12 + 2 + 1088 + 32 + (19+16) | 1185 |
| v4, hybrid + chained, `pt`=14 | 16 + 12 + 12 + 2 + 1088 + 32 + (14+32) | 1208 |

---

## 7. Key derivation

### 7.1 Password key

```
master = KDF(password_utf8, salt, output_length = 32)
```

`KDF` is selected by `kdf_id` and parameterised by the three header parameters.
For v2 the header carries no parameters, so the decrypting implementation MUST
be configured with the parameters used at encryption time and MUST verify that
its configured `kdf_id` matches the header (there is nothing else to check
against).

**When `FLAG_CHAINED` is clear, `master` is used directly as the encryption
key. No HKDF step is applied.** This is easy to get wrong when porting, because
the chained path does apply one.

### 7.2 Subkey derivation (chained mode only)

When `FLAG_CHAINED` is set, two keys are derived from `master` with HKDF-Expand.
`master` is used directly as the pseudorandom key. **There is no HKDF-Extract
step here.**

```
label = b"morpheus-v4-key-"   if version == 4
        b"morpheus-v2-key-"   if version == 2 or 3

for i in 0, 1:
    info_i = label || ascii(i) || salt
    key_i  = HKDF-Expand(hash = SHA-256, prk = master, info = info_i, L = 32)
```

`ascii(i)` is the single ASCII digit character, so `info_0` for v4 is
`b"morpheus-v4-key-0" || salt`, which is 17 + 16 = 33 bytes.

`key_0` is the AES-256-GCM key, `key_1` is the ChaCha20-Poly1305 key.
Implementations SHOULD zero `master` once the subkeys exist.

### 7.3 Hybrid PQ combiner

When `FLAG_HYBRID_PQ` is set, every key from 7.1 or 7.2 is replaced by the
output of a combiner over that key and the ML-KEM-768 shared secret. This uses
full HKDF, meaning Extract followed by Expand.

```
ss = ML-KEM-768.Decaps(dk, kem_ct)          # 32 bytes

info = b"hybrid-pq-v1"                                       if version == 2 or 3
       b"morpheus-hybrid-v4" || LP(kem_ct) || LP(ek) || LP(aad)   if version == 4

key_i' = HKDF(hash = SHA-256,
              ikm  = key_i || ss,           # 64 bytes
              salt = salt,                  # the 16-byte payload salt
              info = info,
              L    = 32)
```

Notes that a porting implementation MUST get right:

- The HKDF `salt` is the payload salt, the same 16 bytes used for the password
  KDF. It is not a fresh value and it is not empty.
- `LP(kem_ct)` wraps the **bare** KEM ciphertext, not `kem_prefix`. This differs
  from the AAD in [section 9](#9-additional-authenticated-data-aad), which wraps
  `kem_prefix`. The two are not interchangeable.
- `ek` is the 1184-byte encapsulation key. The encryptor has it directly. The
  decryptor recovers it from `dk[1152:2336]`. It is never transmitted.
- `aad` is the fully constructed v4 AAD from section 9, which is available
  before any key exists, so there is no circular dependency.
- In chained hybrid mode both keys are combined, each with the same `info`.

**Why v4 changed this.** NIST SP 800-227 (final, September 2025) section 4.6.3
states that a combiner of the form `K <- KDF(K1, K2)` over the shared secrets
alone does not preserve IND-CCA security regardless of the KDF, and recommends
binding both ciphertexts and both encapsulation keys along with a domain
separator. v3's `b"hybrid-pq-v1"` form is that negative example. There is no
live attack on v3 here, since this is an offline tool with no decapsulation
oracle and mutating `kem_ct` already yields a different shared secret, but a
tool published for quantum resistance should not ship the construction the
current recommendation prints as what not to do.

---

### 7.4 Key file combiner (v5, draft)

**Applies only to v5.** A v5 ciphertext always requires a key file; see
[section 17](#17-key-files-v5-draft) for what a key file is and why the version
byte carries this rather than a flag.

The key file is folded in **once**, between the password KDF and everything
downstream, so chaining and hybrid mode compose with it unchanged:

```
digest  = SHA-256( b"morpheus-keyfile-digest-v5" || key_file_bytes )

master' = HKDF(hash = SHA-256,
               ikm  = master || digest,        # 64 bytes
               salt = salt,                    # the 16-byte payload salt
               info = b"morpheus-keyfile-v5",
               L    = 32)
```

`master'` then replaces `master` everywhere: section 7.2 expands it into
subkeys for chained mode, and section 7.3 combines it with the KEM shared
secret for hybrid mode. Both use their **v4** labels unchanged, because
`master'` already differs from any v4 master and the version byte is
authenticated in the AAD, so a fresh subkey label would add a frozen string
that buys nothing.

Four things an implementation MUST get right:

1. **The digest is not length-prefixed**, unlike every other variable field in
   this format. It does not need to be: `key_file_bytes` is the only
   variable-length input and it sits at the end, after a fixed-length label,
   so the concatenation is already injective. A length prefix would also cap
   key files at 65535 bytes, and there is no reason to.
2. **The key file is hashed, not stretched.** It goes through plain SHA-256
   rather than Argon2id. The memory-hard KDF exists to slow down guessing a
   low-entropy password; a key file with real entropy cannot be guessed at all,
   so spending 64 MiB on it buys nothing and would double the cost of every
   operation.
3. **The HKDF salt is the payload salt**, the same 16 bytes the password KDF
   used. So two ciphertexts made from the same password and the same key file
   still produce different keys.
4. **An empty key file MUST be rejected** at encryption time. Hashing zero
   bytes is well defined, which is exactly the problem: it would silently
   produce a valid ciphertext with no second factor at all, and the user would
   believe they had one.

---

## 8. Key verification

This field answers "is this the right key". It is verified **before** the AEAD
so that a wrong password stays distinguishable from tampered data. The AEAD tag
answers the separate question "has anything been modified".

Keeping those two questions separate is deliberate and load-bearing. A
verification value that also covered fields the AEAD tag already authenticates
would make nonce or header tampering fail here rather than at the tag, and be
reported to the user as an incorrect password.

The value is computed over the **final** keys, meaning after the hybrid
combiner in 7.3 has been applied, if it applies.

### 8.1 v3 key-check (8 bytes)

```
key_check = HMAC-SHA256(key = key_0, message = b"morpheus-key-check")[0:8]
```

Only `key_0` is bound, including in chained mode.

### 8.2 v4 and v5 key commitment (32 bytes)

```
key_1_or_empty = key_1 if FLAG_CHAINED else b""

commitment = SHA-256( b"morpheus-cmt-v4" || LP(key_0) || LP(key_1_or_empty) )
```

For a single cipher the trailing field is `LP(b"")`, which is the two bytes
`0x0000`. It is present, not omitted.

v5 uses this unchanged. Because the key file feeds into the keys through
section 7.4, the commitment covers it transitively: a wrong key file yields
different keys and therefore a different commitment. Nothing about the key file
is stored separately, and [section 17.2](#172-no-key-file-fingerprint-is-stored)
explains why that is deliberate.

**Why 32 bytes.** Neither AES-GCM nor ChaCha20-Poly1305 is a committing AEAD,
and efficient key multi-collision attacks against both are published (Len,
Grubbs and Ristenpart, USENIX Security 2021; the file-shaping half in Albertini
et al., USENIX Security 2022). RFC 9771 section 4.3.3 names password-based
encryption as an application that needs key commitment. By the size relation in
Bellare and Hoang (CRYPTO 2024), s bits of committing security needs 2s bits of
expansion, so v3's 64 bits give roughly 32: enough to tell a wrong password from
a right one, nowhere near enough to stop a deliberately constructed ciphertext
that opens to two plausible plaintexts under two passwords. 32 bytes puts that
at 2^128 work.

Chained mode binds both subkeys because committing to the first alone would
leave the second free.

Comparison MUST be constant-time.

---

## 9. Additional Authenticated Data (AAD)

The same AAD is passed to every AEAD call in a given ciphertext, including both
calls in chained mode.

### 9.1 v2

```
aad = header[0:6]
```

### 9.2 v3

```
aad = header[0:18]
```

### 9.3 v4 and v5

```
aad = header[0:18] || LP(salt) || LP(kem_prefix)
```

v5 is identical. The key file needs nothing here: it is already bound through
the key by section 7.4, and putting a function of it in the AAD would write a
value derived from a long-term secret onto the wire in the clear.

where `kem_prefix` is `kem_len || kem_ct` as defined in
[section 6](#6-payload-layout), and is `b""` when `FLAG_HYBRID_PQ` is clear.

**The KEM field is length-prefixed twice, and that is not a mistake.**
`kem_prefix` already begins with its own `u16` length. `LP()` then adds another.
For ML-KEM-768 the v4 AAD therefore ends with:

```
0x04 0x42        LP length = 1090 = len(kem_prefix)
0x04 0x40        kem_len   = 1088 = len(kem_ct)
<1088 bytes>     kem_ct
```

Resulting AAD lengths for ML-KEM-768:

| Case | AAD length |
|---|---|
| v4, not hybrid | 18 + 2 + 16 + 2 = **38** |
| v4, hybrid | 18 + 2 + 16 + 2 + 1090 = **1128** |

Nonces are deliberately absent from the AAD in every version. An AEAD already
authenticates its own nonce, and including it would force nonce generation to
happen before the cipher call for no gain.

**What v4 added and why.** v2 and v3 authenticate every header byte, which is
what stops cipher, KDF, flag and parameter downgrade. But the salt and the KEM
ciphertext live in the payload, so under v3 the tag did not cover them, and the
accurate claim "every header byte is authenticated" was narrower than a reader
would assume. v4 covers both.

---

## 10. Padding

Applied to the UTF-8 plaintext **before** encryption, and only when
`FLAG_PADDED` is set. Padding hides the exact plaintext length by quantising it.

Buckets: 256, 1024, 4096, 16384, 65536.

### 10.1 Choosing the target

**Bucket mode** (the `--pad` behaviour): the target is the smallest bucket
strictly greater than the input length. For input at or above 65536, the target
is the next multiple of 65536 strictly above the input length.

**Fixed-size mode** (the `--fixed-size` behaviour): the target is always 65536.
Input longer than 65532 bytes MUST be rejected, since the length-prefix scheme
below needs 4 bytes.

The target is always strictly greater than the input length, so `pad_len >= 1`
in every case.

### 10.2 Applying padding

Let `pad_len = target - len(data)`.

- If `pad_len <= 255`: **PKCS#7.** Append `pad_len` copies of the byte
  `pad_len`.
- If `pad_len > 255`: **length-prefix.** Emit `u32(len(data)) || data ||
  0x00 * (target - len(data) - 4)`.

### 10.3 Removing padding

Inspect the **last byte** of the decrypted buffer:

- `0x00`: length-prefix mode. The first 4 bytes are a `u32` original length.
  Reject if that length exceeds the available data.
- `0x01` to `0xFF`: PKCS#7 mode. That byte is `pad_len`. Reject if `pad_len`
  exceeds the buffer length, or if the final `pad_len` bytes are not all equal
  to `pad_len`.

The two modes can never be confused, because in length-prefix mode every fill
byte is `0x00` so the last byte is always `0x00`, and in PKCS#7 mode `pad_len`
is in [1, 255] so the last byte is never `0x00`.

An empty buffer MUST be rejected.

---

## 11. KDF parameter bounds

The v3 and v4 headers carry KDF parameters that a decoder reads and allocates
against **before** it can authenticate anything. Those values come from whoever
produced the file. An implementation MUST bound them.

### 11.1 Per-parameter bounds

| KDF | Parameter | Range |
|---|---|---|
| Argon2id | `time_cost` | 1 to 100 |
| Argon2id | `memory_cost` (KiB) | 1024 to 1048576 |
| Argon2id | `parallelism` | 1 to 64 |
| Scrypt | `n` | 1024 to 8388608 |
| Scrypt | `r` | 1 to 64 |
| Scrypt | `p` | 1 to 64 |

### 11.2 Working-set bound

Per-parameter bounds alone are not sufficient, because Scrypt's cost is a
product. The implied allocation MUST also be bounded at 1 GiB:

- Argon2id: `memory_cost * 1024` bytes.
- Scrypt: `128 * r * (n + p)` bytes.

### 11.3 Cost bound

Memory bounds alone leave CPU unbounded. Argon2id at `t=100, m=1 GiB, p=64`
sits inside every rule above and costs minutes of CPU on a file that may be
entirely fabricated. An implementation MUST also bound the product:

| KDF | Cost expression | Ceiling |
|---|---|---|
| Argon2id | `time_cost * memory_cost` | 3145728 (`3 * 65536 * 16`) |
| Scrypt | `n * r * p` | 16777216 (`2^17 * 8 * 1 * 16`) |

Both ceilings are 16x what the reference defaults produce, so every ciphertext
any released version has written decrypts well inside them and deliberate
hardening has room. An implementation MAY offer an explicit opt-out for a file
the user knows is genuinely theirs (the reference CLI spells this
`--allow-expensive-kdf`), and that opt-out MUST be off by default.

An encoder SHOULD apply the same bounds at encryption time. Producing a
ciphertext whose parameters no decoder will accept costs the data.

---

## 12. Conformance

`tests/vectors/` is the conformance suite. It contains stored ciphertexts with
their passwords and expected plaintexts.

**The contract: decrypt every vector to its recorded plaintext and you are
compatible with MORPHEUS.** There is no other conformance claim to make.

| File | Version | Cases | Covers |
|---|---|---|---|
| `v2.json` | 2 | 3 | AES and ChaCha single cipher, Argon2id and Scrypt, chained |
| `v3.json` | 3 | 7 | The above plus hybrid PQ, hybrid + chained |
| `v4.json` | 4 | 8 | The above plus padded |
| `v5.json` | 5 | none yet | **Draft.** v5 cannot ship until this file exists |

Each file is `{format_version, note, cases}`. Each case carries `name`,
`plaintext`, `password`, `ciphertext` (base64), `cipher`, `kdf`, `kdf_params`,
`chain`, `hybrid_pq`, and for hybrid cases `pq_secret_key` (base64).

The vectors deliberately use weak KDF parameters (`time_cost=1,
memory_cost=1024, parallelism=1`) so the suite runs fast. **Those are test
parameters, not recommendations.** A conforming implementation MUST read the
parameters from the header rather than assuming the defaults in
[section 5.2](#52-kdf_id). An implementation that hardcodes the defaults passes
nothing.

### 12.1 Rules for the vectors

These rules exist because the vectors are the only artifact in the project that
can detect a silent compatibility break. Every other crypto test round-trips
in-process, which proves self-consistency and proves nothing about
compatibility.

1. **`v2.json` and `v3.json` MUST NOT be regenerated.** They were produced by
   the implementations that shipped those versions. Regenerating them is
   exactly how a format break gets hidden, because the obvious move when this
   suite goes red under time pressure is to re-record it.
2. A format change MUST get its own version byte and its own vector file. The
   old files stay untouched and MUST keep decrypting.
3. Every version that a decoder accepts MUST have stored vectors. The reference
   suite derives this check from the accepted-version set rather than listing
   versions by hand, so adding a version forces vectors for it.
4. Every ciphertext in a file MUST carry that file's version byte on the wire.
   This is what makes an accidental regeneration fail loudly instead of
   silently rewriting older vectors as the current version.

`v4.json` was regenerated once, after an adversarial review corrected the
commitment to bind key material only. That was safe solely because v4 was
unreleased and untagged at the time. After a release tag it would have required
a v5.

---

## 13. Version history

| Version | Byte | Changes |
|---|---|---|
| v2 | `0x02` | Original. 6-byte header, no KDF parameters on the wire, no key verification field. AAD covers the header only. |
| v3 | `0x03` | 18-byte header carrying KDF parameters, so a ciphertext is self-describing. Adds the 8-byte key-check, which is what gives a wrong password a distinct error from tampering. Adds `FLAG_PADDED`. |
| v4 | `0x04` | Same header as v3. Widens key verification to a 32-byte commitment. Extends the AAD over the salt and the KEM prefix. Replaces the hybrid combiner with the NIST SP 800-227 section 4.6.3 form. New chained subkey label. |
| v5 | `0x05` | **Draft, not implemented.** Same header, payload, AAD and commitment as v4. Adds a mandatory key file as a second factor, folded in by [section 7.4](#74-key-file-combiner-v5-draft). No other change. |

v4 is the only version the reference implementation emits. v2 and v3 remain
decryptable and MUST stay that way.

### 13.1 Rules for a future version

1. Allocate a new version byte. Do not repurpose flags, reserved bytes or
   labels to change the meaning of an existing version.
2. Add vectors for it. Leave every older vector file untouched and decrypting.
3. Update this document in the same change. A format that is only described by
   its implementation is not a specification.
4. If this repository ever goes private, this document and `tests/vectors/`
   MUST travel with the public implementation. A cryptographic tool whose
   format is documented only where nobody can read it is not verifiable.

---

## 14. Security properties and non-goals

**Provided:**

- Confidentiality and integrity of the plaintext under a password, via a
  memory-hard KDF and an AEAD.
- Downgrade resistance across cipher, KDF, flags and (in v3 and v4) KDF
  parameters, because the AAD covers every header byte.
- Key commitment (v4), so a ciphertext cannot be constructed to open to two
  plausible plaintexts under two passwords.
- Optional confidentiality against a future quantum adversary, via ML-KEM-768
  combined with the password-derived key. Hybrid mode is not weaker than
  password-only mode: an attacker must break both.
- Optional plaintext length hiding, via padding.

**Not provided:**

- **Authentication of the sender.** Hybrid mode encrypts to a recipient's public
  key but signs nothing. An attacker who substitutes their own encapsulation key
  substitutes a valid one. The FIPS 203 key checks in the reference
  implementation catch corruption, not substitution.
- **Protection against a compromised endpoint.** Password and plaintext are in
  process memory.
- **Deniability**, **forward secrecy**, or any property depending on an
  interactive protocol. This is an offline file and text format.
- **Traffic analysis resistance beyond padding.** Without `FLAG_PADDED` the
  ciphertext length reveals the plaintext length exactly.

---

## 15. Implementation checklist

For a from-scratch implementation, in dependency order:

1. Base64 with strict validation.
2. Header parse and serialise, both sizes, with the reserved-bytes check.
3. Argon2id and Scrypt at the exact parameters from the header, with the bounds
   in [section 11](#11-kdf-parameter-bounds).
4. AAD construction per version, including the double length prefix on the KEM
   field in v4.
5. AES-256-GCM and ChaCha20-Poly1305 with 12-byte nonces and 16-byte tags.
6. Key commitment and constant-time comparison, verified before the AEAD.
7. Payload parse with every truncation check from
   [section 6](#6-payload-layout).
8. Padding, both modes.
9. HKDF-Expand subkey derivation for chained mode. Watch that the single-cipher
   path uses the KDF output directly with no HKDF step.
10. ML-KEM-768 and the v4 combiner, including recovering `ek` from
    `dk[1152:2336]`.

Steps 1 to 8 cover every non-hybrid vector. Add 9 for the chained vectors and
10 for the hybrid ones.

On Apple platforms, CryptoKit covers AES-GCM, ChaCha20-Poly1305, SHA-256, HMAC
and HKDF; swift-crypto covers ML-KEM. Argon2id has no first-party
implementation and must be supplied. Scrypt is required only to decrypt
existing Scrypt ciphertexts, not to produce new ones.

---

## 16. File transport envelope

A layer **above** the ciphertext format, not part of it. Nothing in sections 1
to 15 changes because of this section, and an implementation that only ever
handles text can ignore it entirely.

The ciphertext format carries UTF-8 text. Encrypting a file therefore needs
somewhere to put the bytes and the original name, and that is this envelope: a
JSON object which is serialised, then encrypted exactly like any other
plaintext.

```json
{"envelope_version": 1, "data": "<base64 of the file bytes>", "filename": "report.pdf"}
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `envelope_version` | integer | yes | Currently `1` |
| `data` | string | yes | Standard base64 of the file's bytes |
| `filename` | string | no | Basename only. Omitted when the sender chooses not to disclose it |

Key order and whitespace are not significant: this is parsed, never compared
byte for byte.

### 16.1 Decoding MUST be strict

A decoder receives plaintext that may or may not be an envelope, and **the
common case is that it is not**. Ordinary plaintext that merely resembles the
schema has to survive untouched.

An implementation MUST treat the plaintext as an envelope only when every one
of the following holds, and MUST otherwise return it unchanged as text:

1. It parses as JSON, **and** the top-level value is an object. A JSON array or
   scalar is not an envelope.
2. `envelope_version` is present and is an integer. A boolean MUST NOT be
   accepted, which matters in languages where `true` and `1` share a numeric
   type after parsing.
3. `envelope_version` is at least 1.
4. `data` is present, is a string, and decodes as **strictly validated**
   base64. A decoder that skips characters outside the alphabet MUST NOT be
   used here.
5. If `filename` is present it is a string of at most 255 characters.

The single exception: when the object is a well-formed envelope whose
`envelope_version` is **greater** than the implementation supports, it MUST
raise an error naming the version rather than returning the JSON as text.
Showing a wall of JSON to someone whose file was written by a newer build is
strictly worse than telling them to update.

These rules are not stylistic. Each corresponds to a defect a looser parser
produced: a plaintext that was a JSON list crashed the decoder; a document
containing a `data` key was mistaken for a file and written to disk, destroying
the user's actual JSON; and unvalidated base64 silently dropped characters.

### 16.2 Filenames are attacker-controlled

`filename` arrives inside someone else's ciphertext. Before it reaches any
filesystem call it MUST be reduced to a safe basename:

1. Replace `\` with `/` first. A POSIX basename leaves `..\..\x` intact.
2. Take the last path component.
3. Remove any character that is not printable, plus `/` and NUL. Terminal
   control sequences in a filename are a display attack in their own right.
4. Strip leading and trailing `.` and space characters.
5. Reject the results `""`, `"."` and `".."`.
6. Reject Windows reserved device names, compared case-insensitively against
   the stem before the first `.`: `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`,
   `LPT1`-`LPT9`. These are reserved even with an extension, so `NUL.txt` is
   rejected too.
7. Truncate to 255 characters.

When nothing usable survives, the implementation MUST fall back to a generated
name rather than writing to whatever is left.

### 16.3 Decrypted files MUST NOT be written implicitly

Decrypting produces bytes in memory. An implementation MUST NOT write them to
disk as a side effect of decryption, because that puts plaintext on disk
whether or not the user wanted it there. Writing is a separate, explicit step.

---

## 17. Key files (v5, draft)

> Draft. Nothing implements this yet and there are no vectors. See the note at
> the top of this document.

A **key file** is a second factor: something you have, alongside the password
you know. Decrypting a v5 ciphertext requires both. Losing either loses the
data, which is the point and also the risk.

The mechanism is [section 7.4](#74-key-file-combiner-v5-draft). This section is
everything else an implementation has to get right.

### 17.1 What a key file is

Any file, of any type and any length above zero. Its bytes are hashed exactly
as they are on disk. There is no format, no header and no magic number,
deliberately: a key file that announces itself is a key file an adversary can
find on a disk.

- Implementations SHOULD offer to **generate** one, and a generated key file
  MUST be exactly 32 bytes from a cryptographic RNG. That is the output width
  of the digest, so more bytes add no strength.
- A generated key file SHOULD have no extension, or an unremarkable one. Do not
  name it `morpheus.key`.
- Implementations MUST reject a **zero-length** key file, at encryption time,
  with an error. Hashing nothing is well defined, and that is the danger: it
  would produce a perfectly valid ciphertext whose second factor is a constant,
  while the user believes they have one.
- Implementations MUST NOT modify, move or rewrite a user-supplied key file.
  A user may reasonably point this at a photograph they already have.

**The warning that MUST accompany the feature:** if the key file changes by a
single byte, the data is unrecoverable. Files get re-encoded, re-saved,
synced, stripped of metadata and "optimised" by the software that holds them.
Pointing this at a photo in a cloud photo library is a way to lose data, and an
implementation that offers to pick an arbitrary file SHOULD say so at the
moment of choosing.

### 17.2 No key file fingerprint is stored

A v5 ciphertext records **nothing** about which key file it needs. Not a hash,
not a truncated hash, not a random identifier.

This is a deliberate refusal, and it has a cost worth stating plainly: when
decryption fails, an implementation cannot tell the user whether the password
or the key file was wrong. It MUST say so honestly, with wording along the
lines of *"the password or the key file is not correct"*, and MUST NOT guess.

The cost is accepted because the alternative is worse. Any stored fingerprint,
however short, makes two ciphertexts encrypted under the same key file
**linkable** by anyone holding both. That turns a key file into a persistent
identifier across everything it protects, which is exactly the property someone
using a second factor is trying to avoid. It would also let an adversary who
has a candidate key file confirm it offline without touching the password.

The key commitment in [section 8.2](#82-v4-and-v5-key-commitment-32-bytes)
already answers "are these the right keys". It does so without revealing which
of the two inputs was wrong, and that is the correct amount of information to
publish.

### 17.3 Why a new version and not a flag on v4

Bits 3 to 7 of the flags field are unassigned, and
[section 5.3](#53-flags) says a decoder is not required to reject them. So a v4
ciphertext with a new "key file" flag set would be accepted by every existing
v4 decoder, which would then derive the key without the key file, fail the
commitment, and report **"incorrect password"** to a user whose password was
perfectly correct.

A version byte is refused loudly by exactly the same decoders. Loud is correct
here: the ciphertext genuinely cannot be read by an implementation that does
not know about key files.

Note the consequence for the flags field: because bits 3 to 7 are explicitly
tolerated by existing decoders, **no future flag bit can ever change how a
ciphertext is decrypted**. Flags may only ever describe something a decoder can
safely ignore. Anything else needs a version byte. That constraint was already
true and is written down here because it is not obvious.

### 17.4 Why v5 has no "key file optional" mode

v5 always requires a key file. There is no flag to turn it off, and a v5
ciphertext without one is not a thing.

The alternative was a v5 that supports key files optionally, which would make a
v5-without-key-file byte-for-byte equivalent to v4 apart from the version byte:
two ways to express one thing, two paths to test, and a reader having to check
a flag to know what a version means. If there is no key file, write v4.

### 17.5 What v5 does not change

Everything else is v4, unchanged: the 18-byte header layout, the payload field
order, the AAD construction, the 32-byte commitment, the padding scheme, the
KDF parameter bounds, the cipher and KDF registries, and the file transport
envelope. An implementation that already does v4 needs
[section 7.4](#74-key-file-combiner-v5-draft) and nothing else.

### 17.6 Checklist before v5 stops being a draft

1. Generate `tests/vectors/v5.json` from whichever implementation lands first,
   covering at minimum: single cipher, chained, padded, hybrid, hybrid plus
   chained, and both KDFs.
2. Get a **second** implementation decrypting those vectors without having seen
   the first one's source. That is the only evidence this document is precise
   enough, and it is the same bar v4 was held to.
3. Add a case with a deliberately wrong key file, asserting the error is the
   ambiguous one from [section 17.2](#172-no-key-file-fingerprint-is-stored)
   rather than something that leaks which factor failed.
4. Add a case rejecting a zero-length key file at encryption time.
5. Remove the draft banners from this document and from section 2, and add
   `0x05` to the accepted-version set in
   [section 4.3](#43-parsing-rules).
6. Only then may any implementation write a v5 ciphertext.
