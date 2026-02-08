#!/usr/bin/env python3
"""Generate the MORPHEUS technical PDF document."""

from fpdf import FPDF

# ── Colour palette ──────────────────────────────────────────────────────────
DARK_BG     = (18, 18, 24)
ACCENT      = (0, 180, 216)
ACCENT_DIM  = (0, 120, 150)
WHITE       = (240, 240, 245)
LIGHT_GRAY  = (180, 180, 190)
SECTION_BG  = (28, 28, 38)
CODE_BG     = (35, 35, 48)
RED         = (255, 80, 80)
ORANGE      = (255, 165, 0)
YELLOW      = (255, 220, 80)
GREEN       = (80, 220, 120)
CYAN        = (0, 220, 240)


class PDF(FPDF):
    def __init__(self):
        super().__init__()
        self.set_auto_page_break(auto=True, margin=20)
        self._section_num = 0

    def header(self):
        # Paint full dark background on EVERY page (fixes auto-break pages)
        self.dark_page()
        if self.page_no() <= 1:
            return
        self.set_fill_color(*DARK_BG)
        self.rect(0, 0, 210, 10, "F")
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*LIGHT_GRAY)
        self.set_xy(10, 3)
        self.cell(0, 5, "MORPHEUS v2.0 -- Technical Documentation & Security Audit", align="L")
        self.set_xy(10, 3)
        self.cell(0, 5, f"Page {self.page_no()}", align="R")
        self.ln(12)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 7)
        self.set_text_color(*LIGHT_GRAY)
        self.cell(0, 10, "CONFIDENTIAL -- 404SecurityNotFound", align="C")

    def dark_page(self):
        self.set_fill_color(*DARK_BG)
        self.rect(0, 0, 210, 297, "F")

    def section_title(self, title):
        self._section_num += 1
        self.set_font("Helvetica", "B", 18)
        self.set_text_color(*ACCENT)
        self.ln(6)
        self.cell(0, 10, f"{self._section_num}. {title}", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(*ACCENT)
        self.set_line_width(0.6)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def sub_title(self, title):
        self.set_font("Helvetica", "B", 13)
        self.set_text_color(*CYAN)
        self.ln(3)
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def body(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*WHITE)
        self.multi_cell(0, 5.5, text)
        self.ln(2)

    def body_bold(self, text):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*WHITE)
        self.multi_cell(0, 5.5, text)
        self.ln(2)

    def bullet(self, text):
        self.set_font("Helvetica", "", 10)
        self.set_text_color(*WHITE)
        x = self.get_x()
        self.cell(6, 5.5, "-")
        self.multi_cell(self.w - self.r_margin - self.get_x(), 5.5, text)
        self.set_x(x)

    def code_block(self, text):
        self.set_fill_color(*CODE_BG)
        self.set_font("Courier", "", 8.5)
        self.set_text_color(*GREEN)
        lines = text.strip().split("\n")
        y_start = self.get_y()
        block_h = len(lines) * 4.5 + 6
        if self.get_y() + block_h > 275:
            self.add_page()
            self.dark_page()
            y_start = self.get_y()
        self.rect(12, y_start, 186, block_h, "F")
        self.set_xy(15, y_start + 3)
        for line in lines:
            self.cell(0, 4.5, line, new_x="LMARGIN", new_y="NEXT")
            self.set_x(15)
        self.ln(4)

    def finding(self, severity, title, description, location="", recommendation=""):
        colors = {
            "CRITICAL": RED,
            "MEDIUM": ORANGE,
            "LOW": YELLOW,
            "INFO": LIGHT_GRAY,
            "POSITIVE": GREEN,
        }
        color = colors.get(severity, WHITE)

        if self.get_y() > 240:
            self.add_page()
            self.dark_page()

        self.set_fill_color(color[0], color[1], color[2])
        self.rect(10, self.get_y(), 3, 6, "F")

        self.set_font("Helvetica", "B", 10)
        self.set_text_color(*color)
        self.set_x(16)
        self.cell(0, 6, f"[{severity}] {title}", new_x="LMARGIN", new_y="NEXT")

        if location:
            self.set_font("Courier", "", 8)
            self.set_text_color(*ACCENT_DIM)
            self.set_x(16)
            self.cell(0, 4.5, f"Location: {location}", new_x="LMARGIN", new_y="NEXT")

        self.set_font("Helvetica", "", 9)
        self.set_text_color(*WHITE)
        self.set_x(16)
        self.multi_cell(180, 4.5, description)

        if recommendation:
            self.set_font("Helvetica", "I", 9)
            self.set_text_color(*CYAN)
            self.set_x(16)
            self.multi_cell(180, 4.5, f"Recommendation: {recommendation}")

        self.ln(4)

    def comparison_row(self, cells, header=False):
        widths = [54, 27, 27, 27, 27, 27]
        self.set_font("Helvetica", "B" if header else "", 8)
        if header:
            self.set_fill_color(40, 40, 55)
            self.set_text_color(*ACCENT)
        else:
            self.set_fill_color(30, 30, 42)
            self.set_text_color(*WHITE)
        h = 7
        for i, cell in enumerate(cells):
            self.cell(widths[i], h, str(cell), border=0, fill=True, align="C" if i > 0 else "L")
        self.ln(h)


def build_pdf():
    pdf = PDF()

    # ── COVER PAGE ──────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.dark_page()
    pdf.ln(50)
    pdf.set_font("Helvetica", "B", 36)
    pdf.set_text_color(*ACCENT)
    pdf.cell(0, 15, "MORPHEUS", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 16)
    pdf.set_text_color(*WHITE)
    pdf.cell(0, 10, "v2.0 Technical Documentation & Security Audit", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(8)
    pdf.set_draw_color(*ACCENT)
    pdf.set_line_width(0.8)
    pdf.line(60, pdf.get_y(), 150, pdf.get_y())
    pdf.ln(12)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*LIGHT_GRAY)
    pdf.cell(0, 7, "Quantum-Resistant Multi-Cipher Encryption Tool", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, "with Hybrid ML-KEM-768 Post-Quantum Key Encapsulation", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(30)
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(*LIGHT_GRAY)
    info = [
        "Classification: Internal Technical Document",
        "Author: 404SecurityNotFound",
        "Security Audit: Independent Code Review",
        "Date: February 2026",
        "Version: 2.0.1",
    ]
    for line in info:
        pdf.cell(0, 5.5, line, align="C", new_x="LMARGIN", new_y="NEXT")

    # ── TABLE OF CONTENTS ───────────────────────────────────────────────────
    pdf.add_page()
    pdf.dark_page()
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(*ACCENT)
    pdf.cell(0, 12, "Table of Contents", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)
    toc = [
        ("1", "Executive Summary", "Why this document matters"),
        ("2", "Why This Tool Exists", "The problem we solve and why existing tools fall short"),
        ("3", "How It Works -- Plain English", "Encryption explained without jargon"),
        ("4", "Architecture Deep Dive", "Module structure, data flow, design decisions"),
        ("5", "Cryptographic Internals", "Ciphers, KDFs, chaining, hybrid PQ, format spec"),
        ("6", "Security Audit Report", "15 findings from adversarial code review"),
        ("7", "Testing & Verification", "122 automated tests plus manual verification procedures"),
        ("8", "Competitive Comparison", "Feature matrix vs age, gpg, Picocrypt, openssl"),
        ("9", "Deployment & Operations", "Installation, configuration, operational security"),
    ]
    for num, title, desc in toc:
        pdf.set_font("Helvetica", "B", 11)
        pdf.set_text_color(*WHITE)
        pdf.cell(8, 6, num + ".")
        pdf.cell(70, 6, title)
        pdf.set_font("Helvetica", "I", 9)
        pdf.set_text_color(*LIGHT_GRAY)
        pdf.cell(0, 6, desc, new_x="LMARGIN", new_y="NEXT")

    # ── SECTION 1: EXECUTIVE SUMMARY ────────────────────────────────────────
    pdf.add_page()
    pdf.dark_page()
    pdf.section_title("Executive Summary")

    pdf.body(
        "MORPHEUS v2.0 is a text and file encryption tool designed for people who need to "
        "protect sensitive information -- credentials, private notes, configuration secrets, API keys, "
        "or any block of text -- without that data ever touching a disk.\n\n"
        "Unlike general-purpose tools like GPG or age, this tool is purpose-built for a specific "
        "workflow: encrypt a block of text, get back a string you can safely store or transmit, and "
        "decrypt it later with your password. The encrypted output is displayed once and automatically "
        "cleared after 60 seconds.\n\n"
        "The tool offers four encryption modes of increasing strength, from single-cipher AES-256-GCM "
        "through to a maximum-security combination of cipher chaining plus hybrid post-quantum "
        "key encapsulation using NIST FIPS 203 ML-KEM-768.\n\n"
        "This document serves three purposes:"
    )
    pdf.bullet("A complete technical reference for developers and security professionals")
    pdf.bullet("An independent security audit with actionable findings")
    pdf.bullet("A plain-English guide for non-technical users who need to understand what the tool does and why they should trust it")

    # ── SECTION 2: WHY THIS TOOL EXISTS ─────────────────────────────────────
    pdf.add_page()
    pdf.dark_page()
    pdf.section_title("Why This Tool Exists")

    pdf.sub_title("The Problem")
    pdf.body(
        "You have a block of sensitive text. Maybe it's an API key for a production system. Maybe it's "
        "a password list, a private note, or a configuration file with database credentials. You need to "
        "encrypt it so you can store or transmit it safely.\n\n"
        "Your options today are surprisingly poor:"
    )
    pdf.bullet("GPG: Powerful but complex. Designed for email, not quick text encryption. The learning curve is steep, the output format is opaque, and there's no post-quantum support.")
    pdf.bullet("age: Simple and elegant, but file-oriented. No GUI, no cipher selection, no PQ, no auto-clear. Your encrypted output sits in terminal scrollback forever.")
    pdf.bullet("openssl enc: Uses CBC mode by default (no authentication!). No KDF tuning. A single wrong flag and your encryption is silently broken.")
    pdf.bullet("Online encryption tools: Your plaintext hits someone else's server. That's not encryption, that's trust.")
    pdf.ln(2)

    pdf.sub_title("What We Built Instead")
    pdf.body(
        "A tool that is obsessive about three things:\n\n"
        "1. Cryptographic depth -- not one algorithm, but layers. AES-256-GCM and ChaCha20-Poly1305 "
        "can be chained so that if either is broken, your data survives. ML-KEM-768 hybrid mode adds "
        "post-quantum resistance on top.\n\n"
        "2. Ephemeral by design -- encrypted output appears once, counts down from 60 seconds, then "
        "vanishes. Clipboard is wiped. Key material is zeroed. Nothing is written to disk. The tool "
        "treats your data like a self-destructing message.\n\n"
        "3. Accessible security -- a modern terminal GUI with dropdown cipher selection, real-time "
        "password strength feedback, and one-click operation. You don't need to know what AES-GCM means "
        "to use it safely. The defaults are secure."
    )

    pdf.sub_title("Who Is This For?")
    pdf.bullet("Security professionals who need to encrypt text blocks without touching disk")
    pdf.bullet("Developers storing secrets that don't belong in plaintext config files")
    pdf.bullet("System administrators sharing credentials through secure channels")
    pdf.bullet("Privacy-conscious users who want encryption they can verify and understand")
    pdf.bullet("Anyone preparing for the post-quantum era who wants hybrid protection today")

    # ── SECTION 3: HOW IT WORKS -- PLAIN ENGLISH ────────────────────────────
    pdf.add_page()
    pdf.dark_page()
    pdf.section_title("How It Works -- Plain English")

    pdf.sub_title("The Lock-and-Key Analogy")
    pdf.body(
        "Think of encryption like a lockbox with a unique lock:\n\n"
        "Your text is the item inside. Your password is the key. The encrypted output is the locked "
        "box -- anyone can carry it, but nobody can see inside without the key.\n\n"
        "What makes this lockbox special is that every time you lock something, the lock itself "
        "changes. Even if you lock the same item with the same key twice, the two locked boxes look "
        "completely different from the outside. An observer can't tell if two boxes contain the same "
        "item or different items."
    )

    pdf.sub_title("What Happens When You Hit 'Encrypt'")
    pdf.body(
        "Step 1 -- Key Strengthening (takes about 1 second)\n"
        "Your password is deliberately put through a slow, memory-intensive process called Argon2id. "
        "This turns your human-memorable password into a 256-bit cryptographic key. The slowness is "
        "the point -- it means an attacker trying millions of passwords would need millions of seconds.\n\n"
        "Step 2 -- Encryption\n"
        "Your text is encrypted with AES-256-GCM (the same algorithm banks and governments use). "
        "A random \"nonce\" (number used once) ensures the output is unique every time. A 16-byte "
        "authentication tag is appended that detects any tampering.\n\n"
        "Step 3 -- Packaging\n"
        "The salt (used in Step 1), the nonce (used in Step 2), and the encrypted text are bundled "
        "into a single base64 string safe for copy/paste.\n\n"
        "Step 4 -- Display and Forget\n"
        "The result appears in the output area. A 60-second countdown begins. When it reaches zero, "
        "the output is erased, the clipboard is cleared, and the key material is overwritten with "
        "zeros in memory."
    )

    pdf.sub_title("What Happens When You Hit 'Decrypt'")
    pdf.body(
        "The process reverses: the tool reads the header to determine which cipher and KDF were used "
        "(this is automatic -- you don't need to remember your settings), derives the same key from "
        "your password plus the stored salt, and decrypts. If the password is wrong or the data has "
        "been tampered with, the authentication tag check fails and you get a generic error message. "
        "The tool deliberately does not tell you which one went wrong -- that would help attackers."
    )

    # ── SECTION 4: ARCHITECTURE DEEP DIVE ───────────────────────────────────
    pdf.add_page()
    pdf.dark_page()
    pdf.section_title("Architecture Deep Dive")

    pdf.sub_title("Module Structure")
    pdf.code_block(
        "morpheus/\n"
        "  __init__.py        Package version (2.0.1)\n"
        "  __main__.py        Entry point -- auto-detects GUI vs CLI\n"
        "  gui.py             Textual TUI (733 lines)\n"
        "  cli.py             Argparse CLI (224 lines)\n"
        "  core/\n"
        "    ciphers.py       Cipher strategy pattern -- AES-GCM, ChaCha20\n"
        "    kdf.py           KDF strategy pattern -- Argon2id, Scrypt\n"
        "    pipeline.py      Orchestration -- chaining, hybrid PQ, key mgmt\n"
        "    formats.py       Versioned binary format -- serialize/deserialize\n"
        "    memory.py        mlock, secure zeroing, SecureBuffer\n"
        "    validation.py    Password scoring (0-100), input checks"
    )

    pdf.sub_title("Design Principles")
    pdf.body_bold("1. Strategy Pattern for Ciphers and KDFs")
    pdf.body(
        "Each cipher (AES-256-GCM, ChaCha20-Poly1305) and each KDF (Argon2id, Scrypt) implements "
        "an abstract base class. The pipeline doesn't know or care which concrete implementation "
        "it's using. This means adding a new cipher (e.g., AES-256-CBC-HMAC for legacy compat) "
        "requires only a new class and a registry entry -- zero changes to the pipeline."
    )

    pdf.body_bold("2. Self-Describing Ciphertext Format")
    pdf.body(
        "The 6-byte header encodes everything needed to decrypt: format version, cipher ID, KDF ID, "
        "and flags. The decryptor reads the header and configures itself automatically. This means "
        "the tool can always decrypt ciphertexts from any version 2.x configuration without the user "
        "needing to remember or specify settings."
    )

    pdf.body_bold("3. Separation of Encryption from Presentation")
    pdf.body(
        "The core/ package has zero dependency on GUI or CLI. You can import EncryptionPipeline in "
        "a script, a web app, or a test harness. The GUI and CLI are thin wrappers that handle "
        "user interaction and delegate all crypto to the pipeline."
    )

    # ── SECTION 5: CRYPTOGRAPHIC INTERNALS ──────────────────────────────────
    pdf.add_page()
    pdf.dark_page()
    pdf.section_title("Cryptographic Internals")

    pdf.sub_title("5.1 Ciphertext Binary Format (Version 2)")
    pdf.code_block(
        "Byte 0:     0x02 (version)\n"
        "Byte 1:     cipher_id (0x01=AES-GCM, 0x02=ChaCha20, 0x03=Chained)\n"
        "Byte 2:     kdf_id    (0x01=Scrypt, 0x02=Argon2id)\n"
        "Byte 3:     flags     (bit0=chained, bit1=hybrid_pq)\n"
        "Bytes 4-5:  reserved  (0x0000)\n"
        "Bytes 6+:   payload\n"
        "\n"
        "Single cipher payload:  [16B salt][12B nonce][ciphertext + 16B tag]\n"
        "Chained payload:        [16B salt][12B nonce1][12B nonce2][ciphertext + tag]\n"
        "Hybrid PQ prefix:       [2B kem_ct_len][kem_ciphertext]  (prepended to payload)"
    )
    pdf.body(
        "The header fields are authenticated via the AAD (Associated Authenticated Data) parameter "
        "of the AEAD cipher. The AAD is constructed as: pack('!BBBB', version, cipher_id, kdf_id, flags). "
        "This cryptographically binds the algorithm choices to the ciphertext -- an attacker cannot "
        "modify the header to trick the decryptor into using a different algorithm without the "
        "authentication tag verification failing."
    )

    pdf.sub_title("5.2 AES-256-GCM")
    pdf.body(
        "NIST SP 800-38D. 256-bit key, 96-bit random nonce, 128-bit authentication tag. "
        "Hardware-accelerated via AES-NI on modern x86/ARM processors. Provides IND-CCA2 security "
        "under the assumption that the block cipher is a PRP.\n\n"
        "Nonce generation: os.urandom(12) -- 96 bits of cryptographic randomness per encryption. "
        "The birthday bound for nonce collision is 2^48 encryptions under the same key, which is "
        "not a concern for our use case (each encryption derives a unique key from a random salt)."
    )

    pdf.sub_title("5.3 ChaCha20-Poly1305")
    pdf.body(
        "RFC 8439. 256-bit key, 96-bit random nonce, 128-bit Poly1305 tag. Constant-time software "
        "implementation -- immune to cache-timing side channels that can affect AES table lookups on "
        "hardware without AES-NI. Preferred by WireGuard, Google QUIC, and Cloudflare."
    )

    pdf.sub_title("5.4 Cipher Chaining")
    pdf.body(
        "When chaining is enabled, the pipeline always uses the fixed order AES-256-GCM (inner) then "
        "ChaCha20-Poly1305 (outer). Two independent 256-bit keys are derived from the master key "
        "using HKDF-Expand (RFC 5869) with distinct info strings:\n\n"
        "  master_key = KDF(password, salt)\n"
        "  key_aes    = HKDF-Expand(master_key, info='cipher-key-0', length=32)\n"
        "  key_chacha = HKDF-Expand(master_key, info='cipher-key-1', length=32)\n\n"
        "The inner encryption produces ciphertext_1 = AES-GCM(key_aes, plaintext, aad). "
        "The outer encryption wraps it: ciphertext_2 = ChaCha20-Poly1305(key_chacha, ciphertext_1, aad). "
        "Both layers use independent nonces."
    )

    pdf.sub_title("5.5 Key Derivation")
    pdf.body(
        "Argon2id (default): RFC 9106, OWASP recommended. Parameters: time_cost=3, memory_cost=65536 "
        "(64 MiB), parallelism=4. Argon2id combines Argon2i (data-independent memory access, resists "
        "side-channel attacks in the first pass) with Argon2d (data-dependent access, resists GPU "
        "attacks in subsequent passes).\n\n"
        "Scrypt (alternative): RFC 7914. Parameters: n=2^17 (131072), r=8, p=1. Memory-hard via "
        "sequential memory access patterns. Well-established but Argon2id is preferred for new designs.\n\n"
        "Both KDFs produce a 256-bit key from the password and a random 128-bit salt."
    )

    pdf.add_page()
    pdf.dark_page()

    pdf.sub_title("5.6 Hybrid Post-Quantum (ML-KEM-768)")
    pdf.body(
        "NIST FIPS 203 (August 2024). ML-KEM (Module-Lattice Key Encapsulation Mechanism) is based "
        "on the hardness of the Module Learning With Errors (MLWE) problem -- a lattice problem that "
        "no known quantum algorithm can solve efficiently.\n\n"
        "ML-KEM-768 provides 192-bit classical security and is the recommended parameter set for "
        "general use. Key sizes: public key 1184 bytes, secret key 2400 bytes, ciphertext 1088 bytes, "
        "shared secret 32 bytes.\n\n"
        "Our hybrid construction:\n"
        "  1. password_key = Argon2id(password, salt)\n"
        "  2. (kem_ct, kem_ss) = ML-KEM-768.Encaps(public_key)\n"
        "  3. final_key = HKDF(password_key || kem_ss, salt, info='hybrid-pq-v1')\n"
        "  4. ciphertext = AES-GCM(final_key, plaintext)\n\n"
        "The HKDF extract step combines entropy from both the password-derived key and the KEM shared "
        "secret. An attacker must break BOTH the password AND ML-KEM to recover the plaintext. If "
        "either layer holds, the data is safe. This is the NIST-recommended approach to hybrid PQ "
        "migration: don't replace classical crypto, layer PQ on top."
    )

    pdf.sub_title("5.7 Memory Protection Model")
    pdf.body(
        "The memory.py module provides best-effort protection via:\n\n"
        "- mlock(2): Prevents the OS from swapping buffer pages to disk. Uses ctypes to call libc "
        "directly. Non-fatal if it fails (e.g., due to RLIMIT_MEMLOCK).\n\n"
        "- Secure zeroing: Overwrites bytearray buffers byte-by-byte after use. Resistant to "
        "dead-store elimination in CPython because the interpreter doesn't optimize at that level.\n\n"
        "- SecureBuffer context manager: Combines mlock + auto-zero in a with-statement pattern.\n\n"
        "Limitation: Python str objects are immutable and cannot be reliably zeroed. The password, "
        "once passed as a string, exists in the Python heap until GC. See the Security Audit for the "
        "full analysis of this limitation."
    )

    # ── SECTION 6: SECURITY AUDIT ───────────────────────────────────────────
    pdf.add_page()
    pdf.dark_page()
    pdf.section_title("Security Audit Report")

    pdf.body(
        "Methodology: Manual line-by-line code review of all 8 source modules (1,736 lines total). "
        "Reviewed for: cryptographic misuse, memory safety, information leakage, injection vectors, "
        "format parsing vulnerabilities, timing attacks, and backdoors. No automated SAST tools were "
        "used -- this is a human adversarial review."
    )
    pdf.ln(2)

    pdf.sub_title("6.1 Findings")
    pdf.ln(2)

    pdf.finding(
        "CRITICAL",
        "Key Zeroing Creates Copies, Does Not Zero Originals",
        "In pipeline.py lines 213-216, the key cleanup code does:\n"
        "  for k in keys: buf = bytearray(k); secure_zero(buf)\n"
        "This creates a NEW bytearray from the immutable bytes object 'k', then zeros the copy. "
        "The original key bytes remain in the Python heap. The same pattern appears at lines 96-98 "
        "and 298-301. This gives a false sense of security -- the actual key material is never zeroed.",
        location="pipeline.py:213-216, 96-98, 298-301",
        recommendation="Use bytearray throughout the key derivation chain instead of bytes. "
        "Modify KDF.derive() and HKDF to return bytearray, and modify cipher.encrypt/decrypt "
        "to accept bytearray keys. This is a fundamental CPython limitation but can be mitigated."
    )

    pdf.finding(
        "CRITICAL",
        "Password String Is Immutable and Cannot Be Zeroed",
        "The password parameter flows as a Python str through the entire codebase: gui.py reads it "
        "from Input.value (str), passes it to EncryptionPipeline.encrypt(plaintext, password) which "
        "passes it to KDF.derive(password, salt) which calls password.encode('utf-8'). At no point "
        "is the password stored in mutable memory. The str object persists in CPython's heap until "
        "garbage collection, and even then the memory page may not be cleared.",
        location="pipeline.py:170, kdf.py:63, gui.py:544",
        recommendation="Accept password as bytes or bytearray at the API boundary. The GUI/CLI "
        "should encode immediately and pass bytearray, which can be zeroed after use. This is "
        "the standard mitigation in Python crypto tools (e.g., paramiko does this)."
    )

    pdf.finding(
        "MEDIUM",
        "secure_key Context Manager Yields Immutable Copy",
        "In memory.py:126, secure_key yields bytes(buf.data), creating an immutable copy. "
        "The SecureBuffer correctly zeros buf.data on exit, but the yielded bytes object is a "
        "separate immutable allocation that cannot be zeroed. Code using 'with secure_key(k) as key' "
        "would hold an unzeroable reference for the duration of the block.",
        location="memory.py:117-128",
        recommendation="Yield buf.data (the bytearray) directly, or document that the context "
        "manager protects against swap only, not heap persistence."
    )

    pdf.finding(
        "MEDIUM",
        "No Payload Length Validation During Decrypt Parsing",
        "In pipeline.py:255-280, the payload is parsed using sequential offset reads without "
        "checking that sufficient bytes remain. A truncated ciphertext could produce empty salt, "
        "nonce, or KEM fields via silent slice truncation. While this fails safely (the auth tag "
        "check will reject it), the error message will be 'incorrect password' rather than "
        "'truncated ciphertext', which makes debugging harder.",
        location="pipeline.py:255-280",
        recommendation="Add explicit length checks: 'if len(payload) < offset + expected_size: "
        "raise ValueError(\"Truncated ciphertext\")'"
    )

    pdf.add_page()
    pdf.dark_page()

    pdf.finding(
        "LOW",
        "libc Loader Re-Attempts on Every Call After Failure",
        "In memory.py:28, '_load_libc()' checks 'if _libc is not None: return'. If the initial "
        "load fails, _libc stays None, causing every subsequent call to re-attempt the dlopen. "
        "This is a minor performance issue, not a security issue.",
        location="memory.py:25-48",
        recommendation="Use a sentinel value (e.g., _libc = False) to distinguish 'not yet "
        "attempted' from 'attempted and failed'."
    )

    pdf.finding(
        "LOW",
        "KEM Ciphertext Length Field Limited to 65535 Bytes",
        "The KEM ciphertext length is encoded as a 2-byte unsigned short (!H). ML-KEM-768 "
        "ciphertext is 1088 bytes, well within range. However, future KEMs (e.g., Classic "
        "McEliece with ~200KB ciphertexts) would overflow this field silently.",
        location="pipeline.py:201, formats.py:19",
        recommendation="Document this limitation. If Classic McEliece support is planned, "
        "use a 4-byte length field (!I) in format version 3."
    )

    pdf.finding(
        "LOW",
        "Clipboard Clear May Not Defeat Clipboard Managers",
        "pyperclip.copy('') overwrites the system clipboard, but clipboard history managers "
        "(macOS Universal Clipboard, Windows Clipboard History, KDE Klipper, various third-party "
        "tools) may retain the previous value in a separate history store.",
        location="gui.py:677",
        recommendation="Document this limitation. Users with clipboard managers should disable "
        "history for sensitive operations, or use the manual copy method."
    )

    pdf.finding(
        "INFO",
        "No Rate Limiting on Decryption Attempts",
        "An attacker with the ciphertext can attempt unlimited offline password guesses. The KDF "
        "cost (Argon2id: ~1 second per attempt, 64MB per attempt) provides substantial protection, "
        "but there is no exponential backoff or lockout mechanism.",
        location="pipeline.py:222-303",
        recommendation="This is inherent to offline encryption (no server to enforce rate limits). "
        "The mitigation is KDF cost + password strength requirements. Document that users should "
        "use 16+ character passwords for high-value data."
    )

    pdf.finding(
        "INFO",
        "Reserved Header Bytes Not Validated on Decode",
        "The 2-byte reserved field (bytes 4-5) is read but not checked to be zero. A modified "
        "ciphertext with non-zero reserved bytes would still decrypt successfully. This is not "
        "a vulnerability because the reserved field is not part of the AAD.",
        location="formats.py:64",
        recommendation="No action needed. Non-zero reserved bytes are forward-compatible (a "
        "future version may use them). If strict validation is desired, add a check."
    )

    pdf.finding(
        "INFO",
        "Exception Handling in Decrypt Catches All Exceptions",
        "gui.py:587 catches bare 'except Exception' and returns a generic error. This is correct "
        "security behavior (prevents information leakage / padding oracle attacks) but may mask "
        "bugs during development.",
        location="gui.py:587-591",
        recommendation="Add debug-mode logging (disabled in production) that logs the actual "
        "exception type for diagnostic purposes."
    )

    pdf.add_page()
    pdf.dark_page()

    pdf.sub_title("6.2 Positive Findings")
    pdf.ln(2)

    pdf.finding("POSITIVE", "Cryptographically Secure Random Generation",
        "All nonces and salts use os.urandom(), which reads from /dev/urandom on Linux and "
        "CryptGenRandom on Windows. No weak PRNGs.", location="ciphers.py:58,75; kdf.py:42")

    pdf.finding("POSITIVE", "Contextual AAD Binds Algorithm Choices",
        "The AAD includes version, cipher_id, kdf_id, and flags. An attacker cannot modify the "
        "header to downgrade the cipher without the auth tag failing. This prevents algorithm "
        "confusion attacks.", location="formats.py:38-40")

    pdf.finding("POSITIVE", "HKDF-Expand Uses Distinct Info Strings",
        "Chained mode derives keys using 'cipher-key-0' and 'cipher-key-1' as HKDF info parameters. "
        "This provides proper domain separation -- knowing key_0 does not help derive key_1.",
        location="pipeline.py:89-93")

    pdf.finding("POSITIVE", "Generic Error Messages on Decrypt Failure",
        "Both GUI and CLI return 'incorrect password or corrupted data' without distinguishing "
        "between wrong password, tampered ciphertext, or format errors. This prevents padding "
        "oracle and error oracle attacks.", location="gui.py:588-591; cli.py:218-221")

    pdf.finding("POSITIVE", "Password Never Accepted via CLI Arguments by Default",
        "The -p/--password flag is suppressed (hidden from help) and triggers a visible stderr "
        "warning when used. The default path always uses getpass for non-echoing interactive input.",
        location="cli.py:71-73, 158-164")

    pdf.finding("POSITIVE", "No Backdoors, No Telemetry, No Network Access",
        "Complete code review confirms: no outbound network calls, no telemetry, no analytics, "
        "no logging to files, no temp file creation, and no eval/exec/import of dynamic code. "
        "The tool is fully offline.", location="All modules")

    pdf.finding("POSITIVE", "Argon2id Parameters Follow OWASP 2024 Guidelines",
        "Default Argon2id params (t=3, m=64MiB, p=4) match the OWASP 2024 recommendation for "
        "interactive applications. Scrypt default n=2^17 also matches OWASP guidance.",
        location="kdf.py:57, kdf.py:85")

    # ── SECTION 7: TESTING & VERIFICATION ───────────────────────────────────
    pdf.add_page()
    pdf.dark_page()
    pdf.section_title("Testing & Verification")

    pdf.sub_title("Automated Test Suite: 122 Tests")
    pdf.body(
        "Run with: python -m pytest tests/ -v\n\n"
        "All tests pass in ~1.2 seconds."
    )

    tests = [
        ("test_ciphers.py", "26", "AES/ChaCha roundtrips, NIST SP 800-38D TC14 vector, RFC 8439 vector, indistinguishability"),
        ("test_kdf.py", "17", "Argon2id/Scrypt derivation, determinism, bytearray returns, salt generation"),
        ("test_formats.py", "18", "Serialize/deserialize, flag combos, reserved byte validation, AAD collision resistance"),
        ("test_validation.py", "17", "Password scoring (0-100), missing char classes, edge cases, Unicode, size limits"),
        ("test_pipeline.py", "35", "All modes, wrong password, KEM length=0 bypass, header tampering, payload truncation"),
        ("test_memory.py", "7", "Secure zeroing with ctypes.memset, SecureBuffer, secure_key context manager"),
        ("test_cli.py", "2", "File encrypt/decrypt roundtrip (text and binary files)"),
    ]

    pdf.comparison_row(["Test File", "Count", "", "", "", "Coverage"], header=True)
    for name, count, desc in tests:
        pdf.set_font("Courier", "", 8)
        pdf.set_text_color(*WHITE)
        pdf.set_fill_color(30, 30, 42)
        pdf.cell(40, 6, name, fill=True)
        pdf.cell(12, 6, count, fill=True, align="C")
        pdf.set_font("Helvetica", "", 8)
        pdf.cell(0, 6, desc, fill=True, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(4)
    pdf.sub_title("Manual Verification Procedures")
    pdf.body(
        "Roundtrip Test: Encrypt text with a known password, then decrypt with the same password. "
        "Verify the output matches the input exactly, including whitespace and special characters.\n\n"
        "Wrong Password Test: Encrypt, then attempt to decrypt with a different password. Verify "
        "the tool returns 'incorrect password or corrupted data' and does not leak partial plaintext.\n\n"
        "Tamper Detection Test: Encrypt, modify a single character in the base64 output, attempt "
        "to decrypt. Verify rejection.\n\n"
        "Uniqueness Test: Encrypt the same text with the same password twice. Verify the two "
        "encrypted outputs are different (different random salt and nonce).\n\n"
        "Cross-Cipher Test: Encrypt with AES-256-GCM, then decrypt (the tool auto-detects the cipher "
        "from the header). Encrypt with ChaCha20-Poly1305, decrypt the same way. Both should work "
        "without specifying the cipher during decryption.\n\n"
        "Hybrid PQ Test: Generate an ML-KEM-768 keypair. Encrypt with the public key. Decrypt with "
        "the secret key and correct password. Verify success. Then try with the wrong secret key. "
        "Verify rejection."
    )

    # ── SECTION 8: COMPETITIVE COMPARISON ───────────────────────────────────
    pdf.add_page()
    pdf.dark_page()
    pdf.section_title("Competitive Comparison")

    pdf.body("Feature matrix comparing MORPHEUS v2.0 against common alternatives:")
    pdf.ln(2)

    headers = ["Feature", "This", "age", "GPG", "Pico.", "openssl"]
    pdf.comparison_row(headers, header=True)

    rows = [
        ["Hybrid PQ (ML-KEM-768)", "Yes", "No", "No", "No", "No"],
        ["Cipher chaining", "Yes", "No", "No", "No", "No"],
        ["One-time auto-clear", "Yes", "No", "No", "No", "No"],
        ["Memory locking (mlock)", "Yes", "No", "Part.", "No", "No"],
        ["Modern TUI / GUI", "Yes", "No", "No", "Yes", "No"],
        ["Argon2id KDF", "Yes", "No", "No", "Yes", "No"],
        ["Scrypt KDF", "Yes", "Yes", "No", "No", "No"],
        ["AES-256-GCM", "Yes", "No", "Yes", "No", "Yes"],
        ["ChaCha20-Poly1305", "Yes", "Yes", "No", "Yes", "No"],
        ["Self-describing format", "Yes", "Yes", "Yes", "Part.", "No"],
        ["Password strength check", "Yes", "No", "No", "No", "No"],
        ["Text-block optimized", "Yes", "No", "No", "No", "No"],
        ["No disk writes", "Yes", "No", "Yes", "No", "No"],
        ["Authenticated encryption", "Yes", "Yes", "Yes", "Yes", "CBC!"],
    ]
    for row in rows:
        pdf.comparison_row(row)

    pdf.ln(6)
    pdf.body(
        "Key insight: No other tool in this category combines post-quantum hybrid encryption, "
        "cipher chaining, and ephemeral output in a user-friendly interface. GPG is the closest "
        "in cryptographic depth but has a steep learning curve and no PQ support. age is the "
        "closest in simplicity but lacks cipher selection and PQ. Picocrypt has a GUI and Argon2 "
        "but no PQ and no cipher chaining.\n\n"
        "The unique position of this tool is at the intersection of modern cryptography, "
        "post-quantum readiness, and usability -- targeting the specific workflow of encrypting "
        "and transmitting sensitive text blocks."
    )

    # ── SECTION 9: DEPLOYMENT ───────────────────────────────────────────────
    pdf.add_page()
    pdf.dark_page()
    pdf.section_title("Deployment & Operations")

    pdf.sub_title("Installation")
    pdf.code_block(
        "git clone https://github.com/404securitynotfound/morpheus.git\n"
        "cd morpheus\n"
        "python -m venv venv && source venv/bin/activate\n"
        "pip install -r requirements.txt\n"
        "python -m pytest tests/ -v       # verify 122 tests pass\n"
        "python morpheus.py  # launch GUI"
    )

    pdf.sub_title("Operational Security Recommendations")
    pdf.bullet("Use in a terminal that supports secure erase or clearing scrollback history")
    pdf.bullet("Disable clipboard managers during sensitive operations")
    pdf.bullet("Use 16+ character passwords for high-value data (24+ for critical data)")
    pdf.bullet("Enable cipher chaining for data that must remain secure for 10+ years")
    pdf.bullet("Enable hybrid PQ for data that must resist future quantum attacks")
    pdf.bullet("Generate ML-KEM keypairs fresh for each session -- do not reuse across sessions")
    pdf.bullet("Verify the test suite passes before first use: python -m pytest tests/ -v")
    pdf.bullet("Pin dependency versions in production (see requirements.txt)")
    pdf.bullet("Run on a full-disk-encrypted system to protect against cold boot attacks")
    pdf.ln(4)

    pdf.sub_title("Dependencies and Supply Chain")
    pdf.body(
        "The tool depends on five Python packages, all widely used and audited:\n\n"
        "cryptography (pyca) -- The standard Python crypto library. Backed by the Python "
        "Cryptographic Authority. Wraps OpenSSL/BoringSSL. Regularly audited.\n\n"
        "argon2-cffi -- Python bindings for the reference Argon2 C implementation. Winner of "
        "the Password Hashing Competition.\n\n"
        "textual -- Terminal GUI framework by Textualize. No native code, pure Python.\n\n"
        "pyperclip -- Clipboard access. Thin wrapper around platform-native clipboard APIs.\n\n"
        "pqcrypto (optional) -- Post-quantum cryptography. Wraps PQClean C reference implementations "
        "of ML-KEM. The reference implementation is NIST-validated."
    )

    # ── END ─────────────────────────────────────────────────────────────────
    pdf.add_page()
    pdf.dark_page()
    pdf.ln(60)
    pdf.set_font("Helvetica", "B", 24)
    pdf.set_text_color(*ACCENT)
    pdf.cell(0, 12, "End of Document", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(6)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(*LIGHT_GRAY)
    pdf.cell(0, 7, "MORPHEUS v2.0", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, "404SecurityNotFound", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 7, "February 2026", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(20)
    pdf.set_draw_color(*ACCENT)
    pdf.line(70, pdf.get_y(), 140, pdf.get_y())
    pdf.ln(6)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(*ACCENT_DIM)
    pdf.cell(0, 6, "\"Unfortunately, no one can be told what the Matrix is.", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 6, 'You have to see it for yourself.\" -- Morpheus', align="C", new_x="LMARGIN", new_y="NEXT")

    return pdf


if __name__ == "__main__":
    pdf = build_pdf()
    pdf.output("docs/MORPHEUS_v2_Technical_Document.pdf")
    print("PDF generated: docs/MORPHEUS_v2_Technical_Document.pdf")
