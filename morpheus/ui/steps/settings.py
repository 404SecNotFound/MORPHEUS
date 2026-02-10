"""Step 2 — Cipher, KDF, and option settings."""

from __future__ import annotations

from textual.containers import Horizontal, Vertical
from textual.widgets import Checkbox, Collapsible, Label, Select, Static

from ...core.ciphers import CIPHER_CHOICES
from ...core.kdf import KDF_CHOICES
from ...core.pipeline import PQ_AVAILABLE
from ..state import WizardState


class SettingsStep(Vertical):
    """Cipher, KDF, chaining, hybrid PQ, and advanced options."""

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(**kw)
        self._state = state

    def compose(self):
        yield Static("Settings", classes="step-title")
        yield Static(
            "Configure the encryption algorithm and key derivation function. "
            "Defaults are secure for most use cases — only change these if you "
            "have specific requirements.",
            classes="step-subtitle",
        )
        yield Static(
            "[dim]Tab between fields. Enter opens dropdowns. "
            "Space toggles checkboxes.[/dim]",
            classes="step-hint",
        )

        with Horizontal(classes="field-row"):
            yield Label("Cipher:", classes="field-label")
            yield Select(
                [(n, n) for n in CIPHER_CHOICES],
                value=self._state.cipher,
                id="cipher-select",
            )
        yield Static(
            "[dim]AES-256-GCM: NIST standard, hardware-accelerated on most CPUs.\n"
            "ChaCha20-Poly1305: Constant-time, excellent for software-only environments.[/dim]",
            classes="field-help",
        )

        with Horizontal(classes="field-row"):
            yield Label("KDF:", classes="field-label")
            yield Select(
                [(n, n) for n in KDF_CHOICES],
                value=self._state.kdf,
                id="kdf-select",
            )
        yield Static(
            "[dim]Argon2id: Memory-hard, resists GPU/ASIC attacks (recommended).\n"
            "Scrypt: Also memory-hard, widely deployed alternative.[/dim]",
            classes="field-help",
        )

        yield Checkbox(
            "Chain ciphers (AES-256-GCM + ChaCha20-Poly1305)",
            id="chain-check",
            value=self._state.chain,
        )
        yield Static(
            "[dim]Double encryption with independent keys — hedges against "
            "a single-cipher break.[/dim]",
            classes="field-help",
        )

        pq_label = "Hybrid Post-Quantum (ML-KEM-768)"
        if not PQ_AVAILABLE:
            pq_label += " [dim](install pqcrypto)[/dim]"
        yield Checkbox(
            pq_label,
            id="pq-check",
            value=self._state.hybrid_pq,
            disabled=not PQ_AVAILABLE,
        )
        if PQ_AVAILABLE:
            yield Static(
                "[dim]Adds ML-KEM-768 key encapsulation on top of password-derived "
                "keys — protects against future quantum computers.[/dim]",
                classes="field-help",
            )

        with Collapsible(title="Advanced options", collapsed=True):
            yield Checkbox("Pad plaintext to hide length", id="pad-check",
                           value=self._state.pad)
            yield Static(
                "[dim]Adds random padding so ciphertext length does not reveal "
                "plaintext size.[/dim]",
                classes="field-help",
            )
            yield Checkbox("Fixed 64 KiB output", id="fixed-check",
                           value=self._state.fixed_size)
            yield Static(
                "[dim]All outputs are exactly 64 KiB — useful when uniform "
                "ciphertext sizes are required.[/dim]",
                classes="field-help",
            )
            yield Checkbox("Omit filename from envelope", id="nofn-check",
                           value=self._state.no_filename)
            yield Static(
                "[dim]Strips the original filename from the encrypted envelope "
                "(file mode only).[/dim]",
                classes="field-help",
            )

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "cipher-select":
            self._state.cipher = event.value
        elif event.select.id == "kdf-select":
            self._state.kdf = event.value

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        mapping = {
            "chain-check": "chain",
            "pq-check": "hybrid_pq",
            "pad-check": "pad",
            "fixed-check": "fixed_size",
            "nofn-check": "no_filename",
        }
        attr = mapping.get(event.checkbox.id)
        if attr:
            setattr(self._state, attr, event.value)
