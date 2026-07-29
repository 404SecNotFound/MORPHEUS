"""Step 2 — Cipher, KDF, and option settings."""

from __future__ import annotations

from textual.containers import Horizontal, Vertical
from textual.widgets import Checkbox, Collapsible, Label, Select, Static

from ...core.ciphers import CIPHER_CHOICES
from ...core.kdf import KDF_CHOICES
from .. import theme
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
            f"[{theme.TEXT_3}]Tab between fields. Enter opens dropdowns. "
            "Space toggles checkboxes.[/]",
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
            f"[{theme.TEXT_3}]AES-256-GCM: NIST standard, hardware-accelerated on most CPUs.\n"
            "ChaCha20-Poly1305: Constant-time, excellent for software-only environments.[/]",
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
            f"[{theme.TEXT_3}]Argon2id: Memory-hard, resists GPU/ASIC attacks (recommended).\n"
            "Scrypt: Also memory-hard, widely deployed alternative.[/]",
            classes="field-help",
        )

        yield Checkbox(
            "Chain ciphers (AES-256-GCM + ChaCha20-Poly1305)",
            id="chain-check",
            value=self._state.chain,
        )
        yield Static(
            f"[{theme.TEXT_3}]Double encryption with independent keys — hedges against "
            "a single-cipher break.[/]",
            classes="field-help",
        )

        # Hybrid post-quantum is CLI-only. The wizard cannot generate, display
        # or accept an ML-KEM keypair, so a checkbox here could only ever fail
        # after the user had already chosen a password (UAT DEF-006). It is
        # signposted rather than silently dropped, because the README presents
        # hybrid PQ as the headline feature and users will come looking for it.
        yield Static(
            f"[{theme.TEXT_3}]Hybrid Post-Quantum (ML-KEM-768) is command-line only — "
            f"the wizard cannot hold a keypair. Use [{theme.TEXT_2}]--generate-keypair[/]"
            f"[{theme.TEXT_3}] then [{theme.TEXT_2}]--hybrid-pq[/]"
            f"[{theme.TEXT_3}] on the CLI.[/]",
            classes="field-help",
        )

        with Collapsible(title="Advanced options", collapsed=True):
            yield Checkbox("Pad plaintext to hide length", id="pad-check",
                           value=self._state.pad)
            yield Static(
                f"[{theme.TEXT_3}]Adds random padding so ciphertext length does not reveal "
                "plaintext size.[/]",
                classes="field-help",
            )
            yield Checkbox("Fixed 64 KiB output", id="fixed-check",
                           value=self._state.fixed_size)
            yield Static(
                f"[{theme.TEXT_3}]All outputs are exactly 64 KiB — useful when uniform "
                "ciphertext sizes are required.[/]",
                classes="field-help",
            )
            yield Checkbox("Omit filename from envelope", id="nofn-check",
                           value=self._state.no_filename)
            yield Static(
                f"[{theme.TEXT_3}]Strips the original filename from the encrypted envelope "
                "(file mode only).[/]",
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
            "pad-check": "pad",
            "fixed-check": "fixed_size",
            "nofn-check": "no_filename",
        }
        attr = mapping.get(event.checkbox.id)
        if attr:
            setattr(self._state, attr, event.value)
