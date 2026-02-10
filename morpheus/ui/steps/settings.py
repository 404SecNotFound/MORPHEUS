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
            "Configure encryption algorithm and key derivation.",
            classes="step-subtitle",
        )

        with Horizontal(classes="field-row"):
            yield Label("Cipher:", classes="field-label")
            yield Select(
                [(n, n) for n in CIPHER_CHOICES],
                value=self._state.cipher,
                id="cipher-select",
            )

        with Horizontal(classes="field-row"):
            yield Label("KDF:", classes="field-label")
            yield Select(
                [(n, n) for n in KDF_CHOICES],
                value=self._state.kdf,
                id="kdf-select",
            )

        yield Checkbox(
            "Chain ciphers (AES-256-GCM + ChaCha20-Poly1305)",
            id="chain-check",
            value=self._state.chain,
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

        with Collapsible(title="Advanced options", collapsed=True):
            yield Checkbox("Pad plaintext to hide length (--pad)", id="pad-check",
                           value=self._state.pad)
            yield Checkbox("Fixed 64 KiB output (--fixed-size)", id="fixed-check",
                           value=self._state.fixed_size)
            yield Checkbox("Omit filename from envelope (--no-filename)", id="nofn-check",
                           value=self._state.no_filename)

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
