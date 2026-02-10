"""Step 1 — Mode selection (Encrypt / Decrypt)."""

from __future__ import annotations

from textual.containers import Vertical
from textual.widgets import RadioButton, RadioSet, Static

from ..state import Mode, WizardState


class ModeStep(Vertical):
    """Choose between Encrypt and Decrypt."""

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(**kw)
        self._state = state

    def compose(self):
        yield Static("Mode", classes="step-title")
        yield Static(
            "Choose an operation. Encrypt converts plaintext into protected "
            "ciphertext. Decrypt reverses the process to recover the original data.",
            classes="step-subtitle",
        )
        yield Static(
            "[dim]Use Up/Down arrows to highlight, Enter to select, "
            "or press Ctrl+E / Ctrl+D to skip this step.[/dim]",
            classes="step-hint",
        )
        with RadioSet(id="mode-radio"):
            yield RadioButton(
                "Encrypt — protect data with a password\n"
                "  Derives a key from your password using a memory-hard KDF,\n"
                "  then encrypts with authenticated encryption (AEAD).",
                id="radio-encrypt",
                value=self._state.mode == Mode.ENCRYPT,
            )
            yield RadioButton(
                "Decrypt — recover data from ciphertext\n"
                "  Reads the algorithm from the ciphertext header and\n"
                "  reverses encryption using your password.",
                id="radio-decrypt",
                value=self._state.mode == Mode.DECRYPT,
            )

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        self._state.mode = Mode(event.index)
