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
            "Choose whether to encrypt new data or decrypt existing ciphertext.",
            classes="step-subtitle",
        )
        with RadioSet(id="mode-radio"):
            yield RadioButton(
                "Encrypt — protect data with a password",
                id="radio-encrypt",
                value=self._state.mode == Mode.ENCRYPT,
            )
            yield RadioButton(
                "Decrypt — recover data from ciphertext",
                id="radio-decrypt",
                value=self._state.mode == Mode.DECRYPT,
            )

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        self._state.mode = Mode(event.index)
