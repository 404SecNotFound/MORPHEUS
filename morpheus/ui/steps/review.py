"""Step 5 — Review summary before running."""

from __future__ import annotations

from textual.containers import Horizontal, Vertical
from textual.widgets import Static

from ...core.validation import check_password_strength
from ..state import InputMethod, Mode, WizardState


class ReviewRow(Horizontal):
    """Key: value row in the review table."""

    def __init__(self, key: str, val: str, **kw) -> None:
        super().__init__(classes="review-row", **kw)
        self._key = key
        self._val = val

    def compose(self):
        yield Static(self._key, classes="review-key")
        yield Static(self._val, classes="review-val")


class ReviewStep(Vertical):
    """Read-only summary of all wizard choices."""

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(**kw)
        self._state = state

    def compose(self):
        s = self._state
        yield Static("Review", classes="step-title")
        yield Static(
            "Confirm your settings, then press Run.",
            classes="step-subtitle",
        )

        mode_str = "Encrypt" if s.mode == Mode.ENCRYPT else "Decrypt"
        yield ReviewRow("Mode:", mode_str)

        cipher_str = s.cipher
        if s.chain:
            cipher_str = "AES-256-GCM + ChaCha20 (chained)"
        yield ReviewRow("Cipher:", cipher_str)
        yield ReviewRow("KDF:", s.kdf)

        if s.hybrid_pq:
            yield ReviewRow("Post-Quantum:", "ML-KEM-768 hybrid")

        flags = []
        if s.pad:
            flags.append("padded")
        if s.fixed_size:
            flags.append("fixed 64K")
        if s.no_filename:
            flags.append("no filename")
        if flags:
            yield ReviewRow("Flags:", ", ".join(flags))

        if s.input_method == InputMethod.TEXT:
            size = len(s.input_text.encode("utf-8"))
            yield ReviewRow("Input:", f"Text ({size} bytes)")
        else:
            yield ReviewRow("Input:", f"File: {s.input_file}")

        # Warnings
        if s.mode == Mode.ENCRYPT:
            strength = check_password_strength(s.password)
            if not strength.is_acceptable:
                yield Static(
                    f"⚠ Password is {strength.label}: "
                    + "; ".join(strength.feedback[:2]),
                    classes="warning-text",
                )
            elif strength.score < 60:
                yield Static(
                    f"⚠ Password strength is only '{strength.label}'. "
                    "Consider a longer password.",
                    classes="warning-text",
                )
