"""Wizard state model — holds all user choices and validation results."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum


class Mode(IntEnum):
    ENCRYPT = 0
    DECRYPT = 1


class InputMethod(IntEnum):
    TEXT = 0
    FILE = 1


STEP_MODE = 0
STEP_SETTINGS = 1
STEP_INPUT = 2
STEP_PASSWORD = 3
STEP_REVIEW = 4
STEP_OUTPUT = 5

STEP_LABELS = ["Mode", "Settings", "Input", "Password", "Review", "Output"]
TOTAL_STEPS = len(STEP_LABELS)


@dataclass
class WizardState:
    """Mutable bag of all wizard data.  Validation methods return (ok, reason)."""

    # Step 1 — Mode
    mode: Mode | None = None

    # Step 2 — Settings
    cipher: str = "AES-256-GCM"
    kdf: str = "Argon2id"
    chain: bool = False
    hybrid_pq: bool = False
    pad: bool = False
    fixed_size: bool = False
    no_filename: bool = False

    # Step 3 — Input
    input_method: InputMethod = InputMethod.TEXT
    input_text: str = ""
    input_file: str = ""

    # Step 4 — Password
    password: str = ""
    password_confirm: str = ""

    # Step 5 — Review (computed, no fields)

    # Step 6 — Output
    output: str = ""

    # Internal
    completed_steps: set[int] = field(default_factory=set)

    # -------------------------------------------------------------------
    # Validation per step
    # -------------------------------------------------------------------

    def validate_mode(self) -> tuple[bool, str]:
        if self.mode is None:
            return False, "Choose Encrypt or Decrypt"
        return True, ""

    def validate_settings(self) -> tuple[bool, str]:
        if not self.cipher:
            return False, "Select a cipher"
        if not self.kdf:
            return False, "Select a KDF"
        return True, ""

    def validate_input(self) -> tuple[bool, str]:
        if self.input_method == InputMethod.TEXT:
            if self.mode == Mode.ENCRYPT and not self.input_text.strip():
                return False, "Enter text to encrypt"
            if self.mode == Mode.DECRYPT and not self.input_text.strip():
                return False, "Paste ciphertext to decrypt"
            return True, ""
        else:
            if not self.input_file.strip():
                return False, "Provide a file path"
            return True, ""

    def validate_password(self) -> tuple[bool, str]:
        if not self.password:
            return False, "Enter a password"
        if self.mode == Mode.ENCRYPT and self.password != self.password_confirm:
            return False, "Passwords do not match"
        return True, ""

    def validate_review(self) -> tuple[bool, str]:
        # Review is valid when all prior steps pass
        for validator in (
            self.validate_mode,
            self.validate_settings,
            self.validate_input,
            self.validate_password,
        ):
            ok, reason = validator()
            if not ok:
                return False, reason
        return True, ""

    VALIDATORS = {
        STEP_MODE: "validate_mode",
        STEP_SETTINGS: "validate_settings",
        STEP_INPUT: "validate_input",
        STEP_PASSWORD: "validate_password",
        STEP_REVIEW: "validate_review",
    }

    def is_step_valid(self, step: int) -> tuple[bool, str]:
        name = self.VALIDATORS.get(step)
        if name is None:
            return True, ""
        return getattr(self, name)()

    def is_step_unlocked(self, step: int) -> bool:
        """A step is unlocked if all prior steps are valid."""
        for i in range(step):
            ok, _ = self.is_step_valid(i)
            if not ok:
                return False
        return True
