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


@dataclass(frozen=True)
class OperationRequest:
    """Everything a run needs, copied once at Execute and then frozen.

    The worker used to read fields off the live `WizardState` while it ran, and
    then call `record_output(result)`, which stamps the fingerprint of the
    state as it is *at that moment*. Argon2id takes long enough to retype a
    password in. Change it mid-run and the ciphertext is produced under the old
    password, stamped as matching the new one, and presented as current: the
    password on screen does not open the result, and nothing says so.

    `invalidate_output` cannot catch that, because it compares the stamp
    against the inputs and the stamp itself is what is wrong.

    So the worker is given a copy instead, with the fingerprint of the inputs
    that produced it travelling alongside. The result is published only if the
    live state still matches that fingerprint.
    """

    mode: Mode
    cipher: str
    kdf: str
    chain: bool
    hybrid_pq: bool
    pad: bool
    fixed_size: bool
    no_filename: bool
    input_method: InputMethod
    input_text: str
    input_file: str
    password: str
    fingerprint: tuple


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

    # Snapshot of the inputs that produced `output`. None when no run has
    # completed. Compared rather than invalidated on events, because widget
    # mounts fire the same change events a user edit does, and reacting to
    # those would discard a valid result merely for navigating back to look.
    output_fingerprint: tuple | None = None

    def input_fingerprint(self) -> tuple:
        """Every field that changes what a run would produce."""
        return (
            self.mode,
            self.cipher,
            self.kdf,
            self.chain,
            self.hybrid_pq,
            self.pad,
            self.fixed_size,
            self.no_filename,
            self.input_method,
            self.input_text,
            self.input_file,
            self.password,
        )

    def snapshot(self) -> OperationRequest:
        """Freeze the inputs a run is about to use, with their fingerprint."""
        return OperationRequest(
            mode=self.mode,
            cipher=self.cipher,
            kdf=self.kdf,
            chain=self.chain,
            hybrid_pq=self.hybrid_pq,
            pad=self.pad,
            fixed_size=self.fixed_size,
            no_filename=self.no_filename,
            input_method=self.input_method,
            input_text=self.input_text,
            input_file=self.input_file,
            password=self.password,
            fingerprint=self.input_fingerprint(),
        )

    def record_output(self, result: str, fingerprint: tuple | None = None) -> None:
        """Store a run's result together with the inputs that produced it.

        `fingerprint` is the one captured when the run started. It must be
        passed by anything asynchronous: defaulting to the current inputs is
        exactly the bug this argument exists to prevent, and is safe only for
        callers that cannot have raced (tests and the screenshot script).
        """
        self.output = result
        self.output_fingerprint = (
            self.input_fingerprint() if fingerprint is None else fingerprint
        )

    def invalidate_output(self) -> None:
        """Discard a result that no longer matches the current inputs.

        `output` is only ever overwritten by a new run, so without this the
        Output step keeps presenting the previous run's result as current:
        encrypt A, change the input to B, and the pane still shows A's
        ciphertext with a live Copy button and a fresh countdown.

        A no-op when the inputs are unchanged, so moving back and forth
        without editing anything keeps the result. Review is un-completed
        alongside Output because the review summary describes the inputs that
        produced the discarded result.
        """
        if not self.output:
            return
        if self.output_fingerprint == self.input_fingerprint():
            return
        self.output = ""
        self.output_fingerprint = None
        self.completed_steps.discard(STEP_OUTPUT)
        self.completed_steps.discard(STEP_REVIEW)

    # -------------------------------------------------------------------
    # Validation per step
    # -------------------------------------------------------------------

    def validate_mode(self) -> tuple[bool, str]:
        if self.mode is None:
            return False, "Choose Encrypt or Decrypt"
        return True, ""

    def validate_settings(self) -> tuple[bool, str]:
        """Reject here anything the engine would reject at Execute.

        The Settings controls are independent widgets, so combinations are
        reachable that `EncryptionPipeline` refuses to build. Every check below
        was previously discovered only after the user had walked through Input,
        typed a password, confirmed it, and pressed Execute. The rule is that a
        choice is rejected where it is made.

        `tests/test_wizard_state.py::TestNoReachableSettingsCombinationIsInvalid`
        sweeps all 64 combinations and fails if any the wizard accepts cannot
        actually be built, so a new option cannot reopen this quietly.
        """
        if not self.cipher:
            return False, "Select a cipher"
        if not self.kdf:
            return False, "Select a KDF"
        if self.chain and self.cipher != "AES-256-GCM":
            return False, (
                "Chaining uses a fixed order, AES-256-GCM then "
                f"ChaCha20-Poly1305, so it cannot run with {self.cipher} as the "
                "primary cipher. Switch the cipher to AES-256-GCM, or turn "
                "chaining off."
            )
        if self.hybrid_pq:
            # Hybrid PQ is CLI-only (UAT DEF-006): the wizard has no key
            # management, and app.py would build the pipeline with hybrid_pq
            # and no public key. Settings no longer offers the control, so
            # this is unreachable through the UI. It stays because the state
            # model must not depend on the UI's current shape — re-adding a
            # checkbox should fail this check, not ship a broken feature.
            return False, (
                "Hybrid post-quantum needs an ML-KEM public key, and this "
                "wizard has no way to supply one. Use the command line: "
                "morpheus --generate-keypair, then "
                "morpheus -o encrypt --hybrid-pq --pq-public-key <key>."
            )
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
