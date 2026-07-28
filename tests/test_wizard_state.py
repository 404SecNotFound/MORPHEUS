"""Tests for the wizard state model and validation logic."""

from morpheus.ui.state import (
    STEP_MODE,
    STEP_OUTPUT,
    STEP_REVIEW,
    STEP_SETTINGS,
    InputMethod,
    Mode,
    WizardState,
)


class TestStaleOutputInvalidation:
    """Editing an earlier step must not leave the previous result on screen.

    Reproduced: encrypt A, go back and change the input to B, then jump to
    Output. The pane showed the ciphertext of *A* with a fresh countdown and a
    live Copy button, so the user could copy and send the wrong ciphertext
    believing it corresponded to B.
    """

    def test_changed_input_discards_the_result(self):
        s = WizardState(mode=Mode.ENCRYPT, input_text="A")
        s.record_output("CIPHERTEXT-FOR-A")
        s.completed_steps.update({STEP_REVIEW, STEP_OUTPUT})

        s.input_text = "B"
        s.invalidate_output()

        assert s.output == ""
        assert STEP_OUTPUT not in s.completed_steps
        assert STEP_REVIEW not in s.completed_steps

    def test_unchanged_input_keeps_the_result(self):
        """Navigating back to look at a step must not destroy the result.

        Widget mounts raise the same change events a user edit does, so
        reacting to events alone would clear a valid result when the user
        only moved between steps. Staleness is derived from the inputs
        themselves, not from events.
        """
        s = WizardState(mode=Mode.ENCRYPT, input_text="A")
        s.record_output("CIPHERTEXT-FOR-A")
        s.completed_steps.update({STEP_REVIEW, STEP_OUTPUT})

        s.invalidate_output()

        assert s.output == "CIPHERTEXT-FOR-A"
        assert STEP_OUTPUT in s.completed_steps

    def test_a_settings_change_also_counts(self):
        """Not just the plaintext: anything that changes the ciphertext."""
        s = WizardState(mode=Mode.ENCRYPT, input_text="A")
        s.record_output("CIPHERTEXT-FOR-A")
        s.completed_steps.add(STEP_OUTPUT)

        s.cipher = "ChaCha20-Poly1305"
        s.invalidate_output()

        assert s.output == ""

    def test_invalidate_keeps_earlier_progress(self):
        """Only the result is stale; the steps that produced it are not."""
        s = WizardState(mode=Mode.ENCRYPT, input_text="A")
        s.record_output("CIPHERTEXT-FOR-A")
        s.completed_steps.update({STEP_MODE, STEP_SETTINGS, STEP_OUTPUT})

        s.input_text = "B"
        s.invalidate_output()

        assert STEP_MODE in s.completed_steps
        assert STEP_SETTINGS in s.completed_steps
        assert STEP_OUTPUT not in s.completed_steps

    def test_invalidate_is_safe_when_nothing_has_run(self):
        s = WizardState(mode=Mode.ENCRYPT)
        s.invalidate_output()
        assert s.output == ""
        assert STEP_OUTPUT not in s.completed_steps


class TestModeValidation:
    def test_no_mode_selected(self):
        s = WizardState()
        ok, reason = s.validate_mode()
        assert not ok
        assert "Choose" in reason

    def test_encrypt_selected(self):
        s = WizardState(mode=Mode.ENCRYPT)
        ok, _ = s.validate_mode()
        assert ok

    def test_decrypt_selected(self):
        s = WizardState(mode=Mode.DECRYPT)
        ok, _ = s.validate_mode()
        assert ok


class TestSettingsValidation:
    def test_defaults_are_valid(self):
        s = WizardState()
        ok, _ = s.validate_settings()
        assert ok

    def test_empty_cipher_invalid(self):
        s = WizardState(cipher="")
        ok, reason = s.validate_settings()
        assert not ok
        assert "cipher" in reason.lower()

    def test_empty_kdf_invalid(self):
        s = WizardState(kdf="")
        ok, reason = s.validate_settings()
        assert not ok
        assert "kdf" in reason.lower()


class TestInputValidation:
    def test_encrypt_empty_text_invalid(self):
        s = WizardState(mode=Mode.ENCRYPT, input_method=InputMethod.TEXT, input_text="")
        ok, reason = s.validate_input()
        assert not ok
        assert "text" in reason.lower()

    def test_encrypt_with_text_valid(self):
        s = WizardState(mode=Mode.ENCRYPT, input_method=InputMethod.TEXT, input_text="hello")
        ok, _ = s.validate_input()
        assert ok

    def test_decrypt_empty_text_invalid(self):
        s = WizardState(mode=Mode.DECRYPT, input_method=InputMethod.TEXT, input_text="")
        ok, reason = s.validate_input()
        assert not ok
        assert "ciphertext" in reason.lower()

    def test_file_mode_empty_path_invalid(self):
        s = WizardState(mode=Mode.ENCRYPT, input_method=InputMethod.FILE, input_file="")
        ok, reason = s.validate_input()
        assert not ok
        assert "file" in reason.lower()

    def test_file_mode_with_path_valid(self):
        s = WizardState(mode=Mode.ENCRYPT, input_method=InputMethod.FILE, input_file="/tmp/test.txt")
        ok, _ = s.validate_input()
        assert ok


class TestPasswordValidation:
    def test_empty_password_invalid(self):
        s = WizardState(mode=Mode.ENCRYPT, password="")
        ok, reason = s.validate_password()
        assert not ok
        assert "password" in reason.lower()

    def test_encrypt_mismatch_invalid(self):
        s = WizardState(mode=Mode.ENCRYPT, password="abc", password_confirm="xyz")
        ok, reason = s.validate_password()
        assert not ok
        assert "match" in reason.lower()

    def test_encrypt_match_valid(self):
        s = WizardState(mode=Mode.ENCRYPT, password="test", password_confirm="test")
        ok, _ = s.validate_password()
        assert ok

    def test_decrypt_no_confirm_needed(self):
        s = WizardState(mode=Mode.DECRYPT, password="test", password_confirm="")
        ok, _ = s.validate_password()
        assert ok


class TestReviewValidation:
    def test_all_valid(self):
        s = WizardState(
            mode=Mode.ENCRYPT,
            cipher="AES-256-GCM",
            kdf="Argon2id",
            input_text="hello",
            password="test",
            password_confirm="test",
        )
        ok, _ = s.validate_review()
        assert ok

    def test_missing_mode_fails_review(self):
        s = WizardState(input_text="hello", password="test", password_confirm="test")
        ok, reason = s.validate_review()
        assert not ok
        assert "Choose" in reason


class TestStepUnlocked:
    def test_mode_always_unlocked(self):
        s = WizardState()
        assert s.is_step_unlocked(STEP_MODE)

    def test_settings_locked_without_mode(self):
        s = WizardState()
        assert not s.is_step_unlocked(STEP_SETTINGS)

    def test_settings_unlocked_with_mode(self):
        s = WizardState(mode=Mode.ENCRYPT)
        assert s.is_step_unlocked(STEP_SETTINGS)

    def test_review_locked_without_password(self):
        s = WizardState(mode=Mode.ENCRYPT, input_text="hi", password="")
        assert not s.is_step_unlocked(STEP_REVIEW)

    def test_review_unlocked_when_complete(self):
        s = WizardState(
            mode=Mode.ENCRYPT,
            input_text="hi",
            password="test",
            password_confirm="test",
        )
        assert s.is_step_unlocked(STEP_REVIEW)

    def test_output_unlocked_when_review_ok(self):
        s = WizardState(
            mode=Mode.ENCRYPT,
            input_text="hi",
            password="test",
            password_confirm="test",
        )
        assert s.is_step_unlocked(STEP_OUTPUT)
