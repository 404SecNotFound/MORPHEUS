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
