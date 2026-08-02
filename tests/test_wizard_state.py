"""Tests for the wizard state model and validation logic."""

from morpheus_crypt.ui.state import (
    STEP_MODE,
    STEP_OUTPUT,
    STEP_REVIEW,
    STEP_SETTINGS,
    InputMethod,
    Mode,
    WizardState,
)


class TestNoReachableSettingsCombinationIsInvalid:
    """Anything the wizard lets you build, the engine must accept.

    This is the guard, not the two cases below it. UAT DEF-005 found that
    `validate_settings` checked only that a cipher and a KDF were non-empty, so
    40 of the 64 reachable Settings combinations were accepted by the wizard
    and rejected by the engine at Execute, four steps and a password entry
    later. Fixing the two known pairs by hand would have been the fourth
    instance of the "enumerated sites hide the ones you did not enumerate"
    pattern in this repository, so the sweep itself is the test.
    """

    def test_every_reachable_combination_the_wizard_accepts_actually_builds(self):
        import itertools

        from morpheus_crypt.core.ciphers import CIPHER_CHOICES
        from morpheus_crypt.core.kdf import Argon2idKDF, ScryptKDF
        from morpheus_crypt.core.pipeline import EncryptionPipeline

        # Cheap KDF params: validity here is decided by the cipher/chain/PQ
        # combination, not by the cost parameters.
        fast = {
            "Argon2id": lambda: Argon2idKDF(time_cost=1, memory_cost=1024, parallelism=1),
            "Scrypt": lambda: ScryptKDF(n=2**10, r=8, p=1),
        }
        pw = "T3st!Passw0rd#Str0ng"
        offenders = []

        for cipher, kdf, chain, pq, pad, fixed in itertools.product(
            CIPHER_CHOICES, fast, (False, True), (False, True), (False, True), (False, True)
        ):
            s = WizardState(
                mode=Mode.ENCRYPT, cipher=cipher, kdf=kdf, chain=chain,
                hybrid_pq=pq, pad=pad, fixed_size=fixed,
                input_text="x", password=pw, password_confirm=pw,
            )
            if not (s.validate_settings()[0] and s.validate_review()[0]):
                continue  # wizard refuses it, which is the point
            try:
                p = EncryptionPipeline(
                    cipher=CIPHER_CHOICES[cipher](), kdf=fast[kdf](),
                    chain=chain, hybrid_pq=pq,
                )
                assert p.decrypt(p.encrypt("x", pw), pw) == "x"
            except Exception as exc:
                offenders.append(
                    f"cipher={cipher} kdf={kdf} chain={chain} hybrid_pq={pq} "
                    f"-> {type(exc).__name__}: {exc}"
                )

        assert not offenders, (
            "the wizard accepts these, so a user reaches Execute and loses a "
            "password entry to a failure that was decidable at the Settings "
            "step:\n  " + "\n  ".join(offenders)
        )

    def test_the_sweep_is_not_vacuous(self):
        """At least one combination must survive, or the test above proves nothing."""
        pw = "T3st!Passw0rd#Str0ng"
        s = WizardState(
            mode=Mode.ENCRYPT, cipher="AES-256-GCM", kdf="Argon2id",
            input_text="x", password=pw, password_confirm=pw,
        )
        assert s.validate_settings()[0] and s.validate_review()[0]

    def test_chain_requires_aes(self):
        s = WizardState(mode=Mode.ENCRYPT, cipher="ChaCha20-Poly1305", chain=True)
        ok, reason = s.validate_settings()
        assert not ok
        assert "chain" in reason.lower() and "AES" in reason

    def test_chain_with_aes_is_accepted(self):
        s = WizardState(mode=Mode.ENCRYPT, cipher="AES-256-GCM", chain=True)
        assert s.validate_settings()[0]

    def test_hybrid_pq_is_refused_because_the_wizard_cannot_supply_a_key(self):
        s = WizardState(mode=Mode.ENCRYPT, cipher="AES-256-GCM", hybrid_pq=True)
        ok, reason = s.validate_settings()
        assert not ok
        assert "key" in reason.lower()


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
        pw = "T3st!Passw0rd#Str0ng"
        s = WizardState(mode=Mode.ENCRYPT, password=pw, password_confirm=pw)
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
            password="T3st!Passw0rd#Str0ng",
            password_confirm="T3st!Passw0rd#Str0ng",
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

    # These two are about step unlocking, not about the password policy, so
    # they need a password that policy accepts. They used "test", which the
    # wizard took before F-02 and the CLI never would have.
    GOOD_PW = "T3st!Passw0rd#Str0ng"

    def test_review_unlocked_when_complete(self):
        s = WizardState(
            mode=Mode.ENCRYPT,
            input_text="hi",
            password=self.GOOD_PW,
            password_confirm=self.GOOD_PW,
        )
        assert s.is_step_unlocked(STEP_REVIEW)

    def test_output_unlocked_when_review_ok(self):
        s = WizardState(
            mode=Mode.ENCRYPT,
            input_text="hi",
            password=self.GOOD_PW,
            password_confirm=self.GOOD_PW,
        )
        assert s.is_step_unlocked(STEP_OUTPUT)


class TestEncryptionPasswordPolicyMatchesTheCli:
    """The wizard must not accept a password the CLI would refuse.

    Security review 2026-08-02, F-02. `validate_password` checked two things:
    non-empty, and that the confirmation matched. A password of `a` therefore
    passed step validation *and* full review validation, and Execute stayed
    live. The Review screen printed a warning, which is not a control.

    The CLI has always refused a weak password at `check_password_strength`,
    with `--no-strength-check` as the explicit opt-out. So the two interfaces
    disagreed on the tool's own documented 12-character minimum, and the one
    aimed at non-experts was the one that failed open.

    Decryption is deliberately unaffected. A password that was acceptable to an
    older build, or to another tool, still has to open its ciphertext, and
    refusing it would lock people out of their own data to enforce a policy
    that can no longer change anything.
    """

    WEAK = "a"
    STRONG = "T3st!Passw0rd#Str0ng"
    PASSPHRASE = "correct horse battery staple"

    def _state(self, **kw):
        state = WizardState(mode=Mode.ENCRYPT)
        for key, value in kw.items():
            setattr(state, key, value)
        return state

    def test_a_one_character_password_is_refused_for_encryption(self):
        state = self._state(password=self.WEAK, password_confirm=self.WEAK)
        ok, reason = state.validate_password()
        assert not ok, "the wizard accepted a one-character password"
        assert reason, "a refusal with no reason is not actionable"

    def test_a_weak_password_cannot_reach_execute(self):
        """Review must fail too, or the button stays live regardless."""
        state = self._state(
            password=self.WEAK, password_confirm=self.WEAK,
            input_text="secret",
        )
        ok, _ = state.validate_review()
        assert not ok, "Execute was reachable with a one-character password"

    def test_a_strong_password_still_passes(self):
        state = self._state(password=self.STRONG, password_confirm=self.STRONG)
        ok, reason = state.validate_password()
        assert ok, f"a strong password was refused: {reason}"

    def test_decryption_accepts_any_non_empty_password(self):
        """Historical and third-party ciphertexts must stay openable."""
        state = WizardState(mode=Mode.DECRYPT, password=self.WEAK)
        ok, _ = state.validate_password()
        assert ok, "the policy locked the user out of their own ciphertext"

    def test_passphrase_mode_accepts_words_without_symbols(self):
        state = self._state(
            passphrase_mode=True,
            password=self.PASSPHRASE, password_confirm=self.PASSPHRASE,
        )
        ok, reason = state.validate_password()
        assert ok, f"passphrase mode rejected a valid passphrase: {reason}"

    def test_passphrase_mode_still_refuses_something_too_short(self):
        state = self._state(
            passphrase_mode=True, password="two words", password_confirm="two words",
        )
        ok, _ = state.validate_password()
        assert not ok

    def test_the_bypass_exists_and_is_explicit(self):
        """Matching --no-strength-check, so the CLI opt-out has a TUI twin."""
        state = self._state(
            skip_strength_check=True,
            password=self.WEAK, password_confirm=self.WEAK,
        )
        ok, _ = state.validate_password()
        assert ok, "there is no way to override the policy deliberately"

    def test_the_confirmation_check_still_runs_first(self):
        state = self._state(password=self.STRONG, password_confirm="different")
        ok, reason = state.validate_password()
        assert not ok
        assert "match" in reason.lower()
