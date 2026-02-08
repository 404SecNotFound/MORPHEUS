"""Tests for the Textual GUI application.

Uses Textual's built-in testing framework (app.run_test()) to verify
widget interactions without a real terminal.
"""

import pytest
from textual.widgets import Button, Checkbox, Input, RadioButton, Select, Static, TextArea

from morpheus.gui import SecureEncryptionApp, StrengthBar


class TestStrengthBar:
    """Unit tests for the password strength indicator widget."""

    def test_weak_renders_red(self):
        bar = StrengthBar()
        bar.score = 20
        rendered = bar.render()
        assert "red" in rendered
        assert "Weak" in rendered

    def test_fair_renders_yellow(self):
        bar = StrengthBar()
        bar.score = 40
        rendered = bar.render()
        assert "yellow" in rendered
        assert "Fair" in rendered

    def test_strong_renders_cyan(self):
        bar = StrengthBar()
        bar.score = 60
        rendered = bar.render()
        assert "cyan" in rendered
        assert "Strong" in rendered

    def test_excellent_renders_green(self):
        bar = StrengthBar()
        bar.score = 80
        rendered = bar.render()
        assert "green" in rendered
        assert "Excellent" in rendered

    def test_zero_score(self):
        bar = StrengthBar()
        bar.score = 0
        rendered = bar.render()
        assert "Weak" in rendered


class TestGUIApp:
    """Integration tests using Textual's async test harness."""

    @pytest.mark.asyncio
    async def test_app_mounts(self):
        """App mounts without errors and key widgets are present."""
        app = SecureEncryptionApp()
        async with app.run_test(size=(120, 50)) as pilot:  # noqa: F841
            assert app.query_one("#input-text", TextArea) is not None
            assert app.query_one("#password-input", Input) is not None
            assert app.query_one("#password-confirm", Input) is not None
            assert app.query_one("#action-btn", Button) is not None
            assert app.query_one("#cipher-select", Select) is not None
            assert app.query_one("#kdf-select", Select) is not None

    @pytest.mark.asyncio
    async def test_mode_toggle_changes_button(self):
        """Switching to Decrypt mode changes the action button label."""
        app = SecureEncryptionApp()
        async with app.run_test(size=(120, 50)) as pilot:
            btn = app.query_one("#action-btn", Button)
            assert str(btn.label) == "ENCRYPT"

            # Set decrypt radio value directly (click may not target correctly)
            decrypt_radio = app.query_one("#mode-decrypt", RadioButton)
            decrypt_radio.value = True
            await pilot.pause()

            assert str(btn.label) == "DECRYPT"

    @pytest.mark.asyncio
    async def test_encrypt_empty_input_no_output(self):
        """Encrypting with empty input does not produce output."""
        app = SecureEncryptionApp()
        async with app.run_test(size=(120, 50)) as pilot:
            app.query_one("#password-input", Input).value = "T3st!Passw0rd#Str0ng"
            app.query_one("#password-confirm", Input).value = "T3st!Passw0rd#Str0ng"

            app._do_encrypt()
            await app.workers.wait_for_complete()
            await pilot.pause()

            output = app.query_one("#output-text", TextArea).text.strip()
            assert output == ""

    @pytest.mark.asyncio
    async def test_encrypt_empty_password_no_output(self):
        """Encrypting with empty password does not produce output."""
        app = SecureEncryptionApp()
        async with app.run_test(size=(120, 50)) as pilot:
            app.query_one("#input-text", TextArea).insert("Hello world")

            app._do_encrypt()
            await app.workers.wait_for_complete()
            await pilot.pause()

            output = app.query_one("#output-text", TextArea).text.strip()
            assert output == ""

    @pytest.mark.asyncio
    async def test_encrypt_decrypt_roundtrip(self):
        """Full encrypt/decrypt cycle through the GUI."""
        app = SecureEncryptionApp()
        async with app.run_test(size=(120, 50)) as pilot:
            plaintext = "Secret message for GUI test"
            password = "T3st!Passw0rd#Str0ng"

            input_area = app.query_one("#input-text", TextArea)
            input_area.insert(plaintext)
            app.query_one("#password-input", Input).value = password
            app.query_one("#password-confirm", Input).value = password

            # Encrypt via action method
            app._do_encrypt()
            # Wait for the threaded worker to complete
            await app.workers.wait_for_complete()
            await pilot.pause()

            output_area = app.query_one("#output-text", TextArea)
            encrypted = output_area.text.strip()
            assert len(encrypted) > 0

            # Switch to decrypt
            app.query_one("#mode-decrypt", RadioButton).value = True
            await pilot.pause()

            # Clear and paste encrypted text
            input_area.clear()
            input_area.insert(encrypted)

            # Decrypt
            app._do_decrypt()
            await app.workers.wait_for_complete()
            await pilot.pause()

            decrypted = output_area.text.strip()
            assert decrypted == plaintext

    @pytest.mark.asyncio
    async def test_pq_checkbox_toggles_keygen_section(self):
        """Enabling PQ checkbox shows the key generation section."""
        app = SecureEncryptionApp()
        async with app.run_test(size=(120, 50)) as pilot:
            keygen = app.query_one("#keygen-section")
            pq_check = app.query_one("#pq-check", Checkbox)

            if not pq_check.disabled:
                pq_check.value = True
                await pilot.pause()
                assert keygen.display is True

    @pytest.mark.asyncio
    async def test_clear_all_action(self):
        """Ctrl+L (clear all) resets input, password, and output."""
        app = SecureEncryptionApp()
        async with app.run_test(size=(120, 50)) as pilot:
            app.query_one("#input-text", TextArea).insert("some text")
            app.query_one("#password-input", Input).value = "password"

            # Trigger clear all via action
            app.action_clear_all()
            await pilot.pause()

            assert app.query_one("#input-text", TextArea).text == ""
            assert app.query_one("#password-input", Input).value == ""
            assert app.query_one("#password-confirm", Input).value == ""

    @pytest.mark.asyncio
    async def test_password_match_indicator(self):
        """Password match indicator updates when passwords match/differ."""
        app = SecureEncryptionApp()
        async with app.run_test(size=(120, 50)) as pilot:
            pwd_input = app.query_one("#password-input", Input)
            confirm_input = app.query_one("#password-confirm", Input)
            match_label = app.query_one("#password-match", Static)

            pwd_input.value = "T3st!Pass"
            confirm_input.value = "T3st!Pass"
            await pilot.pause()
            rendered = str(match_label.render())
            assert "Match" in rendered

            confirm_input.value = "different"
            await pilot.pause()
            rendered = str(match_label.render())
            assert "No match" in rendered

    @pytest.mark.asyncio
    async def test_on_unmount_zeros_keys(self):
        """on_unmount() zeros PQ key material."""
        app = SecureEncryptionApp()
        async with app.run_test(size=(120, 50)) as pilot:  # noqa: F841
            app._pq_public_key = bytearray(b"\xff" * 32)
            app._pq_secret_key = bytearray(b"\xff" * 32)

        # After exiting run_test, on_unmount should have been called
        assert app._pq_public_key is None
        assert app._pq_secret_key is None
