"""Tests for the MORPHEUS wizard GUI.

Uses Textual's built-in testing framework (app.run_test()) to verify
widget interactions without a real terminal.
"""

from unittest.mock import patch

import pytest
from textual.widgets import Button, RadioButton, Static

from morpheus.ui.app import MorpheusWizard
from morpheus.ui.state import Mode
from morpheus.ui.steps.password import StrengthBar, _clipboard_paste


# ── StrengthBar unit tests ──────────────────────────────────────

class TestStrengthBar:
    """Unit tests for the password strength indicator widget."""

    def test_weak_renders_red(self):
        bar = StrengthBar()
        bar.score = 20
        rendered = bar.render()
        assert "#E09050" in rendered
        assert "Weak" in rendered

    def test_fair_renders_amber(self):
        bar = StrengthBar()
        bar.score = 40
        rendered = bar.render()
        assert "#E2B93B" in rendered
        assert "Fair" in rendered

    def test_strong_renders_blue(self):
        bar = StrengthBar()
        bar.score = 60
        rendered = bar.render()
        assert "#5B8CFF" in rendered
        assert "Strong" in rendered

    def test_excellent_renders_green(self):
        bar = StrengthBar()
        bar.score = 80
        rendered = bar.render()
        assert "#6BCB77" in rendered
        assert "Excellent" in rendered

    def test_zero_score(self):
        bar = StrengthBar()
        bar.score = 0
        rendered = bar.render()
        assert "Very weak" in rendered


# ── Wizard app integration tests ────────────────────────────────

class TestWizardApp:
    """Integration tests using Textual's async test harness."""

    @pytest.mark.asyncio
    async def test_app_mounts_with_sidebar(self):
        """App mounts with sidebar and step container."""
        app = MorpheusWizard()
        async with app.run_test(size=(120, 50)) as pilot:  # noqa: F841
            assert app.query_one("#sidebar") is not None
            assert app.query_one("#step-container") is not None
            assert app.query_one("#btn-back", Button) is not None
            assert app.query_one("#btn-next", Button) is not None

    @pytest.mark.asyncio
    async def test_initial_step_is_mode(self):
        """App starts on the Mode step."""
        app = MorpheusWizard()
        async with app.run_test(size=(120, 50)) as pilot:  # noqa: F841
            step_label = app.query_one("#top-step", Static)
            rendered = str(step_label.render())
            assert "Mode" in rendered

    @pytest.mark.asyncio
    async def test_navigation_next_and_back(self):
        """Next goes to Settings, Back returns to Mode."""
        app = MorpheusWizard()
        async with app.run_test(size=(120, 50)) as pilot:
            # Select Encrypt mode first
            encrypt_radio = app.query_one("#radio-encrypt", RadioButton)
            encrypt_radio.value = True
            await pilot.pause()

            # Next
            app.action_next_step()
            await pilot.pause()
            step_label = str(app.query_one("#top-step", Static).render())
            assert "Settings" in step_label

            # Back
            app.action_prev_step()
            await pilot.pause()
            step_label = str(app.query_one("#top-step", Static).render())
            assert "Mode" in step_label

    @pytest.mark.asyncio
    async def test_next_blocked_without_mode(self):
        """Cannot advance past Mode without selecting Encrypt or Decrypt."""
        app = MorpheusWizard()
        async with app.run_test(size=(120, 50)) as pilot:  # noqa: F841
            btn = app.query_one("#btn-next", Button)
            assert btn.disabled

    @pytest.mark.asyncio
    async def test_quick_encrypt_shortcut(self):
        """Ctrl+E sets mode to Encrypt and advances to Settings."""
        app = MorpheusWizard()
        async with app.run_test(size=(120, 50)) as pilot:
            app.action_quick_encrypt()
            await pilot.pause()
            assert app._state.mode == Mode.ENCRYPT
            step_label = str(app.query_one("#top-step", Static).render())
            assert "Settings" in step_label

    @pytest.mark.asyncio
    async def test_quick_decrypt_shortcut(self):
        """Ctrl+D sets mode to Decrypt and advances to Settings."""
        app = MorpheusWizard()
        async with app.run_test(size=(120, 50)) as pilot:
            app.action_quick_decrypt()
            await pilot.pause()
            assert app._state.mode == Mode.DECRYPT
            step_label = str(app.query_one("#top-step", Static).render())
            assert "Settings" in step_label

    @pytest.mark.asyncio
    async def test_clear_all_resets_to_mode(self):
        """Ctrl+L resets state and goes back to Mode step."""
        app = MorpheusWizard()
        async with app.run_test(size=(120, 50)) as pilot:
            # Advance to settings
            app.action_quick_encrypt()
            await pilot.pause()

            # Clear all
            app.action_clear_all()
            await pilot.pause()
            assert app._state.mode is None
            step_label = str(app.query_one("#top-step", Static).render())
            assert "Mode" in step_label

    @pytest.mark.asyncio
    async def test_encrypt_decrypt_roundtrip(self):
        """Full encrypt then decrypt through the wizard state model."""
        app = MorpheusWizard()
        async with app.run_test(size=(120, 50)) as pilot:
            plaintext = "Secret message for wizard test"
            password = "T3st!Passw0rd#Str0ng"

            # Set state directly for speed
            app._state.mode = Mode.ENCRYPT
            app._state.input_text = plaintext
            app._state.password = password
            app._state.password_confirm = password

            # Run encryption
            app._do_encrypt()
            await app.workers.wait_for_complete()
            await pilot.pause()

            encrypted = app._state.output
            assert len(encrypted) > 0

            # Decrypt
            app._state.mode = Mode.DECRYPT
            app._state.input_text = encrypted
            app._state.password = password
            app._state.output = ""

            app._do_decrypt()
            await app.workers.wait_for_complete()
            await pilot.pause()

            assert app._state.output == plaintext


# ── Clipboard helpers ────────────────────────────────────────────

class TestClipboardPaste:
    """Test the clipboard fallback chain in the password step."""

    def test_pyperclip_used_first(self):
        with patch("morpheus.ui.steps.password._pyperclip") as mock_pp:
            mock_pp.paste.return_value = "from-pyperclip"
            assert _clipboard_paste() == "from-pyperclip"

    def test_subprocess_fallback_on_pyperclip_failure(self):
        with patch("morpheus.ui.steps.password._pyperclip", None), \
             patch("morpheus.ui.steps.password.subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {"returncode": 0, "stdout": "from-xclip"})()
            result = _clipboard_paste()
            assert result == "from-xclip"

    def test_returns_none_when_all_fail(self):
        with patch("morpheus.ui.steps.password._pyperclip", None), \
             patch("morpheus.ui.steps.password.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError
            assert _clipboard_paste() is None
