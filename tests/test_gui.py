"""Tests for the MORPHEUS wizard GUI.

Uses Textual's built-in testing framework (app.run_test()) to verify
widget interactions without a real terminal.
"""

from unittest.mock import patch

import pytest
from textual.widgets import Button, RadioButton, Static

from morpheus.ui.app import MorpheusWizard
from morpheus.ui.clipboard import clipboard_copy, clipboard_paste
from morpheus.ui.state import Mode
from morpheus.ui.steps.password import StrengthBar


# ── StrengthBar unit tests ──────────────────────────────────────

class TestStrengthBar:
    """Unit tests for the password strength indicator widget."""

    def test_weak_renders_orange(self):
        bar = StrengthBar()
        bar.score = 20
        rendered = bar.render()
        assert "#FF8800" in rendered
        assert "Weak" in rendered

    def test_fair_renders_gold(self):
        bar = StrengthBar()
        bar.score = 40
        rendered = bar.render()
        assert "#FFD700" in rendered
        assert "Fair" in rendered

    def test_strong_renders_green(self):
        bar = StrengthBar()
        bar.score = 60
        rendered = bar.render()
        assert "#00CC33" in rendered
        assert "Strong" in rendered

    def test_excellent_renders_matrix_green(self):
        bar = StrengthBar()
        bar.score = 80
        rendered = bar.render()
        assert "#00FF41" in rendered
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
    """Test the clipboard fallback chain."""

    def test_pyperclip_used_first(self):
        with patch("morpheus.ui.clipboard._pyperclip") as mock_pp:
            mock_pp.paste.return_value = "from-pyperclip"
            assert clipboard_paste() == "from-pyperclip"

    def test_subprocess_fallback_on_pyperclip_failure(self):
        with patch("morpheus.ui.clipboard._pyperclip", None), \
             patch("morpheus.ui.clipboard.subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {"returncode": 0, "stdout": "from-xclip"})()
            result = clipboard_paste()
            assert result == "from-xclip"

    def test_returns_none_when_all_fail(self):
        with patch("morpheus.ui.clipboard._pyperclip", None), \
             patch("morpheus.ui.clipboard.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError
            assert clipboard_paste() is None

    def test_tkinter_fallback(self):
        with patch("morpheus.ui.clipboard._pyperclip", None), \
             patch("morpheus.ui.clipboard.subprocess.run", side_effect=FileNotFoundError), \
             patch("morpheus.ui.clipboard.tk.Tk") as mock_tk:
            tk_root = mock_tk.return_value
            tk_root.clipboard_get.return_value = "from-tkinter"
            assert clipboard_paste() == "from-tkinter"


class TestClipboardCopy:
    """Test the clipboard copy fallback chain."""

    def test_pyperclip_copy(self):
        with patch("morpheus.ui.clipboard._pyperclip") as mock_pp:
            ok, method = clipboard_copy("test")
            mock_pp.copy.assert_called_once_with("test")
            assert ok is True
            assert method == "pyperclip"

    def test_returns_false_when_all_fail(self):
        with patch("morpheus.ui.clipboard._pyperclip", None), \
             patch("morpheus.ui.clipboard.subprocess.Popen") as mock_popen:
            mock_popen.side_effect = FileNotFoundError
            ok, method = clipboard_copy("test")
            assert ok is False

    def test_tkinter_fallback(self):
        with patch("morpheus.ui.clipboard._pyperclip", None), \
             patch("morpheus.ui.clipboard.subprocess.Popen", side_effect=FileNotFoundError), \
             patch("morpheus.ui.clipboard.tk.Tk") as mock_tk:
            ok, method = clipboard_copy("test")
            assert ok is True
            assert method == "tkinter"
            tk_root = mock_tk.return_value
            tk_root.clipboard_append.assert_called_once_with("test")
