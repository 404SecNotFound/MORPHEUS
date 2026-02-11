"""Tests for the MORPHEUS dashboard GUI.

Uses Textual's built-in testing framework (app.run_test()) to verify
widget interactions without a real terminal.
"""

from unittest.mock import patch

import pytest
from textual.widgets import Button, Static

from morpheus.ui.app import MorpheusApp, MorpheusWizard
from morpheus.ui.clipboard import clipboard_copy, clipboard_paste
from morpheus.ui.panels import StrengthBar
from morpheus.ui.state import Mode


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


# ── Backward compat alias ──────────────────────────────────────

class TestBackwardCompat:
    """MorpheusWizard alias still works."""

    def test_alias_points_to_app(self):
        assert MorpheusWizard is MorpheusApp


# ── Dashboard integration tests ────────────────────────────────

class TestDashboardApp:
    """Integration tests using Textual's async test harness."""

    @pytest.mark.asyncio
    async def test_app_mounts_with_panels(self):
        """App mounts with all six dashboard panels."""
        app = MorpheusApp()
        async with app.run_test(size=(120, 50)) as pilot:  # noqa: F841
            assert app.query_one("#mode-panel") is not None
            assert app.query_one("#settings-panel") is not None
            assert app.query_one("#status-panel") is not None
            assert app.query_one("#input-panel") is not None
            assert app.query_one("#password-panel") is not None
            assert app.query_one("#output-panel") is not None

    @pytest.mark.asyncio
    async def test_header_shows_morpheus(self):
        """Header bar displays MORPHEUS branding."""
        app = MorpheusApp()
        async with app.run_test(size=(120, 50)) as pilot:  # noqa: F841
            title = app.query_one("#header-title", Static)
            rendered = str(title.render())
            assert "MORPHEUS" in rendered

    @pytest.mark.asyncio
    async def test_execute_disabled_without_input(self):
        """Execute button is disabled when form is incomplete."""
        app = MorpheusApp()
        async with app.run_test(size=(120, 50)) as pilot:  # noqa: F841
            btn = app.query_one("#btn-run", Button)
            assert btn.disabled

    @pytest.mark.asyncio
    async def test_quick_encrypt_sets_mode(self):
        """Ctrl+E sets mode to Encrypt."""
        app = MorpheusApp()
        async with app.run_test(size=(120, 50)) as pilot:
            app.action_quick_encrypt()
            await pilot.pause()
            assert app._state.mode == Mode.ENCRYPT

    @pytest.mark.asyncio
    async def test_quick_decrypt_sets_mode(self):
        """Ctrl+D sets mode to Decrypt."""
        app = MorpheusApp()
        async with app.run_test(size=(120, 50)) as pilot:
            app.action_quick_decrypt()
            await pilot.pause()
            assert app._state.mode == Mode.DECRYPT

    @pytest.mark.asyncio
    async def test_clear_all_resets_state(self):
        """Ctrl+L resets all state fields."""
        app = MorpheusApp()
        async with app.run_test(size=(120, 50)) as pilot:
            # Set some state
            app.action_quick_encrypt()
            await pilot.pause()

            # Clear all
            app.action_clear_all()
            await pilot.pause()
            assert app._state.mode is None
            assert app._state.password == ""
            assert app._state.input_text == ""

    @pytest.mark.asyncio
    async def test_encrypt_decrypt_roundtrip(self):
        """Full encrypt then decrypt through the dashboard state model."""
        app = MorpheusApp()
        async with app.run_test(size=(120, 50)) as pilot:
            plaintext = "Secret message for dashboard test"
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
