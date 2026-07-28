"""Tests for the MORPHEUS wizard GUI.

Uses Textual's built-in testing framework (app.run_test()) to verify
widget interactions without a real terminal.
"""

import math
from unittest.mock import patch

import pytest
from textual.widgets import Button, RadioButton, Static, TextArea

from morpheus import __version__
from morpheus.core.validation import check_password_strength
from morpheus.ui import theme
from morpheus.ui.app import MorpheusWizard
from morpheus.ui.clipboard import clipboard_copy, clipboard_paste
from morpheus.ui.state import STEP_MODE, STEP_OUTPUT, Mode
from morpheus.ui.steps.password import StrengthBar

# ── StrengthBar unit tests ──────────────────────────────────────

class TestStrengthBar:
    """Unit tests for the password strength indicator widget."""

    def test_weak_renders_error(self):
        bar = StrengthBar()
        bar.score = 20
        rendered = bar.render()
        assert theme.ERROR in rendered
        assert "Weak" in rendered

    def test_fair_renders_secondary(self):
        bar = StrengthBar()
        bar.score = 40
        rendered = bar.render()
        assert theme.TEXT_2 in rendered
        assert "Fair" in rendered

    def test_strong_renders_primary(self):
        bar = StrengthBar()
        bar.score = 60
        rendered = bar.render()
        assert theme.TEXT in rendered
        assert "Strong" in rendered

    def test_excellent_renders_primary(self):
        bar = StrengthBar()
        bar.score = 80
        rendered = bar.render()
        assert theme.TEXT in rendered
        assert "Excellent" in rendered

    def test_zero_score(self):
        bar = StrengthBar()
        bar.score = 0
        rendered = bar.render()
        assert "Very weak" in rendered

    def test_label_agrees_with_validation_below_twenty(self):
        """The password step and the review step must not disagree.

        Both bands under 40 render in ERROR, so the label is the only thing
        distinguishing them. "abc" scores 15, which is the range where the
        widget used to say "Very weak" while review.py said "Weak".
        """
        result = check_password_strength("abc")
        assert result.score < 20
        bar = StrengthBar()
        bar.score = result.score
        assert result.label in bar.render()


# ── Wizard app integration tests ────────────────────────────────

class TestWizardApp:
    """Integration tests using Textual's async test harness."""

    def test_window_title_tracks_the_package_version(self):
        """TITLE is user-visible; two stale 'v2.0' labels shipped without this."""
        assert MorpheusWizard.TITLE.endswith(__version__)

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


# ── Output step rendering ────────────────────────────────────────

class TestOutputAreaWrapsDeterministically:
    """The ciphertext must wrap to the pane, on every run.

    It used to do so about half the time. Textual wraps a TextArea against
    `wrap_width`, which comes from the widget's compositor region; a widget
    being mounted has no region, so text written in `on_mount` was wrapped at
    width 0 — one long line, clipped at the pane edge. Textual's correction
    runs on the `Resize` message, and that message is delivered asynchronously
    with no ordering guarantee against the next paint, so the same ciphertext
    rendered wrapped or clipped depending on which won.

    These assert the property rather than a screenshot hash. A hash would be a
    proxy for the real invariant, would repeat six full captures per run to
    prove determinism, and would fail on every unrelated copy or palette edit;
    `tests/test_theme.py` already owns rendered-SVG guarding. What actually
    broke is "the document is wrapped at the width the widget really has", and
    that is checkable directly and cheaply.
    """

    # One unbroken base64-ish token, wide enough to need several visual lines
    # at the pane width.
    CIPHERTEXT = "MORPHEUS-v1:" + "QUJDREVGR0hJSktM" * 12

    # Each visit re-mounts the step, and each re-mount is an independent roll:
    # measured against the unfixed code, a visit wrapped at width 0 about 28%
    # of the time. Jumping straight to step 6 from a freshly started app never
    # lost the race — the first layout pass always delivered its Resize in
    # time — so a visit has to *replace* a step already on screen to be a real
    # trial. 20 of them leaves roughly a 1-in-1000 chance of a broken build
    # looking clean.
    VISITS = 20

    async def _visit_output_repeatedly(self) -> list[tuple[int, int]]:
        """Return to step 6 repeatedly, reporting (wrap width, line count)."""
        app = MorpheusWizard()
        seen = []
        async with app.run_test(size=(110, 38)) as pilot:
            app._state.mode = Mode.ENCRYPT
            app._state.input_text = "canary"
            app._state.password = "T3st!Passw0rd#Str0ng"
            app._state.password_confirm = "T3st!Passw0rd#Str0ng"
            # Step 6 is gated on the run having happened, so seed the result
            # and the completion marker or `_goto_step` refuses the jump.
            app._state.output = self.CIPHERTEXT
            app._state.completed_steps.add(STEP_OUTPUT)
            for _ in range(self.VISITS):
                app._goto_step(STEP_OUTPUT)
                await pilot.pause()
                assert app._current_step == STEP_OUTPUT, (
                    "the jump to step 6 was refused, so this would measure "
                    f"step {app._current_step + 1} instead"
                )
                area = app.query_one("#output-area", TextArea)
                seen.append((area.wrap_width, area.wrapped_document.height))
                # Leave, so the next arrival replaces a mounted step rather
                # than being a no-op.
                app._goto_step(STEP_MODE)
                await pilot.pause()
        return seen

    @pytest.mark.asyncio
    async def test_the_output_pane_always_renders_the_same_way(self):
        """Width settled, text wrapped, and identical on every visit.

        Asserted together because they are one property measured once: the
        helper is the slow part, and splitting it would triple the runtime to
        re-derive the same list.
        """
        seen = await self._visit_output_repeatedly()

        assert len(set(seen)) == 1, (
            "the same ciphertext wrapped differently across identical visits, "
            f"so the render depends on event ordering: {sorted(set(seen))}"
        )

        wrap_width, height = seen[0]
        assert wrap_width > 0, (
            "the output pane reports no width, so its contents are wrapped "
            "against nothing and render as one clipped line"
        )

        expected = math.ceil(len(self.CIPHERTEXT) / wrap_width)
        assert height == expected > 1, (
            f"{len(self.CIPHERTEXT)} characters at width {wrap_width} need "
            f"{expected} visual lines but the document reports {height}; "
            "1 means the text sits on a single line running off the pane"
        )


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
        # Patch the module object, not tk.Tk: tkinter is optional, so on a
        # Python built without Tk `clipboard.tk` is None and has no attributes.
        with patch("morpheus.ui.clipboard._pyperclip", None), \
             patch("morpheus.ui.clipboard.subprocess.run", side_effect=FileNotFoundError), \
             patch("morpheus.ui.clipboard.tk") as mock_tk:
            tk_root = mock_tk.Tk.return_value
            tk_root.clipboard_get.return_value = "from-tkinter"
            assert clipboard_paste() == "from-tkinter"

    def test_returns_none_when_tkinter_unavailable(self):
        """Python without Tk must degrade gracefully, not raise."""
        with patch("morpheus.ui.clipboard._pyperclip", None), \
             patch("morpheus.ui.clipboard.subprocess.run", side_effect=FileNotFoundError), \
             patch("morpheus.ui.clipboard.tk", None):
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

    def test_tkinter_fallback(self):
        # Patch the module object, not tk.Tk: see the note in TestClipboardPaste.
        with patch("morpheus.ui.clipboard._pyperclip", None), \
             patch("morpheus.ui.clipboard.subprocess.Popen", side_effect=FileNotFoundError), \
             patch("morpheus.ui.clipboard.tk") as mock_tk:
            ok, method = clipboard_copy("test")
            assert ok is True
            assert method == "tkinter"
            tk_root = mock_tk.Tk.return_value
            tk_root.clipboard_append.assert_called_once_with("test")

    def test_returns_false_when_tkinter_unavailable(self):
        """Python without Tk must degrade gracefully, not raise."""
        with patch("morpheus.ui.clipboard._pyperclip", None), \
             patch("morpheus.ui.clipboard.subprocess.Popen", side_effect=FileNotFoundError), \
             patch("morpheus.ui.clipboard.tk", None):
            ok, method = clipboard_copy("test")
            assert ok is False
            assert method == ""
