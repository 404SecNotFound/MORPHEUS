"""Tests for the MORPHEUS wizard GUI.

Uses Textual's built-in testing framework (app.run_test()) to verify
widget interactions without a real terminal.
"""

import math
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest
from textual.widgets import Button, RadioButton, Static, TextArea
from textual.widgets._footer import FooterKey

from morpheus import __version__
from morpheus.core.validation import check_password_strength
from morpheus.ui import theme
from morpheus.ui.app import MorpheusWizard
from morpheus.ui.clipboard import clipboard_copy, clipboard_paste
from morpheus.ui.state import (
    STEP_INPUT,
    STEP_MODE,
    STEP_OUTPUT,
    STEP_PASSWORD,
    STEP_REVIEW,
    STEP_SETTINGS,
    Mode,
)
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

    Known limit, recorded rather than papered over. This failed 8 runs out of 8
    before the fix, but the step-focus change that landed alongside it also
    guarantees the same property by a second route: focusing the pane forces a
    layout pass that delivers Textual's `Resize`. `OutputArea` is still what
    does the work — instrumenting the real flow showed its `_size_updated`
    performing the re-wrap in 30 arrivals out of 30, and focus arriving while
    the document was still on one line in 24 of them — but deleting
    `OutputArea` now leaves this test green. Anyone reworking step focus should
    re-check the wrap by hand rather than trusting this alone.
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


# ── Keyboard focus ───────────────────────────────────────────────

@asynccontextmanager
async def _wizard_on_step(step: int):
    """Run the wizard with every step unlocked, showing `step`."""
    app = MorpheusWizard()
    async with app.run_test(size=(110, 38)) as pilot:
        app._state.mode = Mode.ENCRYPT
        app._state.input_text = "canary"
        app._state.password = "T3st!Passw0rd#Str0ng"
        app._state.password_confirm = "T3st!Passw0rd#Str0ng"
        # Step 6 is gated on the run having happened, so seed the result and
        # the completion marker or `_goto_step` refuses the jump.
        app._state.output = "MORPHEUS-v1:c2FtcGxlIGNpcGhlcnRleHQ="
        app._state.completed_steps.add(STEP_OUTPUT)
        app._goto_step(step)
        await pilot.pause()
        assert app._current_step == step, (
            f"step {step + 1} was refused; this would assert about step "
            f"{app._current_step + 1} instead"
        )
        yield app, pilot


class TestStepContentTakesFocus:
    """Arriving at a step hands the keyboard to the step, not to the sidebar.

    Focus used to stay on the first sidebar row for the whole session, because
    Textual's auto-focus put it there when the app mounted and nothing ever
    took it away. Up/Down and Enter therefore drove the step list, so the Mode
    step's own instruction ("Use Up/Down arrows to highlight, Enter to select")
    did nothing, and Escape's "focus the sidebar" had nothing to mean.

    Note for anyone reading this after a bug report about the Mode step: the
    radio restoring from state is *not* broken, and TestModeStepRestoresFromState
    below pins that. Focus was the defect.
    """

    # Every step that composes a focusable control, with the one that must take
    # it. Listed in full rather than for one step, because the fix walks the
    # panel for the first focusable widget and each of these finds a different
    # widget type: RadioSet, Select, RadioSet, Input, TextArea.
    FIRST_CONTROLS = [
        (STEP_MODE, "mode-radio"),
        (STEP_SETTINGS, "cipher-select"),
        (STEP_INPUT, "input-tabs"),
        (STEP_PASSWORD, "pwd-input"),
        (STEP_OUTPUT, "output-area"),
    ]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("step,control", FIRST_CONTROLS)
    async def test_focus_lands_on_the_step_and_not_the_sidebar(self, step, control):
        async with _wizard_on_step(step) as (app, _):
            panel = app.query_one("#step-container").children[0]
            focused = app.focused
            assert focused is not None, "nothing is focused"
            assert panel in focused.ancestors, (
                f"focus is on {focused.__class__.__name__}#{focused.id}, which "
                f"is outside the step panel; the keyboard drives that instead "
                f"of step {step + 1}"
            )
            assert focused.id == control

    @pytest.mark.asyncio
    async def test_a_step_with_no_focusable_control_falls_back_to_the_sidebar(self):
        """Review composes none, and must not raise or strand the keyboard."""
        async with _wizard_on_step(STEP_REVIEW) as (app, _):
            panel = app.query_one("#step-container").children[0]
            assert not [w for w in panel.query("*") if w.focusable], (
                "Review has gained a focusable control, so this no longer "
                "covers the empty case it was written for"
            )
            focused = app.focused
            assert focused is not None and focused.id == f"sb-{STEP_REVIEW}", (
                f"expected the sidebar row for the current step, got {focused}"
            )

    @pytest.mark.asyncio
    async def test_escape_returns_focus_to_the_sidebar(self):
        """The sidebar has to stay reachable now that steps claim focus.

        This is a real assertion for the first time. `action_focus_sidebar`
        called `Sidebar.focus()`, and `Sidebar` is a plain container, so it was
        a silent no-op — Escape never moved focus. Nobody noticed while focus
        never left the sidebar to begin with.
        """
        async with _wizard_on_step(STEP_PASSWORD) as (app, pilot):
            assert app.focused.id == "pwd-input"
            await pilot.press("escape")
            await pilot.pause()
            assert app.focused.id == f"sb-{STEP_PASSWORD}", (
                f"escape left focus on {app.focused}; the sidebar cannot be "
                "reached from the step"
            )

    @pytest.mark.asyncio
    async def test_the_sidebar_still_selects_a_step_with_enter(self):
        """Reachable is not enough; it has to still work once you are there."""
        async with _wizard_on_step(STEP_PASSWORD) as (app, pilot):
            await pilot.press("escape")
            await pilot.pause()
            await pilot.press("tab")       # sb-3 -> sb-4 (Review)
            await pilot.pause()
            assert app.focused.id == f"sb-{STEP_REVIEW}", (
                f"tab did not move along the sidebar, it left {app.focused}"
            )
            await pilot.press("enter")
            await pilot.pause()
            assert app._current_step == STEP_REVIEW


class TestGlobalShortcutsSurviveFocus:
    """Ctrl+E and Ctrl+D still reach the app when a text field has focus.

    Textual's Input and TextArea bind "end,ctrl+e" and "delete,ctrl+d", so once
    steps started taking focus these two shortcuts stopped working on the
    Password and Output steps and the footer quietly dropped them there. The
    app binds both `priority=True`, which is what this pins. It cannot be
    caught by calling `action_quick_encrypt()` directly the way the older
    shortcut tests do — the binding is the part that broke, so these press keys.
    """

    # The two steps whose first control is a text widget that claims the keys.
    TEXT_FIELD_STEPS = [(STEP_PASSWORD, "pwd-input"), (STEP_OUTPUT, "output-area")]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("step,control", TEXT_FIELD_STEPS)
    async def test_ctrl_e_and_ctrl_d_are_not_swallowed_by_the_focused_field(
        self, step, control
    ):
        async with _wizard_on_step(step) as (app, pilot):
            assert app.focused.id == control, "this step no longer focuses a text field"

            app._state.mode = Mode.DECRYPT
            await pilot.press("ctrl+e")
            await pilot.pause()
            assert app._state.mode == Mode.ENCRYPT, (
                "ctrl+e reached the focused field instead of the app"
            )

            await pilot.press("ctrl+d")
            await pilot.pause()
            assert app._state.mode == Mode.DECRYPT, (
                "ctrl+d reached the focused field instead of the app"
            )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("step,control", TEXT_FIELD_STEPS)
    async def test_the_footer_still_advertises_them(self, step, control):
        """The footer is the only place these shortcuts are discoverable."""
        async with _wizard_on_step(step) as (app, pilot):
            await pilot.pause()  # the footer redraws a hop after focus moves
            keys = {key.key for key in app.query(FooterKey)}
            assert {"ctrl+e", "ctrl+d"} <= keys, (
                f"step {step + 1} hides shortcuts the app still honours: {sorted(keys)}"
            )


class TestModeStepRestoresFromState:
    """The Mode radio restores from state. `mode.py` does not need fixing.

    This exists to close a bug report that misread the symptom. The report said
    returning to the Mode step left both radios unchecked; the repro set
    `state.mode` and then jumped to the Mode step *while already on it*, which
    `_goto_step` short-circuits, so nothing re-composed and the widget built at
    startup — when `mode` was still None — was still the one on screen.
    `compose()` was always right: it passes `value=self._state.mode == Mode.X`.

    Deleting this test and "fixing" `mode.py` would be a change to working code.
    """

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "mode,on,off",
        [
            (Mode.ENCRYPT, "radio-encrypt", "radio-decrypt"),
            (Mode.DECRYPT, "radio-decrypt", "radio-encrypt"),
        ],
    )
    async def test_the_radio_restores_on_a_genuine_re_mount(self, mode, on, off):
        app = MorpheusWizard()
        async with app.run_test(size=(110, 38)) as pilot:
            app._state.mode = mode
            app._state.completed_steps.add(STEP_MODE)

            # Leave and come back, so the step is really rebuilt. Jumping to
            # the step already on screen is the no-op that misled the report.
            app._goto_step(STEP_SETTINGS)
            await pilot.pause()
            app._goto_step(STEP_MODE)
            await pilot.pause()
            assert app._current_step == STEP_MODE

            chosen = app.query_one(f"#{on}", RadioButton)
            other = app.query_one(f"#{off}", RadioButton)
            assert chosen.value is True
            assert "-on" in chosen.classes, (
                f"{on} is checked but not marked, so it reads as unselected"
            )
            assert other.value is False
            assert "-on" not in other.classes


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
