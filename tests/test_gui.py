"""Tests for the MORPHEUS wizard GUI.

Uses Textual's built-in testing framework (app.run_test()) to verify
widget interactions without a real terminal.
"""

import math
from contextlib import asynccontextmanager
from unittest.mock import patch

import pytest
from textual.widgets import Button, Checkbox, Collapsible, RadioButton, Static, TextArea
from textual.widgets._footer import FooterKey

from morpheus_crypt import __version__
from morpheus_crypt.core.validation import check_password_strength
from morpheus_crypt.ui import theme
from morpheus_crypt.ui.app import MIN_HEIGHT, MIN_WIDTH, MorpheusWizard
from morpheus_crypt.ui.clipboard import clipboard_copy, clipboard_paste
from morpheus_crypt.ui.state import (
    STEP_INPUT,
    STEP_MODE,
    STEP_OUTPUT,
    STEP_PASSWORD,
    STEP_REVIEW,
    STEP_SETTINGS,
    Mode,
)
from morpheus_crypt.ui.steps.password import StrengthBar
from tests.support import settle, settle_on, settle_on_sidebar

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
            await settle(app, pilot)
            step_label = str(app.query_one("#top-step", Static).render())
            assert "Settings" in step_label

            # Back
            app.action_prev_step()
            await settle(app, pilot)
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
            await settle(app, pilot)
            assert app._state.mode == Mode.ENCRYPT
            step_label = str(app.query_one("#top-step", Static).render())
            assert "Settings" in step_label

    @pytest.mark.asyncio
    async def test_quick_decrypt_shortcut(self):
        """Ctrl+D sets mode to Decrypt and advances to Settings."""
        app = MorpheusWizard()
        async with app.run_test(size=(120, 50)) as pilot:
            app.action_quick_decrypt()
            await settle(app, pilot)
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
            await settle(app, pilot)

            # Clear all
            app.action_clear_all()
            await settle(app, pilot)
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


# ── The settle() helper itself ───────────────────────────────────

class TestSettleWaitsForTheRightThing:
    """`settle` guards every GUI test, so its own postcondition needs a guard.

    It used to return as soon as `app.focused` stopped changing. That is also
    true while focus is *still on the sidebar* and the `call_after_refresh`
    handoff has not been scheduled yet — a transient stable state, not the end
    state. The Windows CI runner hit that window and
    `TestStepContentTakesFocus` failed there while passing everywhere else.

    Driven with a fake app rather than a real one, because the point is the
    helper's decision logic and a real app cannot be held on the sidebar: its
    own handoff moves focus away immediately, which is what makes the race so
    hard to reproduce by hand.
    """

    class _W:
        def __init__(self, name, ancestors):
            self.id, self.ancestors = name, ancestors

        def __repr__(self):
            return f"_W({self.id})"

    class _Workers:
        async def wait_for_complete(self):
            return

    class _FakeApp:
        def __init__(self, outer, land_after):
            self.sidebar = object()
            self.workers = outer._Workers()
            self.n = 0
            self.land_after = land_after
            self._on_sidebar = outer._W("sb-0", [self.sidebar])
            self._on_step = outer._W("mode-radio", [object()])

        def query_one(self, selector):
            assert selector == "#sidebar"
            return self.sidebar

        @property
        def focused(self):
            if self.land_after is not None and self.n >= self.land_after:
                return self._on_step
            return self._on_sidebar

    class _FakePilot:
        def __init__(self, app):
            self.app = app

        async def pause(self):
            self.app.n += 1

    @pytest.mark.asyncio
    async def test_focus_stable_on_the_sidebar_is_not_settled(self):
        """The regression: stable, but stable in the wrong place."""
        app = self._FakeApp(self, land_after=None)
        with pytest.raises(AssertionError, match="never landed off the sidebar"):
            await settle(app, self._FakePilot(app))

    @pytest.mark.asyncio
    async def test_returns_once_focus_lands_and_then_holds_still(self):
        app = self._FakeApp(self, land_after=3)
        await settle(app, self._FakePilot(app))
        assert app.n >= 4, "must wait for landing plus one stable frame"


# ── Settings step: hybrid PQ is CLI-only ─────────────────────────

class TestSettingsDoesNotOfferHybridPQ:
    """The wizard must not present a control it cannot honour (UAT DEF-006).

    Settings used to offer a "Hybrid Post-Quantum" checkbox while the TUI had
    no keypair generation, no key entry and no key display anywhere. Ticking
    it walked the user through four more steps, took a password and a
    confirmation, and only then failed out of the pipeline. `docs/USAGE.md`
    compounded it by telling GUI users to click a "Generate Keypair" button
    that never existed, for the feature the README calls differentiator #1.

    The product decision was to make hybrid PQ command-line only, so the
    control is gone and the step signposts the CLI route instead. These
    assertions fail if the checkbox comes back without key management.
    """

    @pytest.mark.asyncio
    async def test_no_hybrid_pq_control_exists_on_settings(self):
        app = MorpheusWizard()
        async with app.run_test(size=(120, 50)) as pilot:
            app._state.mode = Mode.ENCRYPT
            app._show_step(STEP_SETTINGS)
            await settle(app, pilot)
            assert not app.query("#pq-check"), (
                "Settings offers a hybrid PQ control again, but the wizard "
                "still has no way to supply an ML-KEM public key"
            )

    @pytest.mark.asyncio
    async def test_settings_signposts_the_cli_route(self):
        """Removing the control must not silently remove the feature's trail.

        The README presents hybrid PQ as the headline feature, so a user will
        come to the wizard looking for it and needs to be told where it lives.
        """
        app = MorpheusWizard()
        async with app.run_test(size=(120, 50)) as pilot:
            app._state.mode = Mode.ENCRYPT
            app._show_step(STEP_SETTINGS)
            await settle(app, pilot)
            rendered = " ".join(
                str(w.render()) for w in app.query(Static)
            )
            assert "--generate-keypair" in rendered, (
                "Settings no longer tells the user where hybrid PQ lives"
            )


# ── Password step: dice entropy is CLI-only ──────────────────────

class TestPasswordSignpostsDiceEntropy:
    """The password step must name --dice-entropy without offering a screen.

    Physical dice are the one entropy source that survives a compromised
    generator, and the password step is the only moment in the wizard where
    the user is choosing entropy. Leaving the trail off it means the feature
    is reachable only by reading --help, which almost nobody does.

    A dice *screen* is deliberately not the answer. --dice-entropy takes a
    count and never the rolls, because a sequence typed into a networked
    computer is spent (see cli._run_dice_entropy). A wizard field would invite
    exactly that keystroke, so the step signposts the CLI instead — the same
    shape as the hybrid-PQ signpost above.
    """

    @pytest.mark.asyncio
    async def test_encrypt_names_the_dice_flag(self):
        app = MorpheusWizard()
        async with app.run_test(size=(120, 50)) as pilot:
            app._state.mode = Mode.ENCRYPT
            app._show_step(STEP_PASSWORD)
            await settle(app, pilot)
            rendered = " ".join(
                str(w.render()) for w in app.query(Static)
            )
            assert "--dice-entropy" in rendered, (
                "The password step no longer tells the user that dice "
                "entropy can be checked from the CLI"
            )

    @pytest.mark.asyncio
    async def test_decrypt_omits_the_dice_flag(self):
        """Decrypt takes an existing password, so the advice does not apply.

        Rolling dice cannot help someone re-enter a password they already
        have, and the decrypt step is where a user is most likely to be
        stuck. Advice that cannot act on their problem is noise there.
        """
        app = MorpheusWizard()
        async with app.run_test(size=(120, 50)) as pilot:
            app._state.mode = Mode.DECRYPT
            app._show_step(STEP_PASSWORD)
            await settle(app, pilot)
            rendered = " ".join(
                str(w.render()) for w in app.query(Static)
            )
            assert "--dice-entropy" not in rendered, (
                "Dice advice is showing on the decrypt path, where the "
                "password already exists"
            )

    @pytest.mark.asyncio
    async def test_wizard_never_accepts_the_rolls_themselves(self):
        """A count is safe to type here; the sequence is key material.

        This is the assertion that matters if someone later decides the
        signpost should become a field. --dice-entropy is a calculator, and
        the moment the wizard grows an input for the rolls, the tool is
        asking for the seed it exists to keep off the machine.
        """
        app = MorpheusWizard()
        async with app.run_test(size=(120, 50)) as pilot:
            app._state.mode = Mode.ENCRYPT
            app._show_step(STEP_PASSWORD)
            await settle(app, pilot)
            assert not app.query("#dice-input"), (
                "The wizard grew a dice input; --dice-entropy takes a count, "
                "never the rolls"
            )


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
            app._state.record_output(self.CIPHERTEXT)
            app._state.completed_steps.add(STEP_OUTPUT)
            for _ in range(self.VISITS):
                app._goto_step(STEP_OUTPUT)
                await settle(app, pilot)
                assert app._current_step == STEP_OUTPUT, (
                    "the jump to step 6 was refused, so this would measure "
                    f"step {app._current_step + 1} instead"
                )
                area = app.query_one("#output-area", TextArea)
                seen.append((area.wrap_width, area.wrapped_document.height))
                # Leave, so the next arrival replaces a mounted step rather
                # than being a no-op.
                app._goto_step(STEP_MODE)
                await settle(app, pilot)
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
        app._state.record_output("MORPHEUS-v1:c2FtcGxlIGNpcGhlcnRleHQ=")
        app._state.completed_steps.add(STEP_OUTPUT)
        app._goto_step(step)
        await settle(app, pilot)
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

    # Every step, and the control that must take the keyboard on arrival. All
    # six, not a sample: the earlier version covered two, and the one step it
    # happened to miss was the one that was wrong. Between them these exercise
    # five widget types and both branches of the fix — RadioSet, Select,
    # RadioSet, Input, a nav-bar Button, TextArea.
    FIRST_CONTROLS = [
        (STEP_MODE, "mode-radio"),
        (STEP_SETTINGS, "cipher-select"),
        (STEP_INPUT, "input-tabs"),
        (STEP_PASSWORD, "pwd-input"),
        # Review composes only Static text, so its keyboard target is the
        # action it exists to reach. See the fallback test below.
        (STEP_REVIEW, "btn-run"),
        (STEP_OUTPUT, "output-area"),
    ]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("step,control", FIRST_CONTROLS)
    async def test_focus_lands_on_the_step_and_not_the_sidebar(self, step, control):
        async with _wizard_on_step(step) as (app, _):
            panel = app.query_one("#step-container").children[0]
            focused = app.focused
            assert focused is not None, "nothing is focused"

            ancestors = focused.ancestors
            assert app.query_one("#sidebar") not in ancestors, (
                f"step {step + 1} left focus on the sidebar "
                f"({focused.id}); the keyboard drives the step list, not the step"
            )
            assert panel in ancestors or app.query_one("#nav-bar") in ancestors, (
                f"focus is on {focused.__class__.__name__}#{focused.id}, which "
                f"is neither in step {step + 1} nor one of its actions"
            )
            assert focused.id == control

    @pytest.mark.asyncio
    async def test_a_step_with_no_content_falls_back_to_its_primary_action(self):
        """Review's whole purpose is Execute, and Execute is not in the panel.

        Its nav-bar target cannot be found by DOM order. The bar is laid out
        Back, Next, Execute, so "first visible button" picks Back — which is
        how the keyboard ended up somewhere useless here in the first place.
        """
        async with _wizard_on_step(STEP_REVIEW) as (app, _):
            panel = app.query_one("#step-container").children[0]
            assert not [w for w in panel.query("*") if w.focusable], (
                "Review has gained a focusable control, so this no longer "
                "covers the empty case it was written for"
            )
            run = app.query_one("#btn-run", Button)
            assert run.display and not run.disabled, "Execute is not offered"
            assert app.focused is run, (
                f"expected Execute to take the keyboard, got {app.focused}"
            )

    @pytest.mark.asyncio
    async def test_a_step_with_no_action_either_leaves_the_sidebar_focused(self):
        """The last resort still has to be reached, and still must not raise."""
        async with _wizard_on_step(STEP_REVIEW) as (app, pilot):
            for button in app.query_one("#nav-bar").query(Button):
                button.display = False
            app._focus_step_content(app._step_panel)
            await pilot.pause()
            assert app.focused is not None and app.focused.id == f"sb-{STEP_REVIEW}", (
                f"expected the sidebar row for the current step, got {app.focused}"
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
            await settle_on_sidebar(app, pilot)
            assert app.focused.id == f"sb-{STEP_PASSWORD}", (
                f"escape left focus on {app.focused}; the sidebar cannot be "
                "reached from the step"
            )

    @pytest.mark.asyncio
    async def test_the_sidebar_still_selects_a_step_with_enter(self):
        """Reachable is not enough; it has to still work once you are there."""
        async with _wizard_on_step(STEP_PASSWORD) as (app, pilot):
            await pilot.press("escape")
            await settle_on_sidebar(app, pilot)
            await pilot.press("tab")       # sb-3 -> sb-4 (Review)
            # Naming the target, because both settle helpers are already
            # satisfied before Tab moves and would return on sb-3.
            await settle_on(app, pilot, f"sb-{STEP_REVIEW}")
            assert app.focused.id == f"sb-{STEP_REVIEW}", (
                f"tab did not move along the sidebar, it left {app.focused}"
            )
            await pilot.press("enter")
            await settle(app, pilot)
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
            await settle(app, pilot)
            assert app._state.mode == Mode.ENCRYPT, (
                "ctrl+e reached the focused field instead of the app"
            )

            await pilot.press("ctrl+d")
            await settle(app, pilot)
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
            await settle(app, pilot)
            app._goto_step(STEP_MODE)
            await settle(app, pilot)
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
        with patch("morpheus_crypt.ui.clipboard._pyperclip") as mock_pp:
            mock_pp.paste.return_value = "from-pyperclip"
            assert clipboard_paste() == "from-pyperclip"

    def test_subprocess_fallback_on_pyperclip_failure(self):
        with patch("morpheus_crypt.ui.clipboard._pyperclip", None), \
             patch("morpheus_crypt.ui.clipboard.subprocess.run") as mock_run:
            mock_run.return_value = type("R", (), {"returncode": 0, "stdout": "from-xclip"})()
            result = clipboard_paste()
            assert result == "from-xclip"

    def test_returns_none_when_all_fail(self):
        with patch("morpheus_crypt.ui.clipboard._pyperclip", None), \
             patch("morpheus_crypt.ui.clipboard.subprocess.run") as mock_run:
            mock_run.side_effect = FileNotFoundError
            assert clipboard_paste() is None

    def test_tkinter_fallback(self):
        # Patch the module object, not tk.Tk: tkinter is optional, so on a
        # Python built without Tk `clipboard.tk` is None and has no attributes.
        with patch("morpheus_crypt.ui.clipboard._pyperclip", None), \
             patch("morpheus_crypt.ui.clipboard.subprocess.run", side_effect=FileNotFoundError), \
             patch("morpheus_crypt.ui.clipboard.tk") as mock_tk:
            tk_root = mock_tk.Tk.return_value
            tk_root.clipboard_get.return_value = "from-tkinter"
            assert clipboard_paste() == "from-tkinter"

    def test_returns_none_when_tkinter_unavailable(self):
        """Python without Tk must degrade gracefully, not raise."""
        with patch("morpheus_crypt.ui.clipboard._pyperclip", None), \
             patch("morpheus_crypt.ui.clipboard.subprocess.run", side_effect=FileNotFoundError), \
             patch("morpheus_crypt.ui.clipboard.tk", None):
            assert clipboard_paste() is None


class TestClipboardCopy:
    """Test the clipboard copy fallback chain."""

    def test_pyperclip_copy(self):
        with patch("morpheus_crypt.ui.clipboard._pyperclip") as mock_pp:
            ok, method = clipboard_copy("test")
            mock_pp.copy.assert_called_once_with("test")
            assert ok is True
            assert method == "pyperclip"

    def test_returns_false_when_all_fail(self):
        """All three backends must be disabled, not just the first two.

        This patched _pyperclip and Popen but left `tk` live, so the assertion
        only held where tkinter happened to be unavailable. It passed on
        Homebrew Python (built without Tk) and on the Linux CI leg, and failed
        on the macOS runner, where setup-python ships Python with Tk and the
        fallback genuinely succeeded — the function was right and the test was
        wrong. The paste-side equivalent already patched all three.
        """
        with patch("morpheus_crypt.ui.clipboard._pyperclip", None), \
             patch("morpheus_crypt.ui.clipboard.subprocess.Popen") as mock_popen, \
             patch("morpheus_crypt.ui.clipboard.tk", None):
            mock_popen.side_effect = FileNotFoundError
            ok, method = clipboard_copy("test")
            assert ok is False
            assert method == ""

    def test_tkinter_fallback(self):
        # Patch the module object, not tk.Tk: see the note in TestClipboardPaste.
        with patch("morpheus_crypt.ui.clipboard._pyperclip", None), \
             patch("morpheus_crypt.ui.clipboard.subprocess.Popen", side_effect=FileNotFoundError), \
             patch("morpheus_crypt.ui.clipboard.tk") as mock_tk:
            ok, method = clipboard_copy("test")
            assert ok is True
            assert method == "tkinter"
            tk_root = mock_tk.Tk.return_value
            tk_root.clipboard_append.assert_called_once_with("test")

    def test_returns_false_when_tkinter_unavailable(self):
        """Python without Tk must degrade gracefully, not raise."""
        with patch("morpheus_crypt.ui.clipboard._pyperclip", None), \
             patch("morpheus_crypt.ui.clipboard.subprocess.Popen", side_effect=FileNotFoundError), \
             patch("morpheus_crypt.ui.clipboard.tk", None):
            ok, method = clipboard_copy("test")
            assert ok is False
            assert method == ""


class TestExecuteWorkerIsExclusive:
    """Pressing Execute twice must not start a second KDF run.

    Without `exclusive`, N presses spawned N concurrent Argon2id workers.
    Two completions landing in one event-loop turn then killed the app with
    `NoMatches: No nodes match '#output-area'`, losing the ciphertext that had
    just been produced. There is no busy indicator, which is exactly why a
    user presses again.
    """

    @pytest.mark.parametrize("method_name", ["_do_encrypt", "_do_decrypt"])
    def test_worker_is_threaded_and_exclusive(self, method_name):
        import inspect

        func = getattr(MorpheusWizard, method_name)
        closure = inspect.getclosurevars(func).nonlocals
        # Guard against the decorator's internals changing shape underneath
        # this test and leaving it asserting nothing.
        assert "exclusive" in closure and "thread" in closure
        assert closure["thread"] is True
        assert closure["exclusive"] is True, (
            f"{method_name} must be exclusive so a second Execute press "
            "cancels rather than races the first"
        )

    async def test_execute_button_disables_while_running(self):
        """The button must go dead for the duration of the run."""
        app = MorpheusWizard()
        # Explicit size: `run_test()` defaults to 80x24, which is below the
        # declared minimum, and the size gate disables this button on purpose.
        # This test is about the worker, so it needs a terminal the wizard runs
        # in rather than one the gate covers.
        async with app.run_test(size=(120, 50)) as pilot:
            app._set_execute_enabled(False)
            await pilot.pause()
            assert app.query_one("#btn-run", Button).disabled is True
            app._set_execute_enabled(True)
            await pilot.pause()
            assert app.query_one("#btn-run", Button).disabled is False


class TestMinimumTerminalSize:
    """The declared floor, enforced in both directions.

    Every other TUI test runs at 120x50 and the screenshots at 110x40, so until
    now nothing exercised a small terminal and 80x24 -- the standard default --
    rendered a wizard with step 6 missing from the sidebar and the labels
    truncated. Nothing was unreachable, which is why it survived: it reads as
    cramped rather than broken.
    """

    @pytest.mark.asyncio
    async def test_the_wizard_runs_at_exactly_the_declared_minimum(self):
        """The boundary is inclusive, so the declared figure is usable."""
        app = MorpheusWizard()
        async with app.run_test(size=(MIN_WIDTH, MIN_HEIGHT)) as pilot:
            await pilot.pause()
            assert app.query_one("#size-gate").display is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "size",
        [
            (80, 24),                     # the standard terminal default
            (MIN_WIDTH - 1, MIN_HEIGHT),  # one column short
            (MIN_WIDTH, MIN_HEIGHT - 1),  # one row short
        ],
    )
    async def test_the_gate_covers_the_wizard_below_the_minimum(self, size):
        app = MorpheusWizard()
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            assert app.query_one("#size-gate").display is True, (
                f"{size[0]}x{size[1]} is below {MIN_WIDTH}x{MIN_HEIGHT} "
                "and must not render a clipped wizard"
            )

    @pytest.mark.asyncio
    async def test_the_message_names_the_requirement_and_the_actual_size(self):
        """"Too small" without the numbers leaves the user guessing."""
        app = MorpheusWizard()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            rendered = str(app.query_one("#size-gate-detail", Static).render())
            assert f"{MIN_WIDTH}x{MIN_HEIGHT}" in rendered
            assert "80x24" in rendered

    @pytest.mark.asyncio
    async def test_the_nav_buttons_are_dead_while_the_gate_is_up(self):
        """The wizard underneath still holds the keyboard.

        Execute is the control that matters: its outcome lands in a pane the
        user cannot see while the gate covers it.
        """
        app = MorpheusWizard()
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            for selector in ("#btn-back", "#btn-next", "#btn-run"):
                assert app.query_one(selector, Button).disabled is True, (
                    f"{selector} is live behind the size gate"
                )

    @pytest.mark.asyncio
    async def test_resizing_below_the_minimum_and_back_keeps_a_finished_result(self):
        """Resizing is not a user edit, so it must not discard a result.

        This is the derived-staleness property from the S5 fix, restated for a
        new trigger. An earlier design pushed a Screen instead of overlaying a
        layer; that unmounted the step panel, and the ciphertext went with it.
        """
        app = MorpheusWizard()
        async with app.run_test(size=(120, 50)) as pilot:
            app._state.record_output("CIPHERTEXT-THAT-MUST-SURVIVE")
            await pilot.pause()

            await pilot.resize_terminal(80, 24)
            await pilot.pause()
            assert app.query_one("#size-gate").display is True

            await pilot.resize_terminal(120, 50)
            await pilot.pause()
            assert app.query_one("#size-gate").display is False
            assert app._state.output == "CIPHERTEXT-THAT-MUST-SURVIVE", (
                "resizing the terminal destroyed a finished result"
            )


# ── Every control must be reachable at the declared minimum ──────

class TestControlsAreReachableAtTheMinimum:
    """A control you can focus is a control you must be able to see and click.

    Found by the 2026-07-31 UAT run. `f3afa81` declared 100x30 and gates
    anything smaller, which makes 100x30 a supported size and therefore a test
    case. At exactly that size the Settings step laid its Advanced options out
    at rows 35-49 with `#step-container.max_scroll_y == 0`, so Pad, Fixed
    64 KiB and Omit filename could not be scrolled to at all -- and the
    "Advanced options" header that expands them was off-screen too. At 110x38
    a click on Pad landed on `btn-back` and navigated the wizard backwards
    instead, because the nav bar composites over the overflowing panel.

    The container was never at fault: it already sets `overflow-y: auto`. The
    step panels are plain `Vertical` subclasses with no height rule, so they
    defaulted to `1fr` -- exactly the container's height. The container saw a
    child that fitted, reported nothing to scroll, and the child's own children
    laid out past its bottom edge.

    Tab still reached those controls, which is why this survived: the wizard
    was keyboard-navigable to widgets that were not on screen.
    """

    STEPS = [STEP_MODE, STEP_SETTINGS, STEP_INPUT, STEP_PASSWORD,
             STEP_REVIEW, STEP_OUTPUT]

    @staticmethod
    async def _prepared(app, pilot, step):
        """Land on `step` with every collapsible open and state fully populated."""
        s = app._state
        s.mode = Mode.ENCRYPT
        s.input_text = "alpha canary one"
        s.password = s.password_confirm = "T3st!Passw0rd#Str0ng"
        s.record_output("BASE64" * 40)
        for i in range(6):
            s.completed_steps.add(i)
        app._show_step(step)
        await settle(app, pilot)
        for collapsible in app._step_panel.query(Collapsible):
            collapsible.collapsed = False
        for _ in range(3):
            await pilot.pause()

    @pytest.mark.asyncio
    @pytest.mark.parametrize("step", STEPS)
    async def test_every_focusable_control_lies_within_the_scrollable_extent(
        self, step
    ):
        """Geometry, not scrolling.

        The first version of this scrolled to each control and then measured
        it. That raced on the Windows runner: `scroll_visible` lands a frame or
        more later, so a slow turn measured one control against a neighbour's
        scroll position and reported `cipher-select` at rows -15 to -12. The
        property being tested never needed a scroll to happen. A control is
        reachable exactly when it lies inside the container's virtual content,
        which is a static comparison and cannot race.

        Under the old `1fr` panels the virtual height equalled the viewport, so
        anything past the fold fell outside the extent and this fails -- which
        is the bug, stated as arithmetic.
        """
        app = MorpheusWizard()
        async with app.run_test(size=(MIN_WIDTH, MIN_HEIGHT)) as pilot:
            await self._prepared(app, pilot, step)

            container = app.query_one("#step-container")
            content_top = container.content_region.y
            scroll_y = container.scroll_offset.y
            extent = container.virtual_size.height
            unreachable = []

            for widget in list(app._step_panel.query("*")):
                if not widget.focusable or widget.region.height == 0:
                    continue
                # Position in the container's content space, which is what the
                # scrollbar traverses.
                top = widget.region.y - content_top + scroll_y
                if top < 0 or top + widget.region.height > extent:
                    unreachable.append(
                        f"{widget.id or type(widget).__name__} occupies "
                        f"{top}-{top + widget.region.height} of a {extent}-row "
                        f"scrollable extent"
                    )

            assert not unreachable, (
                f"step {step}: focusable controls outside the scrollable extent "
                f"at {MIN_WIDTH}x{MIN_HEIGHT}, so no amount of scrolling reaches "
                f"them: {unreachable}"
            )

    @pytest.mark.asyncio
    async def test_advanced_options_click_hits_the_checkbox_not_the_nav_bar(self):
        """The specific failure: a click on Pad used to press Back.

        Hit-testing rather than `region` alone, because the control was on
        screen by its own coordinates and still unclickable -- the nav bar was
        composited over it, so the click did not miss, it navigated.
        """
        app = MorpheusWizard()
        async with app.run_test(size=(MIN_WIDTH, MIN_HEIGHT)) as pilot:
            await self._prepared(app, pilot, STEP_SETTINGS)

            for box_id in ("pad-check", "fixed-check", "nofn-check"):
                box = app.query_one(f"#{box_id}", Checkbox)
                box.scroll_visible(animate=False)
                for _ in range(3):
                    await pilot.pause()
                region = box.region
                try:
                    hit, _ = app.screen.get_widget_at(
                        region.x + region.width // 2,
                        region.y + region.height // 2,
                    )
                except Exception:
                    hit = None
                assert hit is not None, (
                    f"#{box_id} sits at rows {region.y}-{region.bottom}, off a "
                    f"{MIN_HEIGHT}-row screen, and cannot be scrolled into view"
                )
                assert hit is box or box in hit.ancestors, (
                    f"a click on #{box_id} lands on "
                    f"{hit.id or type(hit).__name__!r}, not the checkbox"
                )

                before = box.value
                await pilot.click(f"#{box_id}")
                await pilot.pause()
                assert box.value != before, f"#{box_id} did not toggle when clicked"
                assert app._current_step == STEP_SETTINGS, (
                    f"clicking #{box_id} navigated away from Settings"
                )


# ── The input stats line holds the foot of the pane ──────────────

class TestInputStatsStaysAtTheFootOfThePane:
    """The character count belongs at the bottom, at every terminal size.

    It used to sit there by accident: `#input-actions` carried no height rule,
    so `1fr` absorbed every spare row and pushed the stats line down. That made
    its position track the terminal rather than the design -- row 43 at 120x50,
    row 31 at 110x38 -- and when the step panels became `height: auto` the
    fraction had nothing to divide, so the buttons collapsed and the stats line
    came up to sit directly under them.

    It is now docked, which states the intent instead of relying on leftover
    space, and the panel's `min-height: 100%` is what guarantees a pane-bottom
    to dock against when the content is shorter than the pane. Docking also
    survives scrolling: Textual reserves the row, so a long input scrolls
    behind the count rather than colliding with it.
    """

    SIZES = [(MIN_WIDTH, MIN_HEIGHT), (110, 38), (120, 50)]

    @staticmethod
    async def _on_input_step(app, pilot):
        state = app._state
        state.mode = Mode.ENCRYPT
        state.input_text = "alpha canary one"
        for i in range(6):
            state.completed_steps.add(i)
        app._show_step(STEP_INPUT)
        await settle(app, pilot)

    @pytest.mark.asyncio
    @pytest.mark.parametrize("size", SIZES)
    async def test_stats_line_sits_on_the_last_row_of_the_pane(self, size):
        app = MorpheusWizard()
        async with app.run_test(size=size) as pilot:
            await self._on_input_step(app, pilot)
            pane = app.query_one("#step-container").content_region
            stats = app.query_one("#input-stats").region
            assert stats.bottom == pane.bottom, (
                f"at {size[0]}x{size[1]} the input stats line ends at row "
                f"{stats.bottom}, not on the pane's last row {pane.bottom}"
            )

    @pytest.mark.asyncio
    @pytest.mark.parametrize("size", SIZES)
    async def test_the_action_buttons_are_not_clipped(self, size):
        """The other half of the same rule: a 1-row row cannot hold a button."""
        app = MorpheusWizard()
        async with app.run_test(size=size) as pilot:
            await self._on_input_step(app, pilot)
            row = app.query_one("#input-actions")
            for button in row.children:
                assert button.region.height == 3, (
                    f"{button.id} renders {button.region.height} rows; a "
                    f"bordered Button needs 3"
                )
                assert button.region.bottom <= row.region.bottom, (
                    f"{button.id} overflows #input-actions"
                )

    @pytest.mark.asyncio
    async def test_scrolling_does_not_collide_with_the_docked_line(self):
        """At the minimum the step scrolls, and the count must keep its row."""
        app = MorpheusWizard()
        async with app.run_test(size=(MIN_WIDTH, MIN_HEIGHT)) as pilot:
            await self._on_input_step(app, pilot)
            container = app.query_one("#step-container")
            assert container.max_scroll_y > 0, (
                "the Input step no longer overflows at the minimum, so this "
                "test is no longer exercising the scrolled case"
            )
            container.scroll_end(animate=False)
            for _ in range(4):
                await pilot.pause()

            stats = app.query_one("#input-stats")
            collisions = [
                widget.id or type(widget).__name__
                for widget in app._step_panel.children
                if widget is not stats
                and widget.region.height
                and widget.region.y < stats.region.bottom
                and widget.region.bottom > stats.region.y
            ]
            assert not collisions, (
                f"scrolled to the end, these overlap the docked stats line: "
                f"{collisions}"
            )
