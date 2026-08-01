"""Main wizard application — 2-pane layout with sidebar + step panel.

Keyboard navigation:
  1-6      Jump to step (if unlocked)
  Left/Right  Previous / next step
  Tab      Cycle through fields in the current step
  Enter    Select / confirm focused element
  Escape   Focus the sidebar
  Ctrl+E   Quick-encrypt  Ctrl+D  Quick-decrypt
  Ctrl+L   Reset all      Ctrl+Q  Quit
  F1       Show keyboard help
"""

from __future__ import annotations

import base64
import json
import os

from textual import events, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.geometry import Size
from textual.widget import Widget
from textual.widgets import Button, Footer, Static

from .. import __version__
from ..core.ciphers import CIPHER_CHOICES
from ..core.kdf import KDF_CHOICES
from ..core.pipeline import EncryptionPipeline
from ..core.validation import validate_input_text
from . import theme
from .sidebar import Sidebar, SidebarItem
from .state import (
    STEP_INPUT,
    STEP_LABELS,
    STEP_MODE,
    STEP_OUTPUT,
    STEP_PASSWORD,
    STEP_REVIEW,
    STEP_SETTINGS,
    TOTAL_STEPS,
    InputMethod,
    Mode,
    OperationRequest,
    WizardState,
)
from .steps.input import InputStep
from .steps.mode import ModeStep
from .steps.output import OutputStep
from .steps.password import PasswordStep
from .steps.review import ReviewStep
from .steps.settings import SettingsStep

# The terminal the wizard is declared to fit, enforced by `_update_size_gate`
# and pinned by tests/test_gui.py::TestMinimumTerminalSize. Below this the
# sidebar drops step 6 and the step labels truncate.
#
# 100x30 rather than the 80x24 default: at 24 rows the six-step sidebar, the top
# bar, the nav bar and the footer leave four rows for the step itself, which is
# not enough for the Settings step's cipher and KDF controls. Declaring a floor
# and saying so is honest; silently reflowing key material into a cramped column
# is not.
MIN_WIDTH = 100
MIN_HEIGHT = 30


class MorpheusWizard(App):
    """2-pane wizard: sidebar (left) + active step panel (right).

    Navigate with keyboard:
      - Number keys 1-6 jump directly to unlocked steps
      - Left/Right arrows move between steps
      - Tab cycles through fields, Enter selects
      - Escape focuses the sidebar for arrow-key browsing
    """

    TITLE = f"MORPHEUS v{__version__}"
    CSS = theme.WIZARD_CSS

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
        # Textual's Input and TextArea both bind "end,ctrl+e" and
        # "delete,ctrl+d". A focused field therefore swallowed these two, and
        # the footer stopped advertising them on the Password and Output steps.
        # Harmless while focus never left the sidebar; a real regression once a
        # step takes the keyboard. Both are documented as global shortcuts, so
        # they outrank the focused widget. Cursor-to-end and delete-right are
        # still on End and Delete.
        Binding("ctrl+e", "quick_encrypt", "Encrypt", priority=True),
        Binding("ctrl+d", "quick_decrypt", "Decrypt", priority=True),
        Binding("ctrl+l", "clear_all", "Clear"),
        Binding("left", "prev_step", "Prev", show=False),
        Binding("right", "next_step", "Next", show=False),
        Binding("escape", "focus_sidebar", show=False),
        Binding("f1", "show_help", "Help"),
        # Number keys to jump directly to steps
        Binding("1", "goto_step_1", "1:Mode", show=False),
        Binding("2", "goto_step_2", "2:Settings", show=False),
        Binding("3", "goto_step_3", "3:Input", show=False),
        Binding("4", "goto_step_4", "4:Password", show=False),
        Binding("5", "goto_step_5", "5:Review", show=False),
        Binding("6", "goto_step_6", "6:Output", show=False),
    ]

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self._state = WizardState()
        self._current_step = STEP_MODE
        self._sidebar: Sidebar | None = None
        # The step panel currently on screen, so a deferred focus call can
        # tell whether it has been superseded.
        self._step_panel: Widget | None = None

    # ── Compose ──────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        # Top bar
        with Horizontal(id="top-bar"):
            yield Static(
                f"[bold {theme.TEXT}]MORPHEUS[/] [{theme.TEXT_3}]v{__version__}[/]",
                id="top-title",
            )
            yield Static(self._step_label(), id="top-step")

        # Body: sidebar + step panel
        self._sidebar = Sidebar(self._state)
        with Horizontal():
            yield self._sidebar
            yield Vertical(id="step-container")

        # Navigation buttons
        with Horizontal(id="nav-bar"):
            yield Button("Back", id="btn-back")
            yield Button("Next", id="btn-next")
            yield Button("Execute", id="btn-run")

        yield Footer()

        # Last, so it is above the wizard in document order as well as on its
        # own CSS layer. Starts hidden via `display: none` in the stylesheet;
        # `_update_size_gate` sets the inline style from then on.
        with Vertical(id="size-gate"):
            yield Static("Terminal too small", id="size-gate-title")
            yield Static("", id="size-gate-detail")

    def on_mount(self) -> None:
        self._show_step(self._current_step)
        self._update_size_gate()

    # ── Terminal size gate ───────────────────────────────────────

    def on_resize(self, event: events.Resize) -> None:
        """Textual fires this on mount and on every terminal resize.

        The event's size is passed rather than read back off `self.size`, which
        still reports the *previous* dimensions while this handler runs. Reading
        it here left the gate one resize behind: shrinking the window did
        nothing until you shrank it a second time.
        """
        self._update_size_gate(event.size)

    def _update_size_gate(self, size: Size | None = None) -> None:
        """Cover the wizard when the terminal is below the declared minimum.

        Deliberately does not touch step state, focus or the workers. Resizing
        is not a user edit, so it must not discard a finished result, and coming
        back up to a usable size must land the user exactly where they were.

        The nav buttons are disabled while the gate is up, because the wizard
        underneath still holds the keyboard and Execute is the one control whose
        blind activation the user cannot see the outcome of.
        """
        if size is None:
            size = self.size
        width, height = size.width, size.height
        too_small = width < MIN_WIDTH or height < MIN_HEIGHT

        try:
            gate = self.query_one("#size-gate", Vertical)
            detail = self.query_one("#size-gate-detail", Static)
        except Exception:
            # Called before compose finished; on_mount will call again.
            return

        if too_small:
            detail.update(
                f"MORPHEUS needs at least {MIN_WIDTH}x{MIN_HEIGHT}.\n"
                f"This terminal is {width}x{height}.\n\n"
                "Resize the window and the wizard returns as you left it."
            )
        gate.display = too_small

        for selector in ("#btn-back", "#btn-next", "#btn-run"):
            try:
                self.query_one(selector, Button).disabled = too_small
            except Exception:
                pass
        if not too_small:
            # Hand the buttons back to the ordinary rules rather than leaving
            # them all enabled, which would offer Next on an invalid step.
            self._update_nav()

    # ── Step management ──────────────────────────────────────────

    def _step_label(self) -> str:
        return f"Step {self._current_step + 1}/{TOTAL_STEPS}: {STEP_LABELS[self._current_step]}"

    def _show_step(self, step: int) -> None:
        """Replace the right pane with the given step's widget."""
        self._current_step = step

        # Update top bar
        try:
            self.query_one("#top-step", Static).update(self._step_label())
        except Exception:
            pass

        # Rebuild right pane.
        #
        # `remove_children` completes asynchronously. Mounting the new panel
        # without waiting for it lets two step changes in one event-loop turn
        # interleave, and a later `query_one("#output-area")` then raises
        # NoMatches and takes the app down with the result still unsaved.
        # `_mount_step` does the same work in order.
        container = self.query_one("#step-container", Vertical)
        panel = self._build_step(step)
        self._step_panel = panel
        self._mount_step(container, panel)

        # Update sidebar indicators
        if self._sidebar:
            self._sidebar.refresh_indicators(step)

        # Update nav buttons
        self._update_nav()

    @work(exclusive=True, group="step-mount")
    async def _mount_step(self, container: Vertical, panel: Widget) -> None:
        """Clear the pane, mount *panel*, then hand it the keyboard.

        Exclusive and grouped, so a rapid Left/Right burst cancels the pending
        mount instead of racing it. If this call has already been superseded
        by a newer step change, drop it rather than mount a stale panel.

        The focus handoff belongs here rather than in `_show_step`. A widget's
        composed children do not exist until the mount completes, and once
        mounting moved into this worker a `call_after_refresh` scheduled by
        `_show_step` could run first, find `panel.query("*")` empty, and fall
        through to the nav-bar fallback. Focus then landed on Back/Next
        instead of the step, non-deterministically, depending on which won the
        turn.
        """
        await container.remove_children()
        if panel is not self._step_panel:
            return
        await container.mount(panel)
        # Routed through the screen rather than `panel.call_next`, so a panel
        # removed before the callback runs cannot swallow it with its queue.
        self.call_after_refresh(self._focus_step_content, panel)

    def _focus_step_content(self, panel: Widget) -> None:
        """Move focus to the first focusable control of a step just shown.

        Without this, focus stays where Textual's auto-focus left it at
        startup — the first sidebar row — so Up/Down and Enter drive the step
        list rather than the step. That contradicts what the app tells the user
        to do ("Use Up/Down arrows to highlight, Enter to select" on the Mode
        step) and makes Escape pointless: the sidebar is meant to be somewhere
        you go on purpose, not where you always are.

        Scoped to `panel` rather than to `#step-container`, because
        `remove_children` completes asynchronously and the outgoing step's
        widgets can still be in the container when this runs — searching the
        container picks one of those and focus lands on the step just left.
        """
        # A quick Left/Right burst can leave an earlier call pending. Drop it
        # rather than focus a step that is no longer on screen.
        if panel is not self._step_panel:
            return

        for widget in panel.query("*"):
            if widget.focusable:
                self.set_focus(widget)
                return

        # Review composes only Static text; its one action, Execute, sits in
        # the nav bar outside the panel. Landing on the sidebar there would be
        # the very thing this method exists to stop, on the step whose whole
        # purpose is pressing a button.
        if self._focus_nav_action():
            return

        # Nothing focusable in the step or the nav bar. Leave the keyboard on
        # the sidebar rather than on a widget this step has just replaced.
        self.action_focus_sidebar()

    def _focus_nav_action(self) -> bool:
        """Focus the step's primary nav-bar action. True if one was found.

        Ordered by intent, not by DOM order. The bar is laid out Back, Next,
        Execute, so "first visible button" would hand Review the Back button —
        the opposite of what the step is for. A step with no content of its own
        wants whatever carries it forward, falling back to Back only when there
        is no forward action to take (an incomplete Review disables Execute,
        and going back is then the right move).

        `display` is tested separately because `Widget.focusable` does not
        consider it: `#btn-run` reports focusable on every step, including the
        five where `_update_nav` has hidden it. Only `disabled` is covered.
        Callers must therefore run this after `_update_nav`, never before.
        """
        for selector in ("#btn-run", "#btn-next", "#btn-back"):
            try:
                button = self.query_one(selector, Button)
            except Exception:
                continue
            if button.display and button.focusable:
                self.set_focus(button)
                return True
        return False

    def _build_step(self, step: int):
        if step == STEP_MODE:
            return ModeStep(self._state)
        if step == STEP_SETTINGS:
            return SettingsStep(self._state)
        if step == STEP_INPUT:
            return InputStep(self._state)
        if step == STEP_PASSWORD:
            return PasswordStep(self._state)
        if step == STEP_REVIEW:
            return ReviewStep(self._state)
        if step == STEP_OUTPUT:
            return OutputStep(self._state)
        return Static("Unknown step")

    def _update_nav(self) -> None:
        """Show/hide and enable/disable Back/Next/Run buttons."""
        btn_back = self.query_one("#btn-back", Button)
        btn_next = self.query_one("#btn-next", Button)
        btn_run = self.query_one("#btn-run", Button)

        btn_back.display = self._current_step > STEP_MODE
        btn_run.display = self._current_step == STEP_REVIEW
        btn_next.display = (
            self._current_step < STEP_REVIEW
            and self._current_step != STEP_OUTPUT
        )

        # Disable Next if current step is invalid
        ok, _ = self._state.is_step_valid(self._current_step)
        btn_next.disabled = not ok

        # Disable Run if review fails
        if self._current_step == STEP_REVIEW:
            ok, _ = self._state.validate_review()
            btn_run.disabled = not ok

    # ── Navigation actions ───────────────────────────────────────

    def action_prev_step(self) -> None:
        if self._current_step > STEP_MODE:
            self._show_step(self._current_step - 1)

    def action_next_step(self) -> None:
        ok, reason = self._state.is_step_valid(self._current_step)
        if not ok:
            self.notify(reason, severity="warning")
            return
        self._state.completed_steps.add(self._current_step)
        if self._current_step < STEP_OUTPUT:
            self._show_step(self._current_step + 1)

    def _goto_step(self, step: int) -> None:
        """Jump to a specific step if it is unlocked."""
        if step == self._current_step:
            return
        if step == STEP_OUTPUT and STEP_OUTPUT not in self._state.completed_steps:
            self.notify("Output is available after encryption/decryption", severity="warning")
            return
        if not self._state.is_step_unlocked(step):
            self.notify("Complete earlier steps first", severity="warning")
            return
        # Mark all steps before the target as completed
        for i in range(step):
            ok, _ = self._state.is_step_valid(i)
            if ok:
                self._state.completed_steps.add(i)
        self._show_step(step)

    def action_goto_step_1(self) -> None:
        self._goto_step(STEP_MODE)

    def action_goto_step_2(self) -> None:
        self._goto_step(STEP_SETTINGS)

    def action_goto_step_3(self) -> None:
        self._goto_step(STEP_INPUT)

    def action_goto_step_4(self) -> None:
        self._goto_step(STEP_PASSWORD)

    def action_goto_step_5(self) -> None:
        self._goto_step(STEP_REVIEW)

    def action_goto_step_6(self) -> None:
        self._goto_step(STEP_OUTPUT)

    def action_focus_sidebar(self) -> None:
        """Focus the sidebar row for the current step.

        This used to call `Sidebar.focus()`, which did nothing: `Sidebar` is a
        plain `Vertical` and containers are not focusable, so Escape never
        moved focus. It went unnoticed because focus never left the sidebar to
        begin with — Textual's auto-focus put it on `sb-0` at startup and
        nothing took it away. Now that a step claims focus, Escape is the way
        back, so it has to actually work. `SidebarItem` is the focusable unit,
        and the row for the current step is the one to land on.
        """
        if not self._sidebar:
            return
        try:
            item = self._sidebar.query_one(f"#sb-{self._current_step}", SidebarItem)
        except Exception:
            return
        self.set_focus(item)

    def action_quick_encrypt(self) -> None:
        self._state.mode = Mode.ENCRYPT
        self._state.completed_steps.add(STEP_MODE)
        if self._current_step == STEP_MODE:
            self._show_step(STEP_SETTINGS)
        else:
            self._update_nav()
        self.notify("Mode set to Encrypt", severity="information")

    def action_quick_decrypt(self) -> None:
        self._state.mode = Mode.DECRYPT
        self._state.completed_steps.add(STEP_MODE)
        if self._current_step == STEP_MODE:
            self._show_step(STEP_SETTINGS)
        else:
            self._update_nav()
        self.notify("Mode set to Decrypt", severity="information")

    def action_clear_all(self) -> None:
        self._state = WizardState()
        if self._sidebar:
            self._sidebar._state = self._state
        self._show_step(STEP_MODE)
        self.notify("All fields cleared", severity="information")

    def action_show_help(self) -> None:
        self.notify(
            "Keyboard shortcuts:\n"
            "  1-6  Jump to step     Tab   Next field\n"
            "  Left/Right  Prev/Next step\n"
            "  Enter  Select item    Esc   Focus sidebar\n"
            "  Ctrl+E  Encrypt mode  Ctrl+D  Decrypt mode\n"
            "  Ctrl+L  Clear all     Ctrl+Q  Quit",
            severity="information",
            timeout=10,
        )

    # ── Sidebar item selection ─────────────────────────────────────

    def on_sidebar_item_selected(self, event: SidebarItem.Selected) -> None:
        """Handle Enter key on a sidebar item."""
        self._goto_step(event.step)

    # ── Button events ────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-back":
            self.action_prev_step()
        elif event.button.id == "btn-next":
            self.action_next_step()
        elif event.button.id == "btn-run":
            self._run_operation()

    # ── Step change events (from child widgets) ──────────────────

    def _on_earlier_step_changed(self) -> None:
        """Discard a stale result, then re-evaluate nav.

        Any edit on a step before Output means the result on the Output step
        no longer describes the current inputs. Keeping it would let the user
        copy the previous run's ciphertext believing it matched what they can
        see on screen.
        """
        if self._current_step < STEP_OUTPUT:
            self._state.invalidate_output()
        self._update_nav()

    def on_radio_set_changed(self, event) -> None:
        """Re-evaluate nav after any radio/checkbox change."""
        self._on_earlier_step_changed()

    def on_select_changed(self, event) -> None:
        self._on_earlier_step_changed()

    def on_checkbox_changed(self, event) -> None:
        self._on_earlier_step_changed()

    def on_input_changed(self, event) -> None:
        self._on_earlier_step_changed()

    def on_text_area_changed(self, event) -> None:
        self._on_earlier_step_changed()

    # ── Run encrypt / decrypt ────────────────────────────────────

    def _set_execute_enabled(self, enabled: bool) -> None:
        """Enable or disable the Execute button.

        The KDF is deliberately slow, and there is no busy indicator, so a
        dead button is the only feedback that the run has started. Tolerates
        the button being absent: the nav bar is rebuilt on every step change.
        """
        try:
            self.query_one("#btn-run", Button).disabled = not enabled
        except Exception:
            pass

    def _run_operation(self) -> None:
        ok, reason = self._state.validate_review()
        if not ok:
            self.notify(reason, severity="error")
            return
        self._state.completed_steps.add(STEP_REVIEW)
        # Belt and braces with `exclusive=True` below: the flag cancels a
        # second worker, this stops the second press registering at all.
        self._set_execute_enabled(False)
        # Taken here, on the UI thread, before anything can edit it. The worker
        # never touches `self._state` again, so a run always describes the
        # inputs that were on screen when Execute was pressed.
        request = self._state.snapshot()
        if request.mode == Mode.ENCRYPT:
            self._do_encrypt(request)
        else:
            self._do_decrypt(request)

    @work(thread=True, exclusive=True)
    def _do_encrypt(self, request: OperationRequest) -> None:
        try:
            pipeline = self._build_pipeline(request)

            if request.input_method == InputMethod.TEXT:
                valid, err = validate_input_text(request.input_text)
                if not valid:
                    self.call_from_thread(self.notify, err, severity="error")
                    return
                result = pipeline.encrypt(
                    request.input_text, request.password,
                    pad=request.pad, fixed_size=request.fixed_size,
                )
            else:
                result = self._encrypt_file(pipeline, request)

            self.call_from_thread(self._publish_result, result, request)
        except Exception as exc:
            self.call_from_thread(self.notify, f"Encryption failed: {exc}", severity="error")
        finally:
            self.call_from_thread(self._set_execute_enabled, True)

    @work(thread=True, exclusive=True)
    def _do_decrypt(self, request: OperationRequest) -> None:
        try:
            pipeline = self._build_pipeline(request)

            if request.input_method == InputMethod.TEXT:
                result = pipeline.decrypt(request.input_text.strip(), request.password)
            else:
                result = self._decrypt_file(pipeline, request)

            self.call_from_thread(self._publish_result, result, request)
        except Exception as exc:
            self.call_from_thread(
                self.notify,
                f"Decryption failed: {exc}",
                severity="error",
            )
        finally:
            self.call_from_thread(self._set_execute_enabled, True)

    def _publish_result(self, result: str, request: OperationRequest) -> None:
        """Show a finished result, but only if it still describes the inputs.

        Runs on the UI thread. If anything changed while the worker was busy,
        the result is for inputs the user can no longer see, so showing it
        would present a ciphertext under a superseded password as current.
        Discarding is the only safe option, and it has to say so: silently
        dropping a result the user waited for reads as the app hanging.
        """
        if self._state.input_fingerprint() != request.fingerprint:
            self.notify(
                "Inputs changed while this was running, so the result was "
                "discarded rather than shown against settings that did not "
                "produce it. Press Execute again.",
                severity="warning",
                timeout=10,
            )
            return
        self._state.record_output(result, request.fingerprint)
        self._goto_output()

    def _goto_output(self) -> None:
        self._state.completed_steps.add(STEP_OUTPUT)
        self._show_step(STEP_OUTPUT)

    def _build_pipeline(self, request: OperationRequest) -> EncryptionPipeline:
        s = request
        cipher_cls = CIPHER_CHOICES[s.cipher]
        kdf_cls = KDF_CHOICES[s.kdf]
        return EncryptionPipeline(
            cipher=cipher_cls(),
            kdf=kdf_cls(),
            chain=s.chain,
            hybrid_pq=s.hybrid_pq,
        )

    def _encrypt_file(self, pipeline: EncryptionPipeline,
                      request: OperationRequest) -> str:
        """Read file, wrap in envelope, encrypt."""
        s = request
        path = s.input_file
        if not os.path.isfile(path):
            raise FileNotFoundError(f"File not found: {path}")
        with open(path, "rb") as f:
            raw = f.read()
        envelope = {
            "envelope_version": 1,
            "data": base64.b64encode(raw).decode(),
        }
        if not s.no_filename:
            envelope["filename"] = os.path.basename(path)
        return pipeline.encrypt(
            json.dumps(envelope), s.password,
            pad=s.pad, fixed_size=s.fixed_size,
        )

    def _decrypt_file(self, pipeline: EncryptionPipeline,
                      request: OperationRequest) -> str:
        """Read encrypted file, decrypt."""
        path = request.input_file
        if not os.path.isfile(path):
            raise FileNotFoundError(f"File not found: {path}")
        # Same codec choice as the CLI decrypt path: utf-8-sig so a ciphertext
        # carrying a Windows editor's BOM is not reported as invalid base64.
        with open(path, "r", encoding="utf-8-sig") as f:
            data = f.read().strip()
        return pipeline.decrypt(data, request.password)


def run_gui() -> None:
    """Launch the MORPHEUS wizard TUI."""
    app = MorpheusWizard()
    app.run()
