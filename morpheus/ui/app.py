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

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Footer, Static

from ..core.ciphers import CIPHER_CHOICES
from ..core.kdf import KDF_CHOICES
from ..core.pipeline import EncryptionPipeline
from ..core.validation import validate_input_text
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
    WizardState,
)
from .steps.input import InputStep
from .steps.mode import ModeStep
from .steps.output import OutputStep
from .steps.password import PasswordStep
from .steps.review import ReviewStep
from .steps.settings import SettingsStep
from .theme import WIZARD_CSS


class MorpheusWizard(App):
    """2-pane wizard: sidebar (left) + active step panel (right).

    Navigate with keyboard:
      - Number keys 1-6 jump directly to unlocked steps
      - Left/Right arrows move between steps
      - Tab cycles through fields, Enter selects
      - Escape focuses the sidebar for arrow-key browsing
    """

    TITLE = "MORPHEUS v2.0"
    CSS = WIZARD_CSS

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+e", "quick_encrypt", "Encrypt"),
        Binding("ctrl+d", "quick_decrypt", "Decrypt"),
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

    # ── Compose ──────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        # Top bar
        with Horizontal(id="top-bar"):
            yield Static("[bold #00FF41]MORPHEUS[/] [#007018]v2.0[/]", id="top-title")
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

    def on_mount(self) -> None:
        self._show_step(self._current_step)

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

        # Rebuild right pane
        container = self.query_one("#step-container", Vertical)
        container.remove_children()

        panel = self._build_step(step)
        container.mount(panel)

        # Update sidebar indicators
        if self._sidebar:
            self._sidebar.refresh_indicators(step)

        # Update nav buttons
        self._update_nav()

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
            self.notify(f"Complete earlier steps first", severity="warning")
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
        if self._sidebar:
            self._sidebar.focus()

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

    def on_radio_set_changed(self, event) -> None:
        """Re-evaluate nav after any radio/checkbox change."""
        self._update_nav()

    def on_select_changed(self, event) -> None:
        self._update_nav()

    def on_checkbox_changed(self, event) -> None:
        self._update_nav()

    def on_input_changed(self, event) -> None:
        self._update_nav()

    def on_text_area_changed(self, event) -> None:
        self._update_nav()

    # ── Run encrypt / decrypt ────────────────────────────────────

    def _run_operation(self) -> None:
        ok, reason = self._state.validate_review()
        if not ok:
            self.notify(reason, severity="error")
            return
        self._state.completed_steps.add(STEP_REVIEW)
        if self._state.mode == Mode.ENCRYPT:
            self._do_encrypt()
        else:
            self._do_decrypt()

    @work(thread=True)
    def _do_encrypt(self) -> None:
        s = self._state
        try:
            pipeline = self._build_pipeline()

            if s.input_method == InputMethod.TEXT:
                text = s.input_text
                valid, err = validate_input_text(text)
                if not valid:
                    self.call_from_thread(self.notify, err, severity="error")
                    return
                result = pipeline.encrypt(
                    text, s.password, pad=s.pad, fixed_size=s.fixed_size,
                )
            else:
                result = self._encrypt_file(pipeline)

            s.output = result
            self.call_from_thread(self._goto_output)
        except Exception as exc:
            self.call_from_thread(self.notify, f"Encryption failed: {exc}", severity="error")

    @work(thread=True)
    def _do_decrypt(self) -> None:
        s = self._state
        try:
            pipeline = self._build_pipeline()

            if s.input_method == InputMethod.TEXT:
                result = pipeline.decrypt(s.input_text.strip(), s.password)
            else:
                result = self._decrypt_file(pipeline)

            s.output = result
            self.call_from_thread(self._goto_output)
        except Exception as exc:
            self.call_from_thread(
                self.notify,
                f"Decryption failed: {exc}",
                severity="error",
            )

    def _goto_output(self) -> None:
        self._state.completed_steps.add(STEP_OUTPUT)
        self._show_step(STEP_OUTPUT)

    def _build_pipeline(self) -> EncryptionPipeline:
        s = self._state
        cipher_cls = CIPHER_CHOICES[s.cipher]
        kdf_cls = KDF_CHOICES[s.kdf]
        return EncryptionPipeline(
            cipher=cipher_cls(),
            kdf=kdf_cls(),
            chain=s.chain,
            hybrid_pq=s.hybrid_pq,
        )

    def _encrypt_file(self, pipeline: EncryptionPipeline) -> str:
        """Read file, wrap in envelope, encrypt."""
        s = self._state
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

    def _decrypt_file(self, pipeline: EncryptionPipeline) -> str:
        """Read encrypted file, decrypt."""
        path = self._state.input_file
        if not os.path.isfile(path):
            raise FileNotFoundError(f"File not found: {path}")
        with open(path, "r") as f:
            data = f.read().strip()
        return pipeline.decrypt(data, self._state.password)


def run_gui() -> None:
    """Launch the MORPHEUS wizard TUI."""
    app = MorpheusWizard()
    app.run()
