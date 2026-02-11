"""Dashboard panel widgets for MORPHEUS — Sampler-inspired layout.

Each panel is a self-contained bordered widget that manages its own
slice of WizardState and UI elements.
"""

from __future__ import annotations

from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import (
    Button,
    Checkbox,
    Input,
    Label,
    RadioButton,
    RadioSet,
    Select,
    Static,
    TextArea,
)

from ..core.ciphers import CIPHER_CHOICES
from ..core.kdf import KDF_CHOICES
from ..core.pipeline import PQ_AVAILABLE
from ..core.validation import check_password_strength
from .clipboard import clipboard_copy, clipboard_paste, save_to_file
from .state import InputMethod, Mode, WizardState

AUTO_CLEAR_SECONDS = 60


# ── Strength bar (shared) ──────────────────────────────────────────


class StrengthBar(Static):
    """Color-coded password strength indicator."""

    score: reactive[int] = reactive(0)

    def render(self) -> str:
        filled = self.score // 10
        empty = 10 - filled
        if self.score >= 80:
            color, label = "#00FF41", "Excellent"
        elif self.score >= 60:
            color, label = "#00CC33", "Strong"
        elif self.score >= 40:
            color, label = "#FFD700", "Fair"
        elif self.score >= 20:
            color, label = "#FF8800", "Weak"
        else:
            color, label = "#FF3333", "Very weak"
        bar = f"[{color}]{'█' * filled}{'░' * empty}[/]"
        return f"{bar} [{color}]{label}[/] [#555]{self.score}/100[/]"


# ── Mode panel ─────────────────────────────────────────────────────


class ModePanel(Vertical):
    """Encrypt / Decrypt mode selector."""

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(**kw)
        self._state = state

    def compose(self):
        yield Static(
            "[#007018]Select operation[/]",
            classes="panel-hint",
        )
        with RadioSet(id="mode-radio"):
            yield RadioButton(
                "ENCRYPT",
                id="radio-encrypt",
                value=self._state.mode == Mode.ENCRYPT,
            )
            yield RadioButton(
                "DECRYPT",
                id="radio-decrypt",
                value=self._state.mode == Mode.DECRYPT,
            )

    def on_mount(self) -> None:
        self.border_title = "[bold]MODE[/]"

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        if event.radio_set.id == "mode-radio":
            self._state.mode = Mode(event.index)


# ── Settings panel ─────────────────────────────────────────────────


class SettingsPanel(Vertical):
    """Cipher, KDF selection and encryption options."""

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(**kw)
        self._state = state

    def compose(self):
        with Horizontal(classes="setting-row"):
            yield Label("Cipher", classes="setting-label")
            yield Select(
                [(n, n) for n in CIPHER_CHOICES],
                value=self._state.cipher,
                id="cipher-select",
            )
        with Horizontal(classes="setting-row"):
            yield Label("KDF", classes="setting-label")
            yield Select(
                [(n, n) for n in KDF_CHOICES],
                value=self._state.kdf,
                id="kdf-select",
            )
        with Horizontal(classes="opts-row"):
            yield Checkbox("Chain", id="chain-check", value=self._state.chain)
            pq_label = "PQ" if PQ_AVAILABLE else "PQ [dim](n/a)[/]"
            yield Checkbox(
                pq_label,
                id="pq-check",
                value=self._state.hybrid_pq,
                disabled=not PQ_AVAILABLE,
            )
            yield Checkbox("Pad", id="pad-check", value=self._state.pad)

    def on_mount(self) -> None:
        self.border_title = "[bold]CIPHER & KDF[/]"

    def on_select_changed(self, event: Select.Changed) -> None:
        if event.select.id == "cipher-select":
            self._state.cipher = event.value
        elif event.select.id == "kdf-select":
            self._state.kdf = event.value

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        mapping = {
            "chain-check": "chain",
            "pq-check": "hybrid_pq",
            "pad-check": "pad",
        }
        attr = mapping.get(event.checkbox.id)
        if attr:
            setattr(self._state, attr, event.value)


# ── Status panel ───────────────────────────────────────────────────


class StatusPanel(Vertical):
    """Real-time readiness checklist with execute button."""

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(**kw)
        self._state = state

    def compose(self):
        yield Static("", id="status-mode")
        yield Static("", id="status-settings")
        yield Static("", id="status-input")
        yield Static("", id="status-password")
        yield Static("[#0D3B0D]─────────────────[/]", classes="status-divider")
        yield Button("▶ ENCRYPT", id="btn-run", variant="success")

    def on_mount(self) -> None:
        self.border_title = "[bold]STATUS[/]"
        self.refresh_status()

    def refresh_status(self) -> None:
        """Update all readiness indicators from current state."""
        s = self._state
        checks = [
            ("status-mode", "Mode", s.validate_mode),
            ("status-settings", "Settings", s.validate_settings),
            ("status-input", "Input", s.validate_input),
            ("status-password", "Password", s.validate_password),
        ]
        for widget_id, label, validator in checks:
            ok, _ = validator()
            if ok:
                icon = "[#00FF41]●[/]"
            else:
                icon = "[#444444]○[/]"
            try:
                self.query_one(f"#{widget_id}", Static).update(
                    f"  {icon} {label}"
                )
            except Exception:
                pass

        # Update execute button label and state
        try:
            btn = self.query_one("#btn-run", Button)
            review_ok, _ = s.validate_review()
            btn.disabled = not review_ok
            if s.mode == Mode.DECRYPT:
                btn.label = "▶ DECRYPT"
            else:
                btn.label = "▶ ENCRYPT"
        except Exception:
            pass


# ── Input panel ────────────────────────────────────────────────────


class InputPanel(Vertical):
    """Text editor or file-path input."""

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(**kw)
        self._state = state

    def compose(self):
        with Horizontal(id="input-header"):
            with RadioSet(id="input-tabs"):
                yield RadioButton(
                    "Text",
                    value=self._state.input_method == InputMethod.TEXT,
                    id="tab-text",
                )
                yield RadioButton(
                    "File",
                    value=self._state.input_method == InputMethod.FILE,
                    id="tab-file",
                )
            yield Static("", id="input-stats")
        yield TextArea(id="input-editor")
        with Horizontal(id="file-row"):
            yield Label("Path:", classes="setting-label")
            yield Input(
                placeholder="/path/to/file",
                id="file-path-input",
                value=self._state.input_file,
            )

    def on_mount(self) -> None:
        self.border_title = "[bold]INPUT[/]"
        editor = self.query_one("#input-editor", TextArea)
        if self._state.input_text:
            editor.insert(self._state.input_text)
        self._update_tab_visibility()
        self._update_stats()

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        if event.radio_set.id == "input-tabs":
            self._state.input_method = InputMethod(event.index)
            self._update_tab_visibility()

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        if event.text_area.id == "input-editor":
            self._state.input_text = event.text_area.text
            self._update_stats()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "file-path-input":
            self._state.input_file = event.value

    def _update_tab_visibility(self) -> None:
        is_text = self._state.input_method == InputMethod.TEXT
        self.query_one("#input-editor").display = is_text
        self.query_one("#input-stats").display = is_text
        self.query_one("#file-row").display = not is_text

    def _update_stats(self) -> None:
        text = self._state.input_text
        lines = text.count("\n") + 1 if text else 0
        chars = len(text)
        try:
            self.query_one("#input-stats", Static).update(
                f"[#007018]{lines}L  {chars}C[/]"
            )
        except Exception:
            pass


# ── Password panel ─────────────────────────────────────────────────


class PasswordPanel(Vertical):
    """Password entry, confirmation, and strength meter."""

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(**kw)
        self._state = state

    def compose(self):
        with Horizontal(classes="pwd-row"):
            yield Label("Key", classes="pwd-label")
            yield Input(
                placeholder="password",
                password=True,
                id="pwd-input",
                classes="pwd-field",
            )
            yield Button("Paste", id="paste-pwd", classes="pwd-btn")
        with Horizontal(classes="pwd-row", id="confirm-row"):
            yield Label("Cfm", classes="pwd-label")
            yield Input(
                placeholder="confirm",
                password=True,
                id="pwd-confirm",
                classes="pwd-field",
            )
            yield Static("", id="match-indicator")
        yield Checkbox("Show password", id="show-pwd-check", value=False)
        yield StrengthBar(id="strength-bar")
        yield Static("", id="pwd-feedback")

    def on_mount(self) -> None:
        self.border_title = "[bold]PASSWORD[/]"
        is_encrypt = self._state.mode == Mode.ENCRYPT
        self.query_one("#confirm-row").display = is_encrypt
        if self._state.password:
            self.query_one("#pwd-input", Input).value = self._state.password
        if self._state.password_confirm:
            self.query_one("#pwd-confirm", Input).value = self._state.password_confirm

    def refresh_for_mode(self) -> None:
        """Show/hide confirm row based on current mode."""
        try:
            is_encrypt = self._state.mode == Mode.ENCRYPT
            self.query_one("#confirm-row").display = is_encrypt
        except Exception:
            pass

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "pwd-input":
            self._state.password = event.value
            self._update_strength()
            self._update_match()
        elif event.input.id == "pwd-confirm":
            self._state.password_confirm = event.value
            self._update_match()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "paste-pwd":
            text = clipboard_paste()
            if text:
                text = text.strip().replace("\n", "").replace("\r", "")
                self.query_one("#pwd-input", Input).value = text
                self.app.notify("Pasted from clipboard")
            else:
                self.app.notify(
                    "Clipboard unavailable — use Ctrl+Shift+V",
                    severity="warning",
                )

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "show-pwd-check":
            show = event.value
            self.query_one("#pwd-input", Input).password = not show
            try:
                self.query_one("#pwd-confirm", Input).password = not show
            except Exception:
                pass

    def _update_strength(self) -> None:
        pwd = self._state.password
        bar = self.query_one("#strength-bar", StrengthBar)
        fb = self.query_one("#pwd-feedback", Static)
        if pwd:
            result = check_password_strength(pwd)
            bar.score = result.score
            if result.feedback:
                fb.update("[#007018]" + " · ".join(result.feedback[:2]) + "[/]")
            else:
                fb.update("")
        else:
            bar.score = 0
            fb.update("")

    def _update_match(self) -> None:
        if self._state.mode != Mode.ENCRYPT:
            return
        pwd = self._state.password
        confirm = self._state.password_confirm
        indicator = self.query_one("#match-indicator", Static)
        if confirm and pwd == confirm:
            indicator.update("[#00FF41]✓ Match[/]")
        elif confirm:
            indicator.update("[#FF3333]✗ Mismatch[/]")
        else:
            indicator.update("")


# ── Output panel ───────────────────────────────────────────────────


class OutputPanel(Vertical):
    """Result display with copy, save, clear, and auto-clear countdown."""

    _countdown: reactive[int] = reactive(-1)
    _timer_handle = None

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(**kw)
        self._state = state

    def compose(self):
        yield TextArea(id="output-area", read_only=True)
        with Horizontal(id="output-actions"):
            yield Button("Copy", id="btn-copy")
            yield Button("Save", id="btn-save")
            yield Button("Clear", id="btn-clear")
            yield Button("Stop timer", id="btn-stop-timer")
            yield Static("", id="countdown-label")

    def on_mount(self) -> None:
        self.border_title = "[bold]OUTPUT[/]"
        if self._state.output:
            self.show_output(self._state.output)

    def show_output(self, text: str) -> None:
        """Display result text and start auto-clear countdown."""
        area = self.query_one("#output-area", TextArea)
        area.clear()
        area.insert(text)
        self.border_subtitle = f"[#007018]{len(text)} chars[/]"
        self._start_countdown()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-copy":
            self._copy_output()
        elif event.button.id == "btn-save":
            self._save_output()
        elif event.button.id == "btn-clear":
            self._clear_output()
        elif event.button.id == "btn-stop-timer":
            self._stop_countdown()
            self.app.notify("Timer stopped")

    def _copy_output(self) -> None:
        text = self.query_one("#output-area", TextArea).text
        if not text.strip():
            self.app.notify("Nothing to copy", severity="warning")
            return
        ok, method = clipboard_copy(text)
        if ok:
            self.app.notify(f"Copied ({method})")
            return
        try:
            self.app.copy_to_clipboard(text)
            self.app.notify("Copied via terminal escape")
            return
        except Exception:
            pass
        path = save_to_file(text, prefix="morpheus_output")
        self.app.notify(f"Clipboard unavailable — saved to {path}", severity="warning")

    def _save_output(self) -> None:
        text = self.query_one("#output-area", TextArea).text
        if not text.strip():
            self.app.notify("Nothing to save", severity="warning")
            return
        path = save_to_file(text, prefix="morpheus_output")
        self.app.notify(f"Saved to {path}")

    def _clear_output(self) -> None:
        self._stop_countdown()
        self.query_one("#output-area", TextArea).clear()
        self.border_subtitle = ""
        self._state.output = ""

    def _start_countdown(self) -> None:
        self._stop_countdown()
        self._countdown = AUTO_CLEAR_SECONDS
        self._timer_handle = self.set_interval(1.0, self._tick)

    def _tick(self) -> None:
        if self._countdown > 0:
            self._countdown -= 1
            try:
                self.query_one("#countdown-label", Static).update(
                    f"[#FFD700]⏱ {self._countdown}s[/]"
                )
            except Exception:
                pass
        else:
            self._clear_output()

    def _stop_countdown(self) -> None:
        if self._timer_handle:
            self._timer_handle.stop()
            self._timer_handle = None
        self._countdown = -1
        try:
            self.query_one("#countdown-label", Static).update("")
        except Exception:
            pass
