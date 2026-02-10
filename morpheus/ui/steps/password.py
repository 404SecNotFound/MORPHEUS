"""Step 4 — Password entry with strength meter."""

from __future__ import annotations

import subprocess

from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Button, Checkbox, Input, Label, Static

from ...core.validation import check_password_strength
from ..state import Mode, WizardState

try:
    import pyperclip as _pyperclip
except ImportError:
    _pyperclip = None  # type: ignore[assignment]


def _clipboard_paste() -> str | None:
    """Read clipboard using pyperclip or subprocess fallback."""
    if _pyperclip is not None:
        try:
            text = _pyperclip.paste()
            if text:
                return text
        except Exception:
            pass
    for cmd in (
        ["xclip", "-selection", "clipboard", "-o"],
        ["xsel", "--clipboard", "--output"],
        ["wl-paste", "--no-newline"],
    ):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
            if result.returncode == 0:
                return result.stdout
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue
    return None


class StrengthBar(Static):
    """5-step discrete password strength indicator."""

    score: reactive[int] = reactive(0)

    def render(self) -> str:
        filled = self.score // 10
        empty = 10 - filled
        if self.score >= 80:
            color, label = "#6BCB77", "Excellent"
        elif self.score >= 60:
            color, label = "#5B8CFF", "Strong"
        elif self.score >= 40:
            color, label = "#E2B93B", "Fair"
        elif self.score >= 20:
            color, label = "#E09050", "Weak"
        else:
            color, label = "#E05C5C", "Very weak"
        return f"[{color}]{'█' * filled}{'░' * empty}[/] {label}"


class PasswordStep(Vertical):
    """Password + confirm + strength meter + paste."""

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(**kw)
        self._state = state

    def compose(self):
        yield Static("Password", classes="step-title")
        yield Static(
            "Choose a strong password. There is no recovery — "
            "if you forget it, your data is permanently lost.",
            classes="step-subtitle",
        )

        with Horizontal(classes="field-row"):
            yield Label("Password:", classes="field-label")
            yield Input(
                placeholder="Enter password...",
                password=True,
                id="pwd-input",
                classes="password-field",
            )
            yield Button("Paste", id="paste-pwd", variant="default")

        with Horizontal(classes="field-row"):
            yield Label("", classes="field-label")  # spacer
            yield StrengthBar(id="strength-bar")
            yield Static("", id="match-indicator")

        yield Static("", id="pwd-feedback")

        # Confirm row (only for encrypt)
        with Horizontal(classes="field-row", id="confirm-row"):
            yield Label("Confirm:", classes="field-label")
            yield Input(
                placeholder="Confirm password...",
                password=True,
                id="pwd-confirm",
                classes="password-field",
            )
            yield Button("Paste", id="paste-confirm", variant="default")

        yield Checkbox("Show password", id="show-pwd-check", value=False)

    def on_mount(self) -> None:
        # Hide confirm row in decrypt mode
        is_encrypt = self._state.mode == Mode.ENCRYPT
        self.query_one("#confirm-row").display = is_encrypt
        # Restore any existing password
        if self._state.password:
            self.query_one("#pwd-input", Input).value = self._state.password
        if self._state.password_confirm:
            self.query_one("#pwd-confirm", Input).value = self._state.password_confirm

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
            self._paste_into("pwd-input")
        elif event.button.id == "paste-confirm":
            self._paste_into("pwd-confirm")

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "show-pwd-check":
            self.query_one("#pwd-input", Input).password = not event.value
            try:
                self.query_one("#pwd-confirm", Input).password = not event.value
            except Exception:
                pass

    def _paste_into(self, input_id: str) -> None:
        text = _clipboard_paste()
        if text:
            text = text.strip().replace("\n", "").replace("\r", "")
            self.query_one(f"#{input_id}", Input).value = text
            self.app.notify("Pasted from clipboard", severity="information")
        else:
            self.app.notify(
                "Clipboard empty or unavailable — try Ctrl+Shift+V",
                severity="warning",
            )

    def _update_strength(self) -> None:
        pwd = self._state.password
        bar = self.query_one("#strength-bar", StrengthBar)
        fb = self.query_one("#pwd-feedback", Static)
        if pwd:
            result = check_password_strength(pwd)
            bar.score = result.score
            if result.feedback:
                fb.update("[dim]" + " · ".join(result.feedback[:2]) + "[/dim]")
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
            indicator.update("[#6BCB77]Match[/#6BCB77]")
        elif confirm:
            indicator.update("[#E05C5C]No match[/#E05C5C]")
        else:
            indicator.update("")
