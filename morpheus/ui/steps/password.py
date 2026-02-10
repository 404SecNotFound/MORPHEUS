"""Step 4 — Password entry with strength meter."""

from __future__ import annotations

from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Button, Checkbox, Input, Label, Static

from ...core.validation import check_password_strength
from ..clipboard import clipboard_copy, clipboard_paste
from ..state import Mode, WizardState


class StrengthBar(Static):
    """5-step discrete password strength indicator — Matrix palette."""

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
        return f"[{color}]{'█' * filled}{'░' * empty}[/] {label}"


class PasswordStep(Vertical):
    """Password + confirm + strength meter + copy/paste."""

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(**kw)
        self._state = state

    def compose(self):
        is_encrypt = self._state.mode == Mode.ENCRYPT

        yield Static("Password", classes="step-title")

        if is_encrypt:
            yield Static(
                "Choose a strong password to protect your data. "
                "There is no recovery mechanism — if you forget this "
                "password, your data is permanently lost.",
                classes="step-subtitle",
            )
            yield Static(
                "[dim]Tip: Use a long passphrase (4+ random words) for best security. "
                "The strength meter updates as you type. "
                "You must confirm the password below.[/dim]",
                classes="step-hint",
            )
        else:
            yield Static(
                "Enter the password that was used to encrypt the data. "
                "The password must match exactly — including case and special characters.",
                classes="step-subtitle",
            )
            yield Static(
                "[dim]Tip: To paste a password, Tab to the password field, "
                "then use Ctrl+Shift+V (terminal paste) or the Paste button.[/dim]",
                classes="step-hint",
            )

        with Horizontal(classes="field-row"):
            yield Label("Password:", classes="field-label")
            yield Input(
                placeholder="Enter password...",
                password=True,
                id="pwd-input",
                classes="password-field",
            )
            yield Button("Paste", id="paste-pwd", classes="pwd-action-btn")
            yield Button("Copy", id="copy-pwd", classes="pwd-action-btn")

        with Horizontal(classes="field-row"):
            yield Label("", classes="field-label")  # spacer
            yield StrengthBar(id="strength-bar")
            yield Static("", id="match-indicator")

        yield Static("", id="pwd-feedback")

        # Confirm row (only for encrypt)
        with Horizontal(classes="field-row", id="confirm-row"):
            yield Label("Confirm:", classes="field-label")
            yield Input(
                placeholder="Re-enter password to confirm...",
                password=True,
                id="pwd-confirm",
                classes="password-field",
            )
            yield Button("Paste", id="paste-confirm", classes="pwd-action-btn")

        yield Checkbox("Show password", id="show-pwd-check", value=False)

        yield Static(
            "[dim]Paste button reads from system clipboard (requires xclip/xsel). "
            "If clipboard is unavailable, use Ctrl+Shift+V to paste directly "
            "into the focused field.[/dim]",
            classes="step-hint",
        )

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
        elif event.button.id == "copy-pwd":
            self._copy_password()

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "show-pwd-check":
            self.query_one("#pwd-input", Input).password = not event.value
            try:
                self.query_one("#pwd-confirm", Input).password = not event.value
            except Exception:
                pass

    def _paste_into(self, input_id: str) -> None:
        text = clipboard_paste()
        if text:
            text = text.strip().replace("\n", "").replace("\r", "")
            self.query_one(f"#{input_id}", Input).value = text
            self.app.notify("Pasted from clipboard", severity="information")
        else:
            self.app.notify(
                "Clipboard unavailable — Tab to the password field, "
                "then press Ctrl+Shift+V to paste from your terminal",
                severity="warning",
            )

    def _copy_password(self) -> None:
        pwd = self._state.password
        if not pwd:
            self.app.notify("No password to copy", severity="warning")
            return
        ok, method = clipboard_copy(pwd)
        if ok:
            self.app.notify(f"Password copied ({method})", severity="information")
        else:
            # Fall back to Textual OSC-52 (unverifiable but often works)
            try:
                self.app.copy_to_clipboard(pwd)
                self.app.notify(
                    "Copied via terminal escape (may not work in all terminals)",
                    severity="information",
                )
            except Exception:
                self.app.notify(
                    "Clipboard unavailable — select text manually with "
                    "your terminal's copy shortcut (Ctrl+Shift+C)",
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
            indicator.update("[#00FF41]Match[/#00FF41]")
        elif confirm:
            indicator.update("[#FF3333]No match[/#FF3333]")
        else:
            indicator.update("")
