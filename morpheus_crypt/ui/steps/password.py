"""Step 4 — Password entry with strength meter."""

from __future__ import annotations

from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Button, Checkbox, Input, Label, Static

from ...core.validation import check_password_strength, strength_label
from .. import theme
from ..clipboard import clipboard_copy, clipboard_paste
from ..state import Mode, WizardState


class StrengthBar(Static):
    """5-step discrete password strength indicator.

    Severity is carried by the text label, not by hue: the ramp only spans
    TEXT, TEXT_2 and ERROR so the meter stays legible without competing with
    the reserved accent. That makes the label load-bearing, so it comes from
    validation.strength_label rather than a second copy of the ladder here.

    The label sits inside the markup, not after it. Outside, it fell through to
    Textual's default foreground and was the one word on the screen that came
    from no token at all.
    """

    score: reactive[int] = reactive(0)

    def render(self) -> str:
        filled = self.score // 10
        empty = 10 - filled
        label = strength_label(self.score)
        if self.score >= 60:
            color = theme.TEXT
        elif self.score >= 40:
            color = theme.TEXT_2
        else:
            color = theme.ERROR
        return f"[{color}]{'█' * filled}{'░' * empty} {label}[/]"


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
            # The dice route rides on this tip instead of taking a block of
            # its own. At the 100x30 minimum the step has no spare rows, and a
            # fourth hint pushed the clipboard paste instructions below the
            # fold — those are load-bearing when the clipboard is unavailable,
            # and this is optional advice. The two sentences dropped to make
            # room narrated the strength meter and the Confirm field, both of
            # which are on screen; README keeps them for readers who are not.
            #
            # It stays a signpost rather than a screen because --dice-entropy
            # takes a count and never the rolls: a field for the sequence
            # would ask the user to type their seed into a networked
            # general-purpose computer, the thing a dice procedure avoids.
            yield Static(
                f"[{theme.TEXT_3}]Tip: Use a long passphrase (4+ random words) for best "
                "security. Rolling physical dice? "
                f"[{theme.TEXT_2}]--dice-entropy N[/]"
                f"[{theme.TEXT_3}] on the CLI reports what N rolls carry. "
                "It takes the count only, never the rolls themselves.[/]",
                classes="step-hint",
            )
        else:
            yield Static(
                "Enter the password that was used to encrypt the data. "
                "The password must match exactly — including case and special characters.",
                classes="step-subtitle",
            )
            yield Static(
                f"[{theme.TEXT_3}]Tip: To paste a password, Tab to the password field, "
                "then use Ctrl+Shift+V (terminal paste) or the Paste button.[/]",
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
            f"[{theme.TEXT_3}]Paste button reads from system clipboard (requires xclip/xsel). "
            "If clipboard is unavailable, use Ctrl+Shift+V to paste directly "
            "into the focused field.[/]",
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
            self._set_revealed("#pwd-input", event.value)
            self._set_revealed("#pwd-confirm", event.value)

    def _set_revealed(self, input_id: str, revealed: bool) -> None:
        """Unmask a password field and mark it as showing secret material.

        The `-revealed` class is what paints the text SIGNAL. It is set here
        rather than in CSS because Textual has no selector for `password=False`,
        so the two have to be kept in step by hand.
        """
        try:
            field = self.query_one(input_id, Input)
        except Exception:
            return  # confirm row is absent in decrypt mode
        field.password = not revealed
        field.set_class(revealed, "-revealed")

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
                fb.update(f"[{theme.TEXT_3}]" + " · ".join(result.feedback[:2]) + "[/]")
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
            indicator.update(f"[{theme.TEXT}]Match[/]")
        elif confirm:
            indicator.update(f"[{theme.ERROR}]No match[/]")
        else:
            indicator.update("")
