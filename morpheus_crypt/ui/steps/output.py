"""Step 6 — Output display with auto-clear and copy."""

from __future__ import annotations

from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Static, TextArea

from .. import theme
from ..clipboard import clipboard_copy, save_to_file
from ..state import Mode, WizardState


class OutputArea(TextArea):
    """A TextArea that re-wraps the instant its width is known.

    Textual wraps a TextArea's document against `wrap_width`, which is derived
    from the widget's compositor region. A freshly mounted widget has no region,
    so anything written during `on_mount` is wrapped at width 0 — one long line
    that clips at the pane edge. Textual's own correction is `_on_resize`, and
    that is where the flicker came from: the `Resize` *message* is delivered
    asynchronously and is not guaranteed to be processed before the next paint,
    so the ciphertext rendered wrapped or clipped roughly 50/50 per run.

    `_size_updated` is the synchronous call inside layout where the width
    actually becomes known — it is what decides whether a `Resize` is worth
    posting at all. Re-wrapping there removes the race rather than betting on
    message ordering. Guarding on the last width wrapped at keeps this to one
    re-wrap per genuine width change.
    """

    _wrapped_at: int = -1

    def _size_updated(self, *args, **kwargs) -> bool:
        changed = super()._size_updated(*args, **kwargs)
        width = self.wrap_width
        if width and width != self._wrapped_at:
            self._wrapped_at = width
            self._rewrap_and_refresh_virtual_size()
        return changed


class OutputStep(Vertical):
    """Read-only output area with copy, clear, and countdown."""

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(**kw)
        self._state = state

    def compose(self):
        is_encrypt = self._state.mode == Mode.ENCRYPT

        yield Static("Output", classes="step-title")

        if is_encrypt:
            yield Static(
                "Encryption complete. The ciphertext below is a base64 string "
                "that contains your encrypted data, algorithm header, and "
                "authentication tag. Store it securely or share it with the recipient.",
                classes="step-subtitle",
            )
        else:
            yield Static(
                "Decryption complete. The recovered plaintext is shown below. "
                "Copy or save it before the auto-clear timer expires.",
                classes="step-subtitle",
            )

        yield Static(
            f"[{theme.TEXT_3}]Copy: use the Copy button, or select text with your mouse "
            "and Ctrl+Shift+C. Save: writes to a temporary file. "
            "Auto-clear wipes the output after 60 seconds for security.[/]",
            classes="step-hint",
        )

        yield Static("", id="output-status")
        yield OutputArea(id="output-area", read_only=True)
        with Horizontal(id="output-actions"):
            yield Button("Copy", id="btn-copy")
            yield Button("Save to file", id="btn-save")
            yield Button("Clear", id="btn-clear")
            yield Button("Stop timer", id="btn-stop-timer")
            yield Static("", id="countdown-label")

    def on_mount(self) -> None:
        if self._state.output:
            area = self.query_one("#output-area", TextArea)
            # `load_text` rebuilds the document and re-wraps all of it against
            # the current width. `clear()` + `insert()` does not: the insert
            # path re-wraps only the edited range, and it does so against the
            # width cached by the last full wrap, which at mount time is 0. So
            # the old pair wrote text that stayed wrapped at 0 even once the
            # real width was known.
            area.load_text(self._state.output)
            status = self.query_one("#output-status", Static)
            status.update(f"{len(self._state.output)} characters")
            # The countdown itself belongs to the app, so that leaving this
            # step does not take the expiry with it (F-09). Coming back here
            # just re-renders whatever it is currently showing.
            self.app._refresh_countdown()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-copy":
            self._copy_output()
        elif event.button.id == "btn-save":
            self._save_output()
        elif event.button.id == "btn-clear":
            self._clear_output()
        elif event.button.id == "btn-stop-timer":
            self.app._stop_auto_clear()
            self.app.notify("Auto-clear timer stopped", severity="information")

    # -- Clipboard --

    def _copy_output(self) -> None:
        text = self.query_one("#output-area", TextArea).text
        if not text.strip():
            self.app.notify("Nothing to copy", severity="warning")
            return

        # 1. Try verifiable clipboard backends first
        ok, method = clipboard_copy(text)
        if ok:
            self.app.notify(
                f"Copied to clipboard ({method})", severity="information",
            )
            return

        # 2. Fall back to Textual OSC-52 (unverifiable — works in modern terminals)
        try:
            self.app.copy_to_clipboard(text)
            self.app.notify(
                "Copied via terminal escape (may not work in all terminals)",
                severity="information",
            )
            return
        except Exception:
            pass

        # 3. Last resort — save to file
        path = save_to_file(text, prefix="morpheus_output")
        self.app.notify(
            f"Clipboard unavailable — saved to {path}",
            severity="warning",
        )

    def _save_output(self) -> None:
        text = self.query_one("#output-area", TextArea).text
        if not text.strip():
            self.app.notify("Nothing to save", severity="warning")
            return
        path = save_to_file(text, prefix="morpheus_output")
        self.app.notify(f"Saved to {path}", severity="information")

    def _clear_output(self) -> None:
        """Delegate, so Clear wipes the result rather than only this pane."""
        self.app._clear_output()
        self.query_one("#output-status", Static).update("")
