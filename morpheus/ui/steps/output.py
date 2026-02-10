"""Step 6 — Output display with auto-clear and copy."""

from __future__ import annotations

import subprocess

from textual.containers import Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import Button, Static, TextArea

from ..state import WizardState

try:
    import pyperclip as _pyperclip
except ImportError:
    _pyperclip = None  # type: ignore[assignment]

AUTO_CLEAR_SECONDS = 60


class OutputStep(Vertical):
    """Read-only output area with copy, clear, and countdown."""

    _countdown: reactive[int] = reactive(-1)
    _timer_handle = None

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(**kw)
        self._state = state

    def compose(self):
        yield Static("Output", classes="step-title")
        yield Static("", id="output-status")
        yield TextArea(id="output-area", read_only=True)
        with Horizontal(id="output-actions"):
            yield Button("Copy", id="btn-copy", variant="primary")
            yield Button("Clear", id="btn-clear", variant="error")
            yield Button("Stop timer", id="btn-stop-timer", variant="default")
            yield Static("", id="countdown-label")

    def on_mount(self) -> None:
        if self._state.output:
            area = self.query_one("#output-area", TextArea)
            area.clear()
            area.insert(self._state.output)
            status = self.query_one("#output-status", Static)
            status.update(f"{len(self._state.output)} characters")
            self._start_countdown()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-copy":
            self._copy_output()
        elif event.button.id == "btn-clear":
            self._clear_output()
        elif event.button.id == "btn-stop-timer":
            self._stop_countdown()
            self.app.notify("Auto-clear timer stopped", severity="information")

    # -- Clipboard --

    def _copy_output(self) -> None:
        text = self.query_one("#output-area", TextArea).text
        if not text.strip():
            self.app.notify("Nothing to copy", severity="warning")
            return
        # Try Textual OSC 52 first, then pyperclip, then subprocess
        try:
            self.app.copy_to_clipboard(text)
            self.app.notify("Copied to clipboard", severity="information")
            return
        except Exception:
            pass
        if _pyperclip is not None:
            try:
                _pyperclip.copy(text)
                self.app.notify("Copied to clipboard", severity="information")
                return
            except Exception:
                pass
        for cmd in (
            ["xclip", "-selection", "clipboard"],
            ["xsel", "--clipboard", "--input"],
            ["wl-copy"],
        ):
            try:
                proc = subprocess.Popen(
                    cmd, stdin=subprocess.PIPE,
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
                proc.communicate(text.encode("utf-8"), timeout=3)
                if proc.returncode == 0:
                    self.app.notify("Copied to clipboard", severity="information")
                    return
            except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
                continue
        self.app.notify(
            "Clipboard unavailable — select text and use Ctrl+Shift+C",
            severity="warning",
        )

    def _clear_output(self) -> None:
        self._stop_countdown()
        self.query_one("#output-area", TextArea).clear()
        self.query_one("#output-status", Static).update("")
        self.query_one("#countdown-label", Static).update("")
        self._state.output = ""

    # -- Countdown --

    def _start_countdown(self) -> None:
        self._stop_countdown()
        self._countdown = AUTO_CLEAR_SECONDS
        self._timer_handle = self.set_interval(1.0, self._tick)

    def _tick(self) -> None:
        if self._countdown > 0:
            self._countdown -= 1
            self.query_one("#countdown-label", Static).update(
                f"Auto-clear in {self._countdown}s"
            )
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
