"""Step 3 — Input (text editor or file path)."""

from __future__ import annotations

from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Input, Label, RadioButton, RadioSet, Static, TextArea

from ..clipboard import clipboard_copy, clipboard_paste
from ..state import InputMethod, Mode, WizardState


class InputStep(Vertical):
    """Text area or file path input."""

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(**kw)
        self._state = state

    def compose(self):
        is_encrypt = self._state.mode == Mode.ENCRYPT
        mode_label = "encrypt" if is_encrypt else "decrypt"

        yield Static("Input", classes="step-title")

        if is_encrypt:
            yield Static(
                "Enter or paste the plaintext you want to encrypt. "
                "You can type directly in the text area, or switch to "
                "File mode to encrypt a file from disk.",
                classes="step-subtitle",
            )
        else:
            yield Static(
                "Paste the ciphertext (base64 string) you want to decrypt, "
                "or switch to File mode to select an encrypted file.",
                classes="step-subtitle",
            )

        yield Static(
            "[dim]Use Up/Down to switch between Text and File. "
            "Tab to move into the editor. "
            "To paste: click the text area, then use Ctrl+Shift+V "
            "(terminal paste).[/dim]",
            classes="step-hint",
        )

        with RadioSet(id="input-tabs"):
            yield RadioButton(
                "Text — type or paste directly",
                value=self._state.input_method == InputMethod.TEXT,
                id="tab-text",
            )
            yield RadioButton(
                "File — encrypt/decrypt a file on disk",
                value=self._state.input_method == InputMethod.FILE,
                id="tab-file",
            )

        yield TextArea(id="input-editor")
        with Horizontal(id="input-actions"):
            yield Button("Paste", id="btn-paste-input")
            yield Button("Copy", id="btn-copy-input")
        yield Static("", id="input-stats")

        # File path row (shown/hidden based on tab)
        with Horizontal(classes="field-row", id="file-row"):
            yield Label("File:", classes="field-label")
            yield Input(
                placeholder="Enter the full path to the file...",
                id="file-path-input",
                value=self._state.input_file,
            )

        yield Static(
            "[dim]File path: use absolute path (e.g. /home/user/secret.txt). "
            "Tab into the field and type or paste the path.[/dim]",
            id="file-help",
            classes="field-help",
        )

    def on_mount(self) -> None:
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

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-paste-input":
            self._paste_input()
        elif event.button.id == "btn-copy-input":
            self._copy_input()

    def _paste_input(self) -> None:
        text = clipboard_paste()
        if text is None:
            self.notify("Could not read clipboard", severity="warning")
            return
        editor = self.query_one("#input-editor", TextArea)
        editor.clear()
        editor.insert(text)
        self._state.input_text = text
        self._update_stats()
        self.notify("Pasted from clipboard", severity="information")

    def _copy_input(self) -> None:
        text = self.query_one("#input-editor", TextArea).text
        if not text.strip():
            self.notify("Nothing to copy", severity="warning")
            return
        ok, method = clipboard_copy(text)
        if ok:
            self.notify(f"Copied to clipboard ({method})", severity="information")
        else:
            self.notify("Could not copy to clipboard", severity="warning")

    def _update_tab_visibility(self) -> None:
        is_text = self._state.input_method == InputMethod.TEXT
        self.query_one("#input-editor", TextArea).display = is_text
        self.query_one("#input-stats", Static).display = is_text
        self.query_one("#file-row").display = not is_text
        self.query_one("#file-help").display = not is_text

    def _update_stats(self) -> None:
        text = self._state.input_text
        lines = text.count("\n") + 1 if text else 0
        chars = len(text)
        self.query_one("#input-stats", Static).update(
            f"{lines} lines · {chars} chars"
        )
