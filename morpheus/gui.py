"""
Modern terminal UI built with Textual.

Provides a full-featured encryption interface with:
  - Cipher and KDF selection
  - Cipher chaining toggle
  - Hybrid post-quantum (ML-KEM-768) toggle
  - Multi-line text input for arbitrary data blocks
  - Password input with real-time strength meter
  - One-time output display with auto-clear countdown
  - Copy-to-clipboard support
"""

from __future__ import annotations

import pyperclip
from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical
from textual.reactive import reactive
from textual.widgets import (
    Button,
    Checkbox,
    Footer,
    Header,
    Input,
    Label,
    ProgressBar,
    RadioButton,
    RadioSet,
    Select,
    Static,
    TextArea,
)

from .core.ciphers import CIPHER_CHOICES
from .core.kdf import KDF_CHOICES
from .core.pipeline import PQ_AVAILABLE, EncryptionPipeline, pq_generate_keypair
from .core.validation import check_password_strength, validate_input_text

AUTO_CLEAR_SECONDS = 60


class StrengthBar(Static):
    """Visual password strength indicator."""

    score: reactive[int] = reactive(0)

    def render(self) -> str:
        filled = self.score // 10
        empty = 10 - filled
        if self.score >= 80:
            color = "green"
            label = "Excellent"
        elif self.score >= 60:
            color = "cyan"
            label = "Strong"
        elif self.score >= 40:
            color = "yellow"
            label = "Fair"
        else:
            color = "red"
            label = "Weak"
        bar = f"[{color}]{'█' * filled}{'░' * empty}[/] {label}"
        return bar


class SecureEncryptionApp(App):
    """Main application."""

    TITLE = "MORPHEUS v2.0"
    SUB_TITLE = "Quantum-Resistant Encryption Tool"

    CSS = """
    Screen {
        background: $surface;
    }

    #app-title {
        text-align: center;
        text-style: bold;
        color: $accent;
        padding: 1 0 0 0;
        width: 100%;
    }

    #app-subtitle {
        text-align: center;
        color: $text-muted;
        padding: 0 0 1 0;
        width: 100%;
    }

    #main-container {
        width: 100%;
        height: 100%;
        padding: 0 2;
        overflow-y: auto;
    }

    .section-box {
        border: round $primary-background-lighten-2;
        padding: 1 2;
        margin: 0 0 1 0;
    }

    .section-title {
        color: $accent;
        text-style: bold;
        padding: 0 0 1 0;
    }

    #config-section {
        height: auto;
    }

    #mode-radio {
        height: auto;
        layout: horizontal;
        padding: 0 0 1 0;
    }

    .config-row {
        height: 3;
        layout: horizontal;
        align: left middle;
    }

    .config-label {
        width: 12;
        color: $text;
        padding: 0 1 0 0;
    }

    .config-select {
        width: 30;
    }

    #options-row {
        height: auto;
        layout: horizontal;
        padding: 1 0 0 0;
    }

    #options-row Checkbox {
        margin: 0 4 0 0;
    }

    #input-section {
        height: auto;
        min-height: 8;
    }

    #input-text {
        height: 8;
        min-height: 5;
    }

    #password-section {
        height: auto;
    }

    .password-row {
        height: 3;
        layout: horizontal;
        align: left middle;
    }

    .password-label {
        width: 12;
        color: $text;
    }

    .password-input {
        width: 40;
    }

    #strength-row {
        height: 1;
        layout: horizontal;
        padding: 0 0 0 12;
    }

    #strength-bar {
        width: 30;
    }

    #password-match {
        color: $success;
        padding: 0 0 0 2;
    }

    #password-feedback {
        color: $warning;
        padding: 0 0 0 12;
        height: auto;
    }

    #action-btn {
        width: 100%;
        margin: 1 0;
    }

    #output-section {
        height: auto;
        min-height: 5;
        border: round $warning;
    }

    #output-header {
        layout: horizontal;
        height: 1;
        padding: 0 0 1 0;
    }

    #output-label {
        color: $warning;
        text-style: bold;
        width: 1fr;
    }

    #countdown-label {
        color: $error;
        text-style: bold;
        width: auto;
    }

    #output-text {
        height: 6;
        min-height: 4;
    }

    #output-buttons {
        layout: horizontal;
        height: 3;
        padding: 1 0 0 0;
    }

    #output-buttons Button {
        margin: 0 2 0 0;
    }

    #status-bar {
        dock: bottom;
        height: 1;
        background: $primary-background;
        color: $text-muted;
        padding: 0 2;
    }

    #pq-status {
        color: $success;
    }

    #pq-warning {
        color: $warning;
    }

    #keygen-section {
        height: auto;
        border: round $accent;
        padding: 1 2;
        margin: 0 0 1 0;
        display: none;
    }

    #keygen-section.visible {
        display: block;
    }

    #pq-info {
        color: $text-muted;
        padding: 0 0 1 0;
    }

    #keygen-output {
        height: auto;
        max-height: 8;
    }
    """

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+e", "do_encrypt", "Encrypt", show=True),
        Binding("ctrl+d", "do_decrypt", "Decrypt", show=True),
        Binding("ctrl+l", "clear_all", "Clear All", show=True),
    ]

    _countdown: reactive[int] = reactive(-1)
    _timer_handle = None
    _pq_public_key: bytes | None = None
    _pq_secret_key: bytes | None = None

    def compose(self) -> ComposeResult:
        yield Header()

        with Vertical(id="main-container"):
            yield Static(
                "[bold cyan]MORPHEUS[/bold cyan]",
                id="app-title",
            )
            yield Static(
                "Quantum-Resistant Multi-Cipher Encryption Tool",
                id="app-subtitle",
            )

            # --- Configuration ---
            with Container(id="config-section", classes="section-box"):
                yield Static("Configuration", classes="section-title")

                with RadioSet(id="mode-radio"):
                    yield RadioButton("Encrypt", value=True, id="mode-encrypt")
                    yield RadioButton("Decrypt", id="mode-decrypt")

                with Horizontal(classes="config-row"):
                    yield Label("Cipher:", classes="config-label")
                    yield Select(
                        [(name, name) for name in CIPHER_CHOICES],
                        value="AES-256-GCM",
                        id="cipher-select",
                        classes="config-select",
                    )

                with Horizontal(classes="config-row"):
                    yield Label("KDF:", classes="config-label")
                    yield Select(
                        [(name, name) for name in KDF_CHOICES],
                        value="Argon2id",
                        id="kdf-select",
                        classes="config-select",
                    )

                with Horizontal(id="options-row"):
                    yield Checkbox(
                        "Chain ciphers (AES + ChaCha)",
                        id="chain-check",
                    )
                    pq_label = "Hybrid Post-Quantum (ML-KEM-768)"
                    if not PQ_AVAILABLE:
                        pq_label += " [dim](not installed)[/dim]"
                    yield Checkbox(
                        pq_label,
                        id="pq-check",
                        disabled=not PQ_AVAILABLE,
                    )

            # --- PQ Key Management ---
            with Container(id="keygen-section"):
                yield Static("Post-Quantum Key Management", classes="section-title")
                yield Static(
                    "Generate an ML-KEM-768 keypair. Keys exist in memory only — "
                    "copy them now or they are lost when the app closes.",
                    id="pq-info",
                )
                with Horizontal():
                    yield Button("Generate Keypair", id="keygen-btn", variant="warning")
                    yield Button("Copy Public Key", id="copy-pk-btn", variant="default")
                    yield Button("Copy Secret Key", id="copy-sk-btn", variant="default")
                yield Static("", id="keygen-output")

            # --- Input ---
            with Container(id="input-section", classes="section-box"):
                yield Static("Input", classes="section-title")
                yield TextArea(id="input-text")

            # --- Password ---
            with Container(id="password-section", classes="section-box"):
                yield Static("Password", classes="section-title")

                with Horizontal(classes="password-row"):
                    yield Label("Password:", classes="password-label")
                    yield Input(
                        placeholder="Enter password...",
                        password=True,
                        id="password-input",
                        classes="password-input",
                    )

                with Horizontal(id="strength-row"):
                    yield StrengthBar(id="strength-bar")
                    yield Static("", id="password-match")

                yield Static("", id="password-feedback")

                with Horizontal(classes="password-row", id="confirm-row"):
                    yield Label("Confirm:", classes="password-label")
                    yield Input(
                        placeholder="Confirm password...",
                        password=True,
                        id="password-confirm",
                        classes="password-input",
                    )

            # --- Action ---
            yield Button(
                "ENCRYPT",
                id="action-btn",
                variant="success",
            )

            # --- Output ---
            with Container(id="output-section", classes="section-box"):
                with Horizontal(id="output-header"):
                    yield Static("Output", id="output-label")
                    yield Static("", id="countdown-label")

                yield TextArea(id="output-text", read_only=True)

                with Horizontal(id="output-buttons"):
                    yield Button("Copy", id="copy-btn", variant="primary")
                    yield Button("Clear Now", id="clear-btn", variant="error")

            # --- Status ---
            yield Static("", id="status-bar")

        yield Footer()

    def on_mount(self) -> None:
        self._update_status()
        self.query_one("#input-text", TextArea).focus()

    # ---------- Reactive watchers ----------

    def watch__countdown(self, value: int) -> None:
        label = self.query_one("#countdown-label", Static)
        if value > 0:
            label.update(f"Auto-clear in {value}s")
        elif value == 0:
            label.update("")
            self._clear_output()
        else:
            label.update("")

    # ---------- Event handlers ----------

    def on_radio_set_changed(self, event: RadioSet.Changed) -> None:
        is_encrypt = event.index == 0
        btn = self.query_one("#action-btn", Button)
        btn.label = "ENCRYPT" if is_encrypt else "DECRYPT"
        btn.variant = "success" if is_encrypt else "primary"

        confirm_row = self.query_one("#confirm-row")
        confirm_row.display = is_encrypt

    def on_checkbox_changed(self, event: Checkbox.Changed) -> None:
        if event.checkbox.id == "pq-check":
            keygen = self.query_one("#keygen-section")
            if event.value:
                keygen.add_class("visible")
                keygen.display = True
            else:
                keygen.remove_class("visible")
                keygen.display = False
        self._update_status()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "password-input":
            pwd = event.value
            if pwd:
                result = check_password_strength(pwd)
                bar = self.query_one("#strength-bar", StrengthBar)
                bar.score = result.score
                fb = self.query_one("#password-feedback", Static)
                if result.feedback:
                    fb.update("[dim]" + " | ".join(result.feedback[:2]) + "[/dim]")
                else:
                    fb.update("")
            else:
                self.query_one("#strength-bar", StrengthBar).score = 0
                self.query_one("#password-feedback", Static).update("")
            self._check_password_match()

        elif event.input.id == "password-confirm":
            self._check_password_match()

    def _check_password_match(self) -> None:
        pwd = self.query_one("#password-input", Input).value
        confirm = self.query_one("#password-confirm", Input).value
        match_label = self.query_one("#password-match", Static)
        if confirm and pwd == confirm:
            match_label.update("[green]Match[/green]")
        elif confirm:
            match_label.update("[red]No match[/red]")
        else:
            match_label.update("")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id

        if btn_id == "action-btn":
            self._run_action()
        elif btn_id == "copy-btn":
            self._copy_output()
        elif btn_id == "clear-btn":
            self._clear_output()
        elif btn_id == "keygen-btn":
            self._generate_keypair()
        elif btn_id == "copy-pk-btn":
            self._copy_pq_key("public")
        elif btn_id == "copy-sk-btn":
            self._copy_pq_key("secret")

    # ---------- Actions ----------

    def action_do_encrypt(self) -> None:
        radio = self.query_one("#mode-radio", RadioSet)
        radio._nodes[0].value = True  # noqa: SLF001
        self._run_action()

    def action_do_decrypt(self) -> None:
        radio = self.query_one("#mode-radio", RadioSet)
        radio._nodes[1].value = True  # noqa: SLF001
        self._run_action()

    def action_clear_all(self) -> None:
        self.query_one("#input-text", TextArea).clear()
        self.query_one("#password-input", Input).value = ""
        self.query_one("#password-confirm", Input).value = ""
        self._clear_output()
        self.query_one("#password-feedback", Static).update("")
        self.query_one("#strength-bar", StrengthBar).score = 0
        self.query_one("#password-match", Static).update("")

    def _run_action(self) -> None:
        radio = self.query_one("#mode-radio", RadioSet)
        is_encrypt = radio.pressed_index == 0

        if is_encrypt:
            self._do_encrypt()
        else:
            self._do_decrypt()

    @work(thread=True)
    def _do_encrypt(self) -> None:
        input_area = self.query_one("#input-text", TextArea)
        text = input_area.text

        valid, err = validate_input_text(text)
        if not valid:
            self.call_from_thread(self._show_error, err)
            return

        password = self.query_one("#password-input", Input).value
        confirm = self.query_one("#password-confirm", Input).value

        if not password:
            self.call_from_thread(self._show_error, "Password cannot be empty")
            return
        if password != confirm:
            self.call_from_thread(self._show_error, "Passwords do not match")
            return

        strength = check_password_strength(password)
        if not strength.is_acceptable:
            self.call_from_thread(
                self._show_error,
                "Password too weak: " + "; ".join(strength.feedback[:2]),
            )
            return

        try:
            pipeline = self._build_pipeline()
            result = pipeline.encrypt(text, password)
            self.call_from_thread(self._show_output, result)
        except Exception as exc:
            self.call_from_thread(self._show_error, str(exc))

    @work(thread=True)
    def _do_decrypt(self) -> None:
        input_area = self.query_one("#input-text", TextArea)
        ciphertext = input_area.text.strip()

        if not ciphertext:
            self.call_from_thread(self._show_error, "Paste encrypted data in the input area")
            return

        password = self.query_one("#password-input", Input).value
        if not password:
            self.call_from_thread(self._show_error, "Password cannot be empty")
            return

        try:
            pipeline = self._build_pipeline()
            result = pipeline.decrypt(ciphertext, password)
            self.call_from_thread(self._show_output, result)
        except Exception:
            self.call_from_thread(
                self._show_error,
                "Decryption failed: incorrect password or corrupted data",
            )

    def _build_pipeline(self) -> EncryptionPipeline:
        cipher_name = self.query_one("#cipher-select", Select).value
        kdf_name = self.query_one("#kdf-select", Select).value
        chain = self.query_one("#chain-check", Checkbox).value
        hybrid = self.query_one("#pq-check", Checkbox).value

        cipher_cls = CIPHER_CHOICES[cipher_name]
        kdf_cls = KDF_CHOICES[kdf_name]

        return EncryptionPipeline(
            cipher=cipher_cls(),
            kdf=kdf_cls(),
            chain=chain,
            hybrid_pq=hybrid,
            pq_public_key=self._pq_public_key,
            pq_secret_key=self._pq_secret_key,
        )

    # ---------- PQ Key management ----------

    def _generate_keypair(self) -> None:
        try:
            pk, sk = pq_generate_keypair()
            self._pq_public_key = pk
            self._pq_secret_key = sk
            output = self.query_one("#keygen-output", Static)
            output.update(
                f"[green]Keypair generated![/green] "
                f"Public key: {len(pk)} bytes | Secret key: {len(sk)} bytes\n"
                "[dim]Keys exist in memory only. Copy them before closing.[/dim]"
            )
        except Exception as exc:
            output = self.query_one("#keygen-output", Static)
            output.update(f"[red]Error: {exc}[/red]")

    def _copy_pq_key(self, which: str) -> None:
        import base64

        if which == "public" and self._pq_public_key:
            data = base64.b64encode(self._pq_public_key).decode()
            pyperclip.copy(data)
            self.notify("Public key copied to clipboard", severity="information")
        elif which == "secret" and self._pq_secret_key:
            data = base64.b64encode(self._pq_secret_key).decode()
            pyperclip.copy(data)
            self.notify("Secret key copied to clipboard — clear it soon!", severity="warning")
        else:
            self.notify("Generate a keypair first", severity="warning")

    # ---------- Output management ----------

    def _show_output(self, text: str) -> None:
        output = self.query_one("#output-text", TextArea)
        output.clear()
        output.insert(text)
        self._start_countdown()

    def _show_error(self, msg: str) -> None:
        self.notify(msg, severity="error", timeout=6)

    def _start_countdown(self) -> None:
        self._stop_countdown()
        self._countdown = AUTO_CLEAR_SECONDS
        self._timer_handle = self.set_interval(1.0, self._tick_countdown)

    def _tick_countdown(self) -> None:
        if self._countdown > 0:
            self._countdown -= 1
        else:
            self._stop_countdown()

    def _stop_countdown(self) -> None:
        if self._timer_handle:
            self._timer_handle.stop()
            self._timer_handle = None
        self._countdown = -1

    def _clear_output(self) -> None:
        self._stop_countdown()
        output = self.query_one("#output-text", TextArea)
        output.clear()
        self.query_one("#countdown-label", Static).update("")
        # Clear the system clipboard. Note: this overwrites the current clipboard
        # contents but clipboard history managers (macOS Universal Clipboard,
        # Windows Clipboard History, KDE Klipper, etc.) may retain the previous
        # value in a separate history store. Users with clipboard managers should
        # disable history during sensitive operations.
        try:
            pyperclip.copy("")
        except Exception:
            pass

    def _copy_output(self) -> None:
        output = self.query_one("#output-text", TextArea)
        text = output.text
        if text.strip():
            try:
                pyperclip.copy(text)
                self.notify("Copied to clipboard (auto-clears with output)", severity="information")
            except Exception:
                self.notify("Clipboard unavailable — select and copy manually", severity="warning")
        else:
            self.notify("Nothing to copy", severity="warning")

    # ---------- Status bar ----------

    def _update_status(self) -> None:
        parts = []

        try:
            cipher_name = self.query_one("#cipher-select", Select).value
            parts.append(cipher_name)
        except Exception:
            parts.append("AES-256-GCM")

        try:
            kdf_name = self.query_one("#kdf-select", Select).value
            parts.append(kdf_name)
        except Exception:
            parts.append("Argon2id")

        try:
            if self.query_one("#chain-check", Checkbox).value:
                parts.append("Chained")
        except Exception:
            pass

        if PQ_AVAILABLE:
            try:
                if self.query_one("#pq-check", Checkbox).value:
                    parts.append("ML-KEM-768")
            except Exception:
                pass

        parts.append("Memory-locked")
        parts.append("No data on disk")

        status = self.query_one("#status-bar", Static)
        status.update(" · ".join(parts))


def run_gui():
    """Launch the TUI application."""
    app = SecureEncryptionApp()
    app.run()
