"""MORPHEUS Dashboard — Sampler-inspired single-screen encryption tool.

All panels visible at once. No wizard steps. See everything, control everything.

Keyboard:
  Tab / Shift+Tab   Navigate between fields
  Enter              Select / activate focused element
  Ctrl+E             Set Encrypt mode
  Ctrl+D             Set Decrypt mode
  Ctrl+L             Clear all fields
  Ctrl+Q             Quit
  F1                 Help
"""

from __future__ import annotations

import base64
import json
import os

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical
from textual.widgets import Button, Footer, RadioButton, Select, Static

from ..core.ciphers import CIPHER_CHOICES
from ..core.kdf import KDF_CHOICES
from ..core.pipeline import EncryptionPipeline
from ..core.validation import check_password_strength, validate_input_text
from .panels import (
    InputPanel,
    ModePanel,
    OutputPanel,
    PasswordPanel,
    SettingsPanel,
    StatusPanel,
)
from .state import InputMethod, Mode, WizardState
from .theme import DASHBOARD_CSS

_MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MiB


class DashboardGrid(Vertical):
    """Main content area holding all dashboard panels."""

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(**kw)
        self._state = state

    def compose(self):
        with Horizontal(id="top-row"):
            yield ModePanel(self._state, id="mode-panel", classes="panel")
            yield SettingsPanel(self._state, id="settings-panel", classes="panel")
            yield StatusPanel(self._state, id="status-panel", classes="panel")
        with Horizontal(id="mid-row"):
            yield InputPanel(self._state, id="input-panel", classes="panel")
            yield PasswordPanel(self._state, id="password-panel", classes="panel")
        yield OutputPanel(self._state, id="output-panel", classes="panel")


class MorpheusApp(App):
    """Single-screen dashboard — all panels visible simultaneously."""

    TITLE = "MORPHEUS"
    CSS = DASHBOARD_CSS

    BINDINGS = [
        Binding("ctrl+q", "quit", "Quit"),
        Binding("ctrl+e", "quick_encrypt", "Encrypt"),
        Binding("ctrl+d", "quick_decrypt", "Decrypt"),
        Binding("ctrl+l", "clear_all", "Clear"),
        Binding("f1", "show_help", "Help"),
    ]

    def __init__(self, **kw) -> None:
        super().__init__(**kw)
        self._state = WizardState()

    # ── Compose ────────────────────────────────────────────────────

    def compose(self) -> ComposeResult:
        with Horizontal(id="header-bar"):
            yield Static(
                "[bold #00FF41]⬡ MORPHEUS[/] [#007018]v2.1[/]",
                id="header-title",
            )
            yield Static(
                "[#007018]Encryption Dashboard[/]",
                id="header-subtitle",
            )
        yield DashboardGrid(self._state, id="dashboard")
        yield Footer()

    # ── State change relay ─────────────────────────────────────────

    def _refresh_status(self) -> None:
        """Refresh the status panel after any state change."""
        try:
            self.query_one("#status-panel", StatusPanel).refresh_status()
        except Exception:
            pass

    def on_radio_set_changed(self, event) -> None:
        self._refresh_status()
        if event.radio_set.id == "mode-radio":
            try:
                self.query_one("#password-panel", PasswordPanel).refresh_for_mode()
            except Exception:
                pass

    def on_select_changed(self, event) -> None:
        self._refresh_status()

    def on_checkbox_changed(self, event) -> None:
        self._refresh_status()

    def on_input_changed(self, event) -> None:
        self._refresh_status()

    def on_text_area_changed(self, event) -> None:
        self._refresh_status()

    # ── Execute button ─────────────────────────────────────────────

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-run":
            self._run_operation()

    def _run_operation(self) -> None:
        ok, reason = self._state.validate_review()
        if not ok:
            self.notify(reason, severity="error")
            return
        if self._state.mode == Mode.ENCRYPT:
            self._do_encrypt()
        else:
            self._do_decrypt()

    # ── Keyboard actions ───────────────────────────────────────────

    def action_quick_encrypt(self) -> None:
        self._state.mode = Mode.ENCRYPT
        try:
            self.query_one("#radio-encrypt", RadioButton).value = True
        except Exception:
            pass
        self._refresh_status()
        try:
            self.query_one("#password-panel", PasswordPanel).refresh_for_mode()
        except Exception:
            pass
        self.notify("Mode → Encrypt")

    def action_quick_decrypt(self) -> None:
        self._state.mode = Mode.DECRYPT
        try:
            self.query_one("#radio-decrypt", RadioButton).value = True
        except Exception:
            pass
        self._refresh_status()
        try:
            self.query_one("#password-panel", PasswordPanel).refresh_for_mode()
        except Exception:
            pass
        self.notify("Mode → Decrypt")

    def action_clear_all(self) -> None:
        # Reset state in-place so all panels keep their reference
        s = self._state
        s.mode = None
        s.cipher = "AES-256-GCM"
        s.kdf = "Argon2id"
        s.chain = False
        s.hybrid_pq = False
        s.pad = False
        s.fixed_size = False
        s.no_filename = False
        s.input_method = InputMethod.TEXT
        s.input_text = ""
        s.input_file = ""
        s.password = ""
        s.password_confirm = ""
        s.output = ""
        s.completed_steps.clear()

        # Reset UI widgets to match
        for rb in self.query("RadioButton"):
            rb.value = False
        try:
            self.query_one("#cipher-select", Select).value = "AES-256-GCM"
            self.query_one("#kdf-select", Select).value = "Argon2id"
        except Exception:
            pass
        for cb in self.query("Checkbox"):
            cb.value = False
        for ta in self.query("TextArea"):
            ta.clear()
        for inp in self.query("Input"):
            inp.value = ""

        self._refresh_status()
        self.notify("All fields cleared")

    def action_show_help(self) -> None:
        self.notify(
            "Keyboard shortcuts:\n"
            "  Tab / Shift+Tab  Navigate fields\n"
            "  Enter            Select / activate\n"
            "  Ctrl+E  Encrypt    Ctrl+D  Decrypt\n"
            "  Ctrl+L  Clear all  Ctrl+Q  Quit",
            severity="information",
            timeout=10,
        )

    # ── Encrypt / Decrypt ──────────────────────────────────────────

    @work(thread=True)
    def _do_encrypt(self) -> None:
        s = self._state
        try:
            strength = check_password_strength(s.password)
            if not strength.is_acceptable:
                msg = (
                    f"Password too weak ({strength.label}). "
                    + "; ".join(strength.feedback[:2])
                )
                self.call_from_thread(self.notify, msg, severity="error")
                return

            pipeline = self._build_pipeline()

            if s.input_method == InputMethod.TEXT:
                valid, err = validate_input_text(s.input_text)
                if not valid:
                    self.call_from_thread(self.notify, err, severity="error")
                    return
                result = pipeline.encrypt(
                    s.input_text, s.password, pad=s.pad, fixed_size=s.fixed_size,
                )
            else:
                result = self._encrypt_file(pipeline)

            s.output = result
            self.call_from_thread(self._show_output, result)
        except Exception as exc:
            self.call_from_thread(
                self.notify, f"Encryption failed: {exc}", severity="error"
            )

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
            self.call_from_thread(self._show_output, result)
        except Exception as exc:
            self.call_from_thread(
                self.notify, f"Decryption failed: {exc}", severity="error"
            )

    def _show_output(self, text: str) -> None:
        try:
            self.query_one("#output-panel", OutputPanel).show_output(text)
        except Exception:
            pass

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
        s = self._state
        path = s.input_file
        if not os.path.isfile(path):
            raise FileNotFoundError(f"File not found: {path}")
        file_size = os.path.getsize(path)
        if file_size > _MAX_FILE_SIZE:
            raise ValueError(
                f"File too large ({file_size / 1024 / 1024:.1f} MiB, max 100 MiB)"
            )
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
        path = self._state.input_file
        if not os.path.isfile(path):
            raise FileNotFoundError(f"File not found: {path}")
        file_size = os.path.getsize(path)
        if file_size > _MAX_FILE_SIZE:
            raise ValueError(
                f"File too large ({file_size / 1024 / 1024:.1f} MiB, max 100 MiB)"
            )
        with open(path, "r") as f:
            data = f.read().strip()
        return pipeline.decrypt(data, self._state.password)


# Backward-compat alias — tests and entry points may reference this
MorpheusWizard = MorpheusApp


def run_gui() -> None:
    """Launch the MORPHEUS dashboard TUI."""
    app = MorpheusApp()
    app.run()
