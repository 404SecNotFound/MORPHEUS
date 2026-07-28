"""Cross-platform clipboard utilities with robust fallbacks."""

from __future__ import annotations

import os
import subprocess
import tempfile

try:
    import pyperclip as _pyperclip
except ImportError:
    _pyperclip = None  # type: ignore[assignment]

# tkinter is an optional part of the stdlib: Python built without Tk (Homebrew,
# most slim Docker images, Debian without python3-tk) has no _tkinter module.
# It is only ever a last-resort clipboard backend, so never let it break import.
try:
    import tkinter as tk
except ImportError:
    tk = None  # type: ignore[assignment]


def clipboard_copy(text: str) -> tuple[bool, str]:
    """Copy *text* to system clipboard.

    Returns ``(success, method)`` where *method* describes which backend
    was used.  Tries verifiable backends first (pyperclip, system utils)
    before falling back to the unverifiable OSC-52 terminal escape.
    """
    # 1. pyperclip — most portable, verifiable
    if _pyperclip is not None:
        try:
            _pyperclip.copy(text)
            return True, "pyperclip"
        except Exception:
            pass

    # 2. System clipboard utilities (verifiable via return code)
    for name, cmd in (
        ("xclip", ["xclip", "-selection", "clipboard"]),
        ("xsel", ["xsel", "--clipboard", "--input"]),
        ("wl-copy", ["wl-copy"]),
        ("pbcopy", ["pbcopy"]),
    ):
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            proc.communicate(text.encode("utf-8"), timeout=3)
            if proc.returncode == 0:
                return True, name
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue

    # 3. tkinter fallback (often available with Python installs)
    if tk is not None:
        try:
            root = tk.Tk()
            root.withdraw()
            root.clipboard_clear()
            root.clipboard_append(text)
            root.update()
            root.destroy()
            return True, "tkinter"
        except Exception:
            pass

    return False, ""


def clipboard_paste() -> str | None:
    """Read text from the system clipboard, or *None* on failure."""
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
        ["pbpaste"],
    ):
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=3,
            )
            if result.returncode == 0 and result.stdout:
                return result.stdout
        except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
            continue

    if tk is not None:
        try:
            root = tk.Tk()
            root.withdraw()
            text = root.clipboard_get()
            root.destroy()
            if text:
                return text
        except Exception:
            pass

    return None


def save_to_file(text: str, prefix: str = "morpheus") -> str:
    """Save *text* to a temp file as a clipboard fallback.  Returns path."""
    fd, path = tempfile.mkstemp(prefix=f"{prefix}_", suffix=".txt")
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    return path
