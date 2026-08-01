"""The transport envelope that carries a file's bytes and its original name.

One implementation, used by both the CLI and the wizard. They had two: the CLI
parsed the envelope on decrypt and the wizard did not, so encrypting a file in
the wizard and decrypting it there returned the JSON to the user instead of
their file (2026-08-02 review, F-05).

The parser is strict on purpose. The previous one asked `"data" in envelope`
after `envelope.get(...)`, which produced three separate defects (F-07):

  * a ciphertext whose plaintext was a JSON *list* reached
    `AttributeError: 'list' object has no attribute 'get'`
  * a plaintext that merely happened to contain a `data` key, such as
    `{"data": "SGVsbG8="}`, was treated as a file envelope and written out as
    `Hello`, destroying the user's actual JSON
  * base64 was decoded without `validate=True`, so non-base64 characters were
    silently skipped rather than rejected

So `decode` recognises an envelope only when the whole schema holds, and says
"this is not an envelope" for everything else rather than guessing. Plaintext
that is not ours must survive untouched; that is the common case, not the edge
case.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from dataclasses import dataclass

from .errors import FormatError

ENVELOPE_VERSION = 1

# A filename is attacker-controlled: it arrives inside someone else's
# ciphertext. Bound it before it reaches a filesystem call or a terminal.
MAX_FILENAME_LENGTH = 255


@dataclass(frozen=True)
class FileEnvelope:
    """A decoded envelope. `filename` is None when the sender omitted it."""

    data: bytes
    filename: str | None


def encode(raw: bytes, filename: str | None = None) -> str:
    """Wrap file bytes for transport through the string-oriented pipeline."""
    envelope: dict[str, object] = {
        "envelope_version": ENVELOPE_VERSION,
        "data": base64.b64encode(raw).decode(),
    }
    if filename:
        envelope["filename"] = os.path.basename(filename)
    return json.dumps(envelope)


def decode(text: str) -> FileEnvelope | None:
    """Parse *text* as an envelope, or return None if it is ordinary plaintext.

    Raises `FormatError` only for the one case that is an envelope but cannot
    be read: a version newer than this build understands. Everything else that
    fails the schema is simply not an envelope, and the caller should treat it
    as the plaintext it is.
    """
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(parsed, dict):
        return None

    version = parsed.get("envelope_version")
    if not isinstance(version, int) or isinstance(version, bool):
        return None
    if version > ENVELOPE_VERSION:
        raise FormatError(
            f"envelope version {version} is newer than this build supports "
            f"(max {ENVELOPE_VERSION}). Update MORPHEUS to decrypt this file."
        )
    if version < 1:
        return None

    encoded = parsed.get("data")
    if not isinstance(encoded, str):
        return None
    try:
        raw = base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        return None

    name = parsed.get("filename")
    if name is not None:
        if not isinstance(name, str) or len(name) > MAX_FILENAME_LENGTH:
            return None
        name = safe_filename(name)
        if not name:
            name = None

    return FileEnvelope(data=raw, filename=name)


def safe_filename(name: str) -> str:
    """Reduce a sender-controlled name to something safe to create on disk.

    `os.path.basename` alone blocks traversal and nothing else. A filename
    arrives from whoever produced the ciphertext, so it can carry terminal
    control sequences, NUL bytes, Windows separators that POSIX basename does
    not treat as separators, or a reserved device name (2026-08-02 review,
    F-08). Returns "" when nothing usable survives, so the caller falls back to
    a generated name.
    """
    # Both separator styles, because a POSIX basename leaves "..\\..\\x" whole.
    name = name.replace("\\", "/")
    name = os.path.basename(name)
    name = "".join(ch for ch in name if ch.isprintable() and ch not in '/\x00')
    name = name.strip(". ")
    if name in {"", ".", ".."}:
        return ""
    stem = name.split(".", 1)[0].upper()
    if stem in {
        "CON", "PRN", "AUX", "NUL",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    }:
        return ""
    return name[:MAX_FILENAME_LENGTH]
