"""Output-file creation, in one place, for every caller that writes a secret.

The CLI already opened its outputs carefully. The wizard had no file-writing
path at all, and the CLI's own keypair route bypassed its helper for the public
key (2026-08-02 review, F-06). Rather than let a second implementation grow in
the UI layer, the flag handling lives here and `cli.py` wraps it with its own
error reporting.

This module raises. It does not print and does not exit, so a UI can catch it
and a CLI can turn it into a message.
"""

from __future__ import annotations

import os


def open_secure(path: str, force: bool = False, binary: bool = False):
    """Open *path* for writing, owner-only, refusing to follow a symlink.

    Three things happen together here, and dropping any one of them reopens a
    real hole:

    * ``O_NOFOLLOW`` refuses a symlink at the final component. An existence
      check cannot replace it: ``os.path.exists`` reports False for a *dangling*
      link, so the write would land on the link's target. That is exactly how
      the public-key path could be made to overwrite an unrelated file.
    * ``O_EXCL`` makes the existence check atomic rather than a TOCTOU window.
      ``force`` swaps it for ``O_TRUNC`` so an intentional overwrite still
      works, and still refuses symlinks.
    * ``fchmod`` is applied unconditionally, so the mode depends on neither the
      umask nor whatever permissions an overwritten file happened to carry.

    ``O_NOFOLLOW`` does not exist on every platform; where it is absent the
    symlink guarantee does not hold and that is a documented limitation rather
    than a silent one.
    """
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    flags |= os.O_TRUNC if force else os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
    except OSError:
        os.close(fd)
        raise
    if binary:
        return os.fdopen(fd, "wb")
    # Text mode names both its codec and its newlines. The locale codec is
    # UTF-8 on macOS and Linux and cp1252 on Windows, and Windows text mode
    # also rewrites "\n" as "\r\n" -- which silently changed the bytes of a
    # decrypted file on that platform.
    return os.fdopen(fd, "w", encoding="utf-8", newline="")


def unique_path(directory: str, name: str) -> str:
    """A path under *directory* named *name* that does not already exist.

    Decryption must never quietly replace a file the user already has, and the
    wizard has no prompt to ask with, so it steps aside instead: ``report.pdf``
    becomes ``report (1).pdf``. Racy by nature, which is why the actual create
    still uses ``O_EXCL``; this only picks a candidate.
    """
    candidate = os.path.join(directory, name)
    if not os.path.exists(candidate):
        return candidate
    stem, ext = os.path.splitext(name)
    for n in range(1, 1000):
        candidate = os.path.join(directory, f"{stem} ({n}){ext}")
        if not os.path.exists(candidate):
            return candidate
    raise OSError(f"could not find an unused name for {name!r} in {directory!r}")
