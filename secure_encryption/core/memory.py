"""
Secure memory handling utilities.

Provides best-effort memory protection for sensitive data:
  - mlock to prevent pages from swapping to disk
  - Explicit zeroing of bytearray buffers
  - Context manager for automatic cleanup

Note: Python's immutable strings cannot be reliably zeroed. All sensitive
intermediates should use bytearray where possible.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import sys
from contextlib import contextmanager

_libc_loaded = False  # Sentinel: distinguishes "not yet attempted" from "attempted and failed"
_libc = None
_mlock = None
_munlock = None


def _load_libc():
    """Lazily load libc for mlock/munlock. Only attempts once."""
    global _libc_loaded, _libc, _mlock, _munlock
    if _libc_loaded:
        return

    _libc_loaded = True  # Mark as attempted regardless of outcome

    if sys.platform == "win32":
        # Windows uses VirtualLock but we skip for simplicity
        return

    libc_name = ctypes.util.find_library("c")
    if not libc_name:
        return

    try:
        _libc = ctypes.CDLL(libc_name, use_errno=True)
        _mlock = _libc.mlock
        _mlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _mlock.restype = ctypes.c_int
        _munlock = _libc.munlock
        _munlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _munlock.restype = ctypes.c_int
    except OSError:
        _libc = None


def mlock_buffer(buf: bytearray) -> bool:
    """
    Lock a bytearray's memory pages to prevent swapping to disk.
    Returns True if successful, False otherwise (non-fatal).
    """
    _load_libc()
    if _mlock is None:
        return False

    try:
        addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
        result = _mlock(addr, len(buf))
        return result == 0
    except (ValueError, TypeError):
        return False


def munlock_buffer(buf: bytearray) -> bool:
    """Unlock previously mlocked memory pages."""
    _load_libc()
    if _munlock is None:
        return False

    try:
        addr = ctypes.addressof((ctypes.c_char * len(buf)).from_buffer(buf))
        result = _munlock(addr, len(buf))
        return result == 0
    except (ValueError, TypeError):
        return False


def secure_zero(buf: bytearray) -> None:
    """Overwrite a bytearray with zeros."""
    for i in range(len(buf)):
        buf[i] = 0


class SecureBuffer:
    """
    A bytearray wrapper that mlocks on creation and zeros + munlocks on close.

    Usage:
        with SecureBuffer(32) as buf:
            buf.data[:] = key_bytes
            # use buf.data
        # buf is now zeroed and unlocked
    """

    def __init__(self, size: int):
        self.data = bytearray(size)
        self._locked = mlock_buffer(self.data)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def close(self):
        """Zero the buffer and unlock memory."""
        secure_zero(self.data)
        if self._locked:
            munlock_buffer(self.data)
            self._locked = False


@contextmanager
def secure_key(key_bytes: bytes | bytearray):
    """
    Context manager: copies key into a locked bytearray, yields it,
    then zeros and unlocks on exit.

    Yields the mutable bytearray directly (not an immutable bytes copy)
    so that the only copy of the key material is the one that gets zeroed.
    """
    buf = SecureBuffer(len(key_bytes))
    try:
        buf.data[:] = key_bytes
        yield buf.data
    finally:
        buf.close()
