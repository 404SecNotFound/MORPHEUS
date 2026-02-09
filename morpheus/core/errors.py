"""Structured error types for MORPHEUS.

All errors inherit from both ``MorpheusError`` and ``ValueError`` so that
existing code that catches ``ValueError`` continues to work unchanged.

Hierarchy::

    MorpheusError (Exception)
    +-- FormatError        — ciphertext wire-format parsing failures
    +-- PaddingError       — padding encode / decode failures
    +-- KDFParameterError  — invalid KDF config or bounds violation
    +-- ConfigurationError — invalid pipeline setup (missing keys, bad combo)
    +-- DecryptionError    — authentication / decryption failures
        +-- WrongPasswordError — key-check or AEAD mismatch
"""

from __future__ import annotations


class MorpheusError(Exception):
    """Base class for all MORPHEUS errors."""


class FormatError(MorpheusError, ValueError):
    """Ciphertext wire-format is malformed (bad header, version, encoding)."""


class PaddingError(MorpheusError, ValueError):
    """Padding is invalid or cannot be removed."""


class KDFParameterError(MorpheusError, ValueError):
    """KDF parameter out of allowed bounds or unknown KDF identifier."""


class ConfigurationError(MorpheusError, ValueError):
    """Pipeline is mis-configured (missing key, incompatible options)."""


class DecryptionError(MorpheusError, ValueError):
    """Decryption failed (truncated ciphertext, PQ failure, etc.)."""


class WrongPasswordError(DecryptionError):
    """Key-check mismatch — the password is almost certainly wrong."""
