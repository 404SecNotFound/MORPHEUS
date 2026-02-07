"""
Input validation utilities.

Provides password strength checking with a granular scoring system
and input sanitization for the encryption pipeline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

SPECIAL_CHARS = r"""!@#$%^&*(),.?":{}|<>~`\[\]\-_=+;'/\\"""

# Scoring weights
_SCORE_LENGTH_BASE = 12
_SCORE_LENGTH_GOOD = 16
_SCORE_LENGTH_EXCELLENT = 24


@dataclass
class PasswordStrength:
    """Result of password strength analysis."""
    score: int            # 0-100
    label: str            # "Weak", "Fair", "Strong", "Excellent"
    feedback: list[str]   # Human-readable improvement suggestions
    is_acceptable: bool   # Meets minimum requirements


def check_password_strength(password: str) -> PasswordStrength:
    """
    Evaluate password strength on a 0-100 scale.

    Minimum requirements for is_acceptable=True:
      - At least 12 characters
      - Contains uppercase and lowercase letters
      - Contains at least one digit
      - Contains at least one special character
    """
    score = 0
    feedback: list[str] = []
    length = len(password)

    if length == 0:
        return PasswordStrength(
            score=0, label="Weak",
            feedback=["Password cannot be empty"],
            is_acceptable=False,
        )

    # Length scoring (0-35 points)
    if length >= _SCORE_LENGTH_EXCELLENT:
        score += 35
    elif length >= _SCORE_LENGTH_GOOD:
        score += 25
    elif length >= _SCORE_LENGTH_BASE:
        score += 15
    elif length >= 8:
        score += 5
        feedback.append(f"Use at least 12 characters (currently {length})")
    else:
        feedback.append(f"Use at least 12 characters (currently {length})")

    # Character class scoring (0-40 points, 10 each)
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[^A-Za-z0-9\s]", password))

    if has_upper:
        score += 10
    else:
        feedback.append("Add uppercase letters (A-Z)")

    if has_lower:
        score += 10
    else:
        feedback.append("Add lowercase letters (a-z)")

    if has_digit:
        score += 10
    else:
        feedback.append("Add digits (0-9)")

    if has_special:
        score += 10
    else:
        feedback.append("Add special characters (!@#$%...)")

    # Diversity bonus (0-15 points)
    unique_chars = len(set(password))
    if unique_chars >= 12:
        score += 15
    elif unique_chars >= 8:
        score += 10
    elif unique_chars >= 5:
        score += 5

    # Entropy bonus for mixed patterns (0-10 points)
    # Penalize common patterns
    if not re.search(r"(.)\1{2,}", password):  # No triple+ repeats
        score += 5
    else:
        feedback.append("Avoid repeated characters (aaa, 111)")

    if not re.search(r"(?:012|123|234|345|456|567|678|789|abc|bcd|cde|def)", password.lower()):
        score += 5
    else:
        feedback.append("Avoid sequential patterns (123, abc)")

    score = min(score, 100)

    # Determine label
    if score >= 80:
        label = "Excellent"
    elif score >= 60:
        label = "Strong"
    elif score >= 40:
        label = "Fair"
    else:
        label = "Weak"

    # Minimum bar
    is_acceptable = (
        length >= _SCORE_LENGTH_BASE
        and has_upper
        and has_lower
        and has_digit
        and has_special
    )

    return PasswordStrength(
        score=score,
        label=label,
        feedback=feedback,
        is_acceptable=is_acceptable,
    )


def validate_input_text(text: str) -> tuple[bool, str]:
    """
    Validate encryption input text.
    Returns (is_valid, error_message).
    """
    if not text:
        return False, "Input text cannot be empty"
    if len(text.encode("utf-8")) > 10 * 1024 * 1024:  # 10 MiB
        return False, "Input text exceeds 10 MiB limit"
    return True, ""
