"""
Input validation utilities.

Provides password strength checking with a granular scoring system,
passphrase-mode validation, breach detection via HIBP k-anonymity,
and input sanitization for the encryption pipeline.
"""

from __future__ import annotations

import hashlib
import re
import urllib.request
import urllib.error
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


def check_passphrase_strength(passphrase: str) -> PasswordStrength:
    """
    Evaluate passphrase strength based on word count and diversity.

    Designed for word-based passwords like "correct horse battery staple".
    Does NOT require digits, uppercase, or special characters.

    Minimum requirements for is_acceptable=True:
      - At least 4 words
      - At least 20 characters total
    """
    if not passphrase:
        return PasswordStrength(
            score=0, label="Weak",
            feedback=["Passphrase cannot be empty"],
            is_acceptable=False,
        )

    words = re.split(r"[\s\-_.,;:!?/\\|]+", passphrase.strip())
    words = [w for w in words if w]  # remove empty tokens
    word_count = len(words)
    total_len = len(passphrase)

    if word_count == 0:
        return PasswordStrength(
            score=0, label="Weak",
            feedback=["Passphrase must contain words"],
            is_acceptable=False,
        )

    score = 0
    feedback: list[str] = []

    # Word count scoring (0-40 points)
    if word_count >= 7:
        score += 40
    elif word_count >= 5:
        score += 30
    elif word_count >= 4:
        score += 20
    else:
        score += max(0, word_count * 5)
        feedback.append(f"Use at least 4 words (currently {word_count})")

    # Total length scoring (0-25 points)
    if total_len >= 30:
        score += 25
    elif total_len >= 24:
        score += 20
    elif total_len >= 20:
        score += 15
    else:
        score += max(0, total_len // 3)
        feedback.append(f"Use at least 20 characters total (currently {total_len})")

    # Word uniqueness scoring (0-20 points)
    unique_words = len(set(w.lower() for w in words))
    if unique_words == word_count:
        score += 20
    elif unique_words >= max(1, int(word_count * 0.75)):
        score += 10
    else:
        score += 5
        feedback.append("Avoid repeating the same words")

    # Average word length bonus (0-15 points)
    avg_len = sum(len(w) for w in words) / word_count
    if avg_len >= 6:
        score += 15
    elif avg_len >= 4:
        score += 10
    elif avg_len >= 3:
        score += 5
    else:
        feedback.append("Use longer words for more entropy")

    score = min(score, 100)

    if score >= 80:
        label = "Excellent"
    elif score >= 60:
        label = "Strong"
    elif score >= 40:
        label = "Fair"
    else:
        label = "Weak"

    is_acceptable = word_count >= 4 and total_len >= 20

    return PasswordStrength(
        score=score, label=label,
        feedback=feedback, is_acceptable=is_acceptable,
    )


def check_password_leaked(password: str, *, timeout: float = 5.0) -> tuple[bool, int]:
    """
    Check if a password appears in known data breaches via Have I Been Pwned.

    Uses k-anonymity: only the first 5 characters of the SHA-1 hash are sent
    to the API. The full password never leaves the machine.

    Returns (is_leaked, breach_count).
    Raises urllib.error.URLError on network failure.
    """
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    req = urllib.request.Request(url, headers={"User-Agent": "MORPHEUS-EncryptionTool"})
    resp = urllib.request.urlopen(req, timeout=timeout)
    body = resp.read().decode("utf-8")

    for line in body.splitlines():
        parts = line.strip().split(":")
        if len(parts) == 2 and parts[0] == suffix:
            return True, int(parts[1])

    return False, 0


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
