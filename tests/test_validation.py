"""Tests for password validation and input checking."""

import pytest

from morpheus.core.validation import (
    check_password_strength,
    validate_input_text,
)


class TestPasswordStrength:
    def test_excellent_password(self):
        result = check_password_strength("C0mpl3x!P@ssw0rd#2024xz")
        assert result.is_acceptable
        assert result.score >= 75
        assert result.label in ("Strong", "Excellent")

    def test_strong_password(self):
        result = check_password_strength("MyStr0ng!Pass")
        assert result.is_acceptable
        assert result.score >= 50

    def test_weak_short_password(self):
        result = check_password_strength("abc")
        assert not result.is_acceptable
        assert result.label == "Weak"

    def test_no_uppercase_fails(self):
        result = check_password_strength("lowercaseonly1!!")
        assert not result.is_acceptable
        assert any("uppercase" in f.lower() for f in result.feedback)

    def test_no_lowercase_fails(self):
        result = check_password_strength("UPPERCASEONLY1!!")
        assert not result.is_acceptable
        assert any("lowercase" in f.lower() for f in result.feedback)

    def test_no_digit_fails(self):
        result = check_password_strength("NoDigitsHere!!aa")
        assert not result.is_acceptable
        assert any("digit" in f.lower() for f in result.feedback)

    def test_no_special_fails(self):
        result = check_password_strength("NoSpecial1234Aa")
        assert not result.is_acceptable
        assert any("special" in f.lower() for f in result.feedback)

    def test_too_short_fails(self):
        result = check_password_strength("Sh0rt!")
        assert not result.is_acceptable

    def test_minimum_acceptable(self):
        # Exactly meets requirements: 12 chars, upper, lower, digit, special
        result = check_password_strength("Abcdefgh1j!k")
        assert result.is_acceptable

    def test_empty_password(self):
        result = check_password_strength("")
        assert not result.is_acceptable
        assert result.score == 0

    def test_repeated_chars_penalized(self):
        r1 = check_password_strength("Aaa111!!!bbbCCC")
        r2 = check_password_strength("Ax9!Bz2@Cy3#Lk")
        assert r2.score >= r1.score

    def test_sequential_chars_penalized(self):
        r1 = check_password_strength("Abc123!@#defGH")
        r2 = check_password_strength("Xk9!Mz2@Qy3#Nw")
        assert r2.score >= r1.score


class TestInputValidation:
    def test_valid_text(self):
        ok, err = validate_input_text("Hello, this is a block of text to encrypt.")
        assert ok
        assert err == ""

    def test_empty_text(self):
        ok, err = validate_input_text("")
        assert not ok
        assert "empty" in err.lower()

    def test_multiline_text(self):
        text = "Line 1\nLine 2\nLine 3\n" * 100
        ok, err = validate_input_text(text)
        assert ok

    def test_unicode_text(self):
        ok, _ = validate_input_text("Unicode: \u00e9\u00e8\u00ea \u00fc\u00f6\u00e4 \u4e16\u754c \U0001f512")
        assert ok

    def test_oversized_text(self):
        huge = "x" * (11 * 1024 * 1024)  # 11 MiB
        ok, err = validate_input_text(huge)
        assert not ok
        assert "10 MiB" in err
