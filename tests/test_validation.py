"""Tests for password validation and input checking."""

from unittest.mock import patch, MagicMock

from morpheus.core.validation import (
    check_passphrase_strength,
    check_password_leaked,
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


class TestPassphraseStrength:
    """Tests for passphrase-mode validation."""

    def test_strong_passphrase_accepted(self):
        result = check_passphrase_strength("correct horse battery staple")
        assert result.is_acceptable
        assert result.score >= 50

    def test_five_word_passphrase(self):
        result = check_passphrase_strength("the quick brown fox jumped")
        assert result.is_acceptable
        assert result.score >= 60

    def test_seven_word_excellent(self):
        result = check_passphrase_strength("alpha bravo charlie delta echo foxtrot golf")
        assert result.is_acceptable
        assert result.label in ("Strong", "Excellent")

    def test_too_few_words_rejected(self):
        result = check_passphrase_strength("only two")
        assert not result.is_acceptable
        assert any("4 words" in f for f in result.feedback)

    def test_three_words_rejected(self):
        result = check_passphrase_strength("three word pass")
        assert not result.is_acceptable

    def test_too_short_rejected(self):
        result = check_passphrase_strength("a b c d e f g h")
        assert not result.is_acceptable
        assert any("20 characters" in f for f in result.feedback)

    def test_empty_passphrase(self):
        result = check_passphrase_strength("")
        assert not result.is_acceptable
        assert result.score == 0

    def test_hyphen_separated(self):
        result = check_passphrase_strength("correct-horse-battery-staple")
        assert result.is_acceptable

    def test_underscore_separated(self):
        result = check_passphrase_strength("correct_horse_battery_staple")
        assert result.is_acceptable

    def test_repeated_words_lower_score(self):
        r1 = check_passphrase_strength("word word word word word word")
        r2 = check_passphrase_strength("alpha bravo charlie delta echo foxtrot")
        assert r2.score > r1.score

    def test_no_special_chars_required(self):
        """Passphrase mode should NOT require digits or special characters."""
        result = check_passphrase_strength("correct horse battery staple")
        assert result.is_acceptable
        # Verify no feedback about digits/special chars
        for f in result.feedback:
            assert "digit" not in f.lower()
            assert "special" not in f.lower()


class TestPasswordLeakCheck:
    """Tests for HIBP breach detection (mocked network)."""

    def test_leaked_password_detected(self):
        """A password found in the breach database returns (True, count)."""
        # SHA-1 of "password" = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        fake_response = (
            "1D2DA4053E34E76F6576ED1DA63134B5E2A:2\r\n"
            "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\n"
            "1F2B668E8AABEF1C59E7B6D4A0F0E3B2C1D:5\r\n"
        )
        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_response.encode("utf-8")
        with patch("morpheus.core.validation.urllib.request.urlopen", return_value=mock_resp):
            is_leaked, count = check_password_leaked("password")
        assert is_leaked
        assert count == 3861493

    def test_safe_password_not_flagged(self):
        """A password not in the breach database returns (False, 0)."""
        fake_response = (
            "0000000000000000000000000000000000A:1\r\n"
            "0000000000000000000000000000000000B:2\r\n"
        )
        mock_resp = MagicMock()
        mock_resp.read.return_value = fake_response.encode("utf-8")
        with patch("morpheus.core.validation.urllib.request.urlopen", return_value=mock_resp):
            is_leaked, count = check_password_leaked("xK9!mZ2@qY3#nW$vB8")
        assert not is_leaked
        assert count == 0

    def test_network_error_propagates(self):
        """Network errors should propagate so the caller can handle them."""
        import urllib.error
        with patch(
            "morpheus.core.validation.urllib.request.urlopen",
            side_effect=urllib.error.URLError("no network"),
        ):
            try:
                check_password_leaked("anything")
                assert False, "Should have raised"
            except urllib.error.URLError:
                pass  # expected
