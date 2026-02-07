"""Tests for CLI file encryption/decryption."""

import os
import tempfile

import pytest

from secure_encryption.cli import run_cli


class TestFileEncryption:
    """Test the -f/--file flag for file-based encrypt/decrypt."""

    def test_file_encrypt_decrypt_roundtrip(self):
        """Encrypt a file and decrypt it back to the original."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a test file
            original = os.path.join(tmpdir, "secret.txt")
            with open(original, "w") as f:
                f.write("Top secret contents\nLine 2\n")

            encrypted = os.path.join(tmpdir, "secret.txt.enc")

            # Encrypt (password via stdin)
            import io
            import sys

            # Simulate interactive password input
            old_stdin = sys.stdin
            sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\n")

            try:
                run_cli([
                    "-o", "encrypt",
                    "-f", original,
                    "--output", encrypted,
                ])
            finally:
                sys.stdin = old_stdin

            assert os.path.exists(encrypted)

            # Decrypt
            decrypted = os.path.join(tmpdir, "decrypted.txt")
            sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\n")

            try:
                run_cli([
                    "-o", "decrypt",
                    "-f", encrypted,
                    "--output", decrypted,
                ])
            finally:
                sys.stdin = old_stdin

            assert os.path.exists(decrypted)
            with open(decrypted, "r") as f:
                content = f.read()
            assert content == "Top secret contents\nLine 2\n"

    def test_file_binary_roundtrip(self):
        """Encrypt and decrypt a binary file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            original = os.path.join(tmpdir, "data.bin")
            binary_data = os.urandom(1024)
            with open(original, "wb") as f:
                f.write(binary_data)

            encrypted = os.path.join(tmpdir, "data.bin.enc")

            import io
            import sys

            old_stdin = sys.stdin
            sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\n")
            try:
                run_cli(["-o", "encrypt", "-f", original, "--output", encrypted])
            finally:
                sys.stdin = old_stdin

            assert os.path.exists(encrypted)

            decrypted = os.path.join(tmpdir, "data_out.bin")
            sys.stdin = io.StringIO("T3st!Passw0rd#Str0ng\n")
            try:
                run_cli(["-o", "decrypt", "-f", encrypted, "--output", decrypted])
            finally:
                sys.stdin = old_stdin

            with open(decrypted, "rb") as f:
                result = f.read()
            assert result == binary_data
