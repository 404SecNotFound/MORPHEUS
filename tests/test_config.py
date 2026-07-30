"""Tests for persistent preferences (config.toml)."""

import os
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from morpheus_crypt.core.config import (
    load_config,
    save_config,
)


class TestSaveLoadConfig:
    """Test config save/load roundtrip."""

    def test_save_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            with patch("morpheus_crypt.core.config._CONFIG_DIR", Path(tmpdir)), \
                 patch("morpheus_crypt.core.config._CONFIG_FILE", cfg_file):
                settings = {
                    "cipher": "ChaCha20-Poly1305",
                    "kdf": "Scrypt",
                    "chain": True,
                    "pad": True,
                }
                save_config(settings)
                loaded = load_config()
                assert loaded["cipher"] == "ChaCha20-Poly1305"
                assert loaded["kdf"] == "Scrypt"
                assert loaded["chain"] is True
                assert loaded["pad"] is True

    def test_missing_file_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "nonexistent" / "config.toml"
            with patch("morpheus_crypt.core.config._CONFIG_FILE", cfg_file):
                assert load_config() == {}

    def test_invalid_keys_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            cfg_file.write_text('unknown_key = "value"\ncipher = "AES-256-GCM"\n')
            with patch("morpheus_crypt.core.config._CONFIG_FILE", cfg_file):
                loaded = load_config()
                assert "unknown_key" not in loaded
                assert loaded["cipher"] == "AES-256-GCM"

    def test_invalid_cipher_value_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            cfg_file.write_text('cipher = "InvalidCipher"\nkdf = "Argon2id"\n')
            with patch("morpheus_crypt.core.config._CONFIG_FILE", cfg_file):
                loaded = load_config()
                assert "cipher" not in loaded
                assert loaded["kdf"] == "Argon2id"

    def test_boolean_parsing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            cfg_file.write_text("chain = true\npad = false\nfixed_size = yes\n")
            with patch("morpheus_crypt.core.config._CONFIG_FILE", cfg_file):
                loaded = load_config()
                assert loaded["chain"] is True
                assert loaded["pad"] is False
                assert loaded["fixed_size"] is True

    def test_comments_and_empty_lines_ignored(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            cfg_file.write_text("# comment\n\ncipher = \"AES-256-GCM\"\n# another\n")
            with patch("morpheus_crypt.core.config._CONFIG_FILE", cfg_file):
                loaded = load_config()
                assert loaded["cipher"] == "AES-256-GCM"

    @pytest.mark.skipif(
        os.name != "posix",
        reason="POSIX file modes; on Windows os.chmod only sets the read-only "
               "attribute, so the file reports 0o666 and protection comes from "
               "inherited NTFS ACLs instead. Documented in SECURITY.md",
    )
    def test_file_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            with patch("morpheus_crypt.core.config._CONFIG_DIR", Path(tmpdir)), \
                 patch("morpheus_crypt.core.config._CONFIG_FILE", cfg_file):
                save_config({"cipher": "AES-256-GCM"})
                mode = oct(os.stat(cfg_file).st_mode & 0o777)
                assert mode == "0o600"


class TestSecuritySettingsAreNotPersistable:
    """Settings that change security behaviour must not live in a config file.

    A config file is a soft target: nothing prompts about it and nothing used
    to announce it. `passphrase` swaps the password policy for a weaker
    word-based one, and `check_leaks` sends a hash of every password to a
    third party. Both stay available as explicit CLI flags.

    Precedence itself is now argparse's job (``parser.set_defaults`` before
    ``parse_args``) and is covered end-to-end by
    ``tests/test_cli.py::TestConfigPrecedence``.
    """

    def test_planted_security_keys_are_ignored_on_load(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            cfg_file.write_text(
                "passphrase = true\ncheck_leaks = true\ncipher = \"Scrypt\"\n"
                "chain = true\n"
            )
            with patch("morpheus_crypt.core.config._CONFIG_FILE", cfg_file):
                loaded = load_config()
            assert "passphrase" not in loaded
            assert "check_leaks" not in loaded
            # A legitimate key from the same file still loads, so this test
            # cannot pass merely because parsing failed outright.
            assert loaded["chain"] is True

    def test_they_are_not_written_even_if_passed_to_save(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            with patch("morpheus_crypt.core.config._CONFIG_DIR", Path(tmpdir)), \
                 patch("morpheus_crypt.core.config._CONFIG_FILE", cfg_file):
                save_config({
                    "cipher": "AES-256-GCM",
                    "passphrase": True,
                    "check_leaks": True,
                })
            written = cfg_file.read_text(encoding="utf-8")
            assert "passphrase" not in written
            assert "check_leaks" not in written
            assert "cipher" in written
