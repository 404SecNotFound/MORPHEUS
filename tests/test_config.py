"""Tests for persistent preferences (config.toml)."""

import argparse
import os
import tempfile
from pathlib import Path
from unittest.mock import patch

from morpheus.core.config import (
    apply_config_defaults,
    load_config,
    save_config,
)


class TestSaveLoadConfig:
    """Test config save/load roundtrip."""

    def test_save_and_load_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            with patch("morpheus.core.config._CONFIG_DIR", Path(tmpdir)), \
                 patch("morpheus.core.config._CONFIG_FILE", cfg_file):
                settings = {
                    "cipher": "ChaCha20-Poly1305",
                    "kdf": "Scrypt",
                    "chain": True,
                    "pad": True,
                    "passphrase": True,
                }
                save_config(settings)
                loaded = load_config()
                assert loaded["cipher"] == "ChaCha20-Poly1305"
                assert loaded["kdf"] == "Scrypt"
                assert loaded["chain"] is True
                assert loaded["pad"] is True
                assert loaded["passphrase"] is True

    def test_missing_file_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "nonexistent" / "config.toml"
            with patch("morpheus.core.config._CONFIG_FILE", cfg_file):
                assert load_config() == {}

    def test_invalid_keys_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            cfg_file.write_text('unknown_key = "value"\ncipher = "AES-256-GCM"\n')
            with patch("morpheus.core.config._CONFIG_FILE", cfg_file):
                loaded = load_config()
                assert "unknown_key" not in loaded
                assert loaded["cipher"] == "AES-256-GCM"

    def test_invalid_cipher_value_skipped(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            cfg_file.write_text('cipher = "InvalidCipher"\nkdf = "Argon2id"\n')
            with patch("morpheus.core.config._CONFIG_FILE", cfg_file):
                loaded = load_config()
                assert "cipher" not in loaded
                assert loaded["kdf"] == "Argon2id"

    def test_boolean_parsing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            cfg_file.write_text("chain = true\npad = false\nfixed_size = yes\ncheck_leaks = 0\n")
            with patch("morpheus.core.config._CONFIG_FILE", cfg_file):
                loaded = load_config()
                assert loaded["chain"] is True
                assert loaded["pad"] is False
                assert loaded["fixed_size"] is True
                assert loaded["check_leaks"] is False

    def test_comments_and_empty_lines_ignored(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            cfg_file.write_text("# comment\n\ncipher = \"AES-256-GCM\"\n# another\n")
            with patch("morpheus.core.config._CONFIG_FILE", cfg_file):
                loaded = load_config()
                assert loaded["cipher"] == "AES-256-GCM"

    def test_file_permissions(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            cfg_file = Path(tmpdir) / "config.toml"
            with patch("morpheus.core.config._CONFIG_DIR", Path(tmpdir)), \
                 patch("morpheus.core.config._CONFIG_FILE", cfg_file):
                save_config({"cipher": "AES-256-GCM"})
                mode = oct(os.stat(cfg_file).st_mode & 0o777)
                assert mode == "0o600"


class TestApplyConfigDefaults:
    """Test that config defaults are applied correctly to argparse namespace."""

    def test_config_fills_unset_values(self):
        args = argparse.Namespace(
            cipher="AES-256-GCM",  # argparse default
            kdf="Argon2id",  # argparse default
            chain=False,
            pad=False,
            passphrase=False,
        )
        config = {"cipher": "ChaCha20-Poly1305", "chain": True}
        apply_config_defaults(args, config)
        assert args.cipher == "ChaCha20-Poly1305"
        assert args.chain is True

    def test_cli_overrides_config(self):
        args = argparse.Namespace(
            cipher="ChaCha20-Poly1305",  # user explicitly chose this
            kdf="Argon2id",
            chain=True,  # user explicitly set this
            pad=False,
        )
        config = {"cipher": "AES-256-GCM", "chain": False, "pad": True}
        apply_config_defaults(args, config)
        # cipher was explicitly set to non-default, so it stays
        assert args.cipher == "ChaCha20-Poly1305"
        # chain was explicitly set to True, so config's False doesn't override
        assert args.chain is True
        # pad was not set by user (False), so config's True applies
        assert args.pad is True

    def test_empty_config_no_changes(self):
        args = argparse.Namespace(cipher="AES-256-GCM", kdf="Argon2id", chain=False)
        apply_config_defaults(args, {})
        assert args.cipher == "AES-256-GCM"
        assert args.chain is False
