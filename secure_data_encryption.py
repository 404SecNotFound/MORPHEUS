#!/usr/bin/env python3
"""
SecureDataEncryption — entry point.

Launches the modern TUI by default.
Pass --cli for command-line mode, or any CLI flags to auto-detect.

Usage:
    python secure_data_encryption.py            # Launch GUI
    python secure_data_encryption.py --cli      # Launch CLI interactive mode
    python secure_data_encryption.py -o encrypt # CLI with flags
"""

from secure_encryption.__main__ import main

if __name__ == "__main__":
    main()
