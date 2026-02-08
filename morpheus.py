#!/usr/bin/env python3
"""
MORPHEUS — entry point.

Launches the modern TUI by default.
Pass --cli for command-line mode, or any CLI flags to auto-detect.

Usage:
    python morpheus.py            # Launch GUI
    python morpheus.py --cli      # Launch CLI interactive mode
    python morpheus.py -o encrypt # CLI with flags
"""

from morpheus.__main__ import main

if __name__ == "__main__":
    main()
