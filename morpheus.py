#!/usr/bin/env python3
"""
MORPHEUS — entry point.

Launches the TUI wizard when given no arguments. Passing any flag runs the
command-line interface instead — there is no separate mode switch.

Usage:
    python morpheus.py             # Launch the wizard
    python morpheus.py -o encrypt --data "secret"
    python morpheus.py --help      # Every flag, with worked examples
"""

from morpheus.__main__ import main

if __name__ == "__main__":
    main()
