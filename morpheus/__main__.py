"""
Entry point for `python -m morpheus`.

Launches the GUI (TUI) by default, or CLI mode when any flags are given.
"""

from __future__ import annotations

import sys


def main():
    # Any command-line argument (beyond the program name) implies CLI mode.
    # The GUI is only launched for bare `python -m morpheus` / `morpheus`.
    if len(sys.argv) > 1:
        from .cli import run_cli
        run_cli()
    else:
        from .gui import run_gui
        run_gui()


if __name__ == "__main__":
    main()
