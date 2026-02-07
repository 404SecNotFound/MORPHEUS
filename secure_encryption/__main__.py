"""
Entry point for `python -m secure_encryption`.

Launches the GUI (TUI) by default, or CLI mode with --cli flag.
"""

from __future__ import annotations

import sys


def main():
    if "--cli" in sys.argv:
        sys.argv.remove("--cli")
        from .cli import run_cli
        run_cli()
    elif len(sys.argv) > 1 and sys.argv[1] in ("-o", "--operation", "-h", "--help",
                                                  "--generate-keypair", "--cipher",
                                                  "--kdf", "--chain", "--hybrid-pq",
                                                  "-f", "--file"):
        # Auto-detect CLI mode from flags
        from .cli import run_cli
        run_cli()
    else:
        from .gui import run_gui
        run_gui()


if __name__ == "__main__":
    main()
