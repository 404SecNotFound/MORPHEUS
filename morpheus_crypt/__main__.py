"""
Entry point for `python -m morpheus_crypt`, and for the `morpheus` command.

The module path and the command name differ on purpose: the import package is
`morpheus_crypt` because the `morpheus` name on PyPI belongs to someone else,
while the command users type is unchanged.

Launches the GUI (TUI) by default, or CLI mode when any flags are given.
"""

from __future__ import annotations

import os
import sys

from .core.errors import MorpheusError


def main():
    # Any command-line argument (beyond the program name) implies CLI mode.
    # The GUI is only launched for bare `python -m morpheus` / `morpheus`.
    #
    # Everything runs under one handler. A raw traceback tells the user
    # nothing they can act on and discloses absolute install paths; several
    # reachable inputs (a binary file passed to --inspect, an empty --data on
    # a closed stdin) used to produce exactly that.
    try:
        if len(sys.argv) > 1:
            from .cli import run_cli
            run_cli()
        else:
            from .gui import run_gui
            run_gui()
    except KeyboardInterrupt:
        # Ctrl-C at a password prompt is a normal way to leave.
        print("\nCancelled.", file=sys.stderr)
        sys.exit(130)  # 128 + SIGINT, the shell convention
    except MorpheusError as exc:
        # Raised deliberately by our own code, so the message is the point.
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except (BrokenPipeError, EOFError) as exc:
        # `... | head` closes the pipe; a closed stdin ends a prompt early.
        print(f"Error: input or output ended unexpectedly ({type(exc).__name__}).",
              file=sys.stderr)
        sys.exit(1)
    except Exception as exc:  # noqa: BLE001 - deliberate catch-all at the boundary
        print(
            f"Error: unexpected failure: {type(exc).__name__}: {exc}\n"
            "This is a bug. Re-run with MORPHEUS_DEBUG=1 for a full traceback.",
            file=sys.stderr,
        )
        if os.environ.get("MORPHEUS_DEBUG"):
            raise
        sys.exit(1)


if __name__ == "__main__":
    main()
