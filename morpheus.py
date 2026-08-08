#!/usr/bin/env python3
"""
MORPHEUS entry point.

The reference implementation of the ciphertext format specified in
docs/FORMAT.md. A bare invocation prints the help.

Usage:
    python morpheus.py -o encrypt --data "secret"
    python morpheus.py --help      # Every flag, with worked examples
"""

from morpheus_crypt.__main__ import main

if __name__ == "__main__":
    main()
