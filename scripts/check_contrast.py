#!/usr/bin/env python3
"""Print the WCAG contrast table for the MORPHEUS palette.

Usage: python scripts/check_contrast.py
Exits non-zero if any token used for text falls below AA on the background.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from morpheus_crypt.ui import theme  # noqa: E402


def _linear(channel: float) -> float:
    c = channel / 255.0
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def luminance(hex_colour: str) -> float:
    h = hex_colour.lstrip("#")
    r, g, b = (int(h[i:i + 2], 16) for i in (0, 2, 4))
    return 0.2126 * _linear(r) + 0.7152 * _linear(g) + 0.0722 * _linear(b)


def contrast(fg: str, bg: str) -> float:
    a, b = luminance(fg), luminance(bg)
    hi, lo = max(a, b), min(a, b)
    return (hi + 0.05) / (lo + 0.05)


def grade(ratio: float) -> str:
    if ratio >= 7:
        return "AAA"
    if ratio >= 4.5:
        return "AA"
    if ratio >= 3:
        return "AA-large"
    return "FAIL"


def main() -> int:
    failures = 0
    print(f"Palette contrast against BG {theme.BG}\n")
    for name in sorted(theme.TEXT_TOKENS):
        value = getattr(theme, name)
        ratio = contrast(value, theme.BG)
        mark = grade(ratio)
        if ratio < 4.5:
            failures += 1
            mark += "  <-- below AA"
        print(f"  {name:14} {value}  {ratio:6.2f}:1  {mark}")

    print(f"\n  {'TEXT_4':14} {theme.TEXT_4}  "
          f"{contrast(theme.TEXT_4, theme.BG):6.2f}:1  "
          f"decoration and disabled controls only")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
