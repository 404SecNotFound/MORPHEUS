#!/usr/bin/env python3
"""Print the WCAG contrast table for the MORPHEUS palette.

Usage: python scripts/check_contrast.py
Exits non-zero if any token used for text falls below AA on any surface it can
be painted on.

Every surface, not just BG. Checking one background answered the real question
only while there was one, and the moment the current-step row fill arrived that
stopped being true without the check failing, which is the dangerous shape for
a guard. Walking the product caught a candidate fill that put ERROR at 4.43:1.
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
    for surface_name in sorted(theme.SURFACE_TOKENS):
        surface = getattr(theme, surface_name)
        print(f"Palette contrast on {surface_name} {surface}\n")
        for name in sorted(theme.TEXT_TOKENS):
            value = getattr(theme, name)
            ratio = contrast(value, surface)
            mark = grade(ratio)
            if ratio < 4.5:
                failures += 1
                mark += "  <-- below AA"
            print(f"  {name:14} {value}  {ratio:6.2f}:1  {mark}")

        print(f"\n  {'TEXT_4':14} {theme.TEXT_4}  "
              f"{contrast(theme.TEXT_4, surface):6.2f}:1  "
              f"decoration and disabled controls only\n")

    # How far the surfaces sit apart, which is the number that decides whether
    # a fill can carry meaning on its own. It cannot: see the design note in
    # theme.py. Printed so the next person does not have to rediscover it.
    print(f"Surface separation {theme.SURFACE_CURRENT} vs {theme.BG}: "
          f"{contrast(theme.SURFACE_CURRENT, theme.BG):.2f}:1")
    print(f"Accent glyph {theme.ACCENT} on {theme.BG}: "
          f"{contrast(theme.ACCENT, theme.BG):.2f}:1  <- what marks the row")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
