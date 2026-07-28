"""Guards for the terminal visual system (docs/design/2026-07-28-terminal-visual-system.md)."""

import re
from pathlib import Path

from morpheus.ui import theme

# theme.py's own source, read once at import rather than per call.
#
# The CSS guards below need the token NAMES, which survive only in the source:
# WIZARD_CSS is assembled by string concatenation, so as a value it holds
# resolved hex and the names are gone. Matching hex instead would not work
# either, because SELECTED and BORDER_FOCUS are both #ecebe6, and hex cannot
# tell a selection from a focus ring.
_THEME_SOURCE = Path(theme.__file__).read_text(encoding="utf-8")

# Scope the scan to the CSS literal. The token definition block sits above it
# and mentions every name legitimately, which would otherwise read as usage.
_CSS_SOURCE = _THEME_SOURCE.partition("WIZARD_CSS = ")[2]

# The spec pins an exact value for each token. Kept module level so the value
# test and the completeness check share one source of truth.
SPEC_TOKENS = {
    "BG": "#0e0e11", "BORDER": "#212124", "BORDER_STRONG": "#303032",
    "BORDER_FOCUS": "#ecebe6", "TEXT": "#f1f0ec", "TEXT_2": "#a3a29b",
    "TEXT_3": "#8f8d84", "TEXT_4": "#5f5e58", "SELECTED": "#ecebe6",
    "SIGNAL": "#f4b23e", "ERROR": "#e5594f",
}


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


def rules_using(token_name):
    """Yield (selector, declaration) pairs for CSS rules referencing a token.

    Matches the token name on word boundaries rather than the literal spelling
    with surrounding spaces. Removing those spaces is identical Python, so a
    substring match would let a real violation through unseen.
    """
    selector = "?"
    for line in _CSS_SOURCE.splitlines():
        stripped = line.strip()
        if stripped.endswith("{"):
            selector = stripped[:-1].strip()
        elif re.search(rf"\b{token_name}\b", line):
            yield selector, stripped


class TestPaletteContrast:
    def test_every_text_token_passes_aa_against_the_background(self):
        for name in sorted(theme.TEXT_TOKENS):
            value = getattr(theme, name)
            ratio = contrast(value, theme.BG)
            assert ratio >= 4.5, f"{name} ({value}) is {ratio:.2f}:1 on BG, needs >= 4.5"

    def test_text_4_fails_aa_and_is_excluded_from_the_text_token_list(self):
        """TEXT_4 failing AA is deliberate, not a bug to fix by brightening it.

        It is therefore kept out of TEXT_TOKENS, which bounds it to decoration
        and non-focusable disabled controls rather than informational text.
        """
        assert contrast(theme.TEXT_4, theme.BG) < 4.5
        assert "TEXT_4" not in theme.TEXT_TOKENS


class TestTokenValues:
    def test_every_token_matches_the_spec_value(self):
        actual = {name: getattr(theme, name) for name in SPEC_TOKENS}
        assert actual == SPEC_TOKENS

        declared = {
            name
            for name, value in vars(theme).items()
            if name.isupper() and isinstance(value, str) and value.startswith("#")
        }
        assert declared == set(SPEC_TOKENS), (
            "theme.py's colour tokens have drifted from the spec: "
            f"{sorted(declared ^ set(SPEC_TOKENS))}"
        )


class TestRestrictedTokenUsage:
    """Which selectors may reference the two restricted tokens.

    SIGNAL marks exposed secret material and nothing else; TEXT_4 is below AA
    and must not render informational text. The first test guards the parser
    itself, since a parser that silently matches nothing would make both rules
    pass while checking nothing.
    """

    SIGNAL_SELECTORS = {"#output-area", "#countdown-label"}

    # Two sanctioned TEXT_4 sites, for different reasons:
    #   .section-divider    decoration, a rule glyph rather than a string
    #   #btn-next:disabled  non-focusable disabled control, WCAG 1.4.3 exempt
    TEXT_4_SELECTORS = {".section-divider", "#btn-next:disabled"}

    def test_the_parser_actually_matches_something(self):
        assert list(rules_using("SIGNAL")), "SIGNAL parser matched nothing"
        assert list(rules_using("TEXT_4")), "TEXT_4 parser matched nothing"

    def test_signal_appears_only_on_the_allowed_selectors(self):
        offenders = [
            f"{sel}: {decl}"
            for sel, decl in rules_using("SIGNAL")
            if sel not in self.SIGNAL_SELECTORS
        ]
        assert not offenders, (
            "amber is reserved for exposed secret material:\n  "
            + "\n  ".join(offenders)
        )

    def test_text_4_renders_no_informational_text(self):
        offenders = [
            f"{sel}: {decl}"
            for sel, decl in rules_using("TEXT_4")
            if decl.startswith("color:") and sel not in self.TEXT_4_SELECTORS
        ]
        ratio = contrast(theme.TEXT_4, theme.BG)
        assert not offenders, (
            f"TEXT_4 is {ratio:.2f}:1 and must not render informational text:\n  "
            + "\n  ".join(offenders)
        )


class TestAllColoursGoThroughTokens:
    """theme.py's token block is the only place a colour may be a literal.

    The other guards match token names, so a raw hex literal bypasses them all.
    """

    def test_no_hex_literals_outside_the_token_block(self):
        pkg = Path(__file__).resolve().parent.parent / "morpheus"
        offenders = []
        for path in sorted(pkg.rglob("*.py")):
            source = path.read_text()
            if path.name == "theme.py":
                # The token block legitimately defines the palette.
                source = source.partition("WIZARD_CSS = ")[2]
            for match in re.findall(r"#[0-9A-Fa-f]{6}\b", source):
                offenders.append(f"{path.relative_to(pkg.parent)}: {match}")
        assert not offenders, (
            "colours must come from theme tokens, not hex literals:\n  "
            + "\n  ".join(offenders)
        )
