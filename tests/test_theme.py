"""Guards for the terminal visual system (docs/design/2026-07-28-terminal-visual-system.md)."""

import math
import re
from pathlib import Path

import pytest

from morpheus.ui import theme
from morpheus.ui.app import MorpheusWizard
from morpheus.ui.state import STEP_OUTPUT, TOTAL_STEPS, Mode

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


def _rgb(hex_colour: str) -> tuple[int, int, int]:
    h = hex_colour.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def rgb_distance(a: str, b: str) -> float:
    """Plain Euclidean RGB distance. Crude, but enough to catch 'looks amber'."""
    return math.dist(_rgb(a), _rgb(b))


def fills_on_rendered_glyphs(svg: str) -> set[str]:
    """Every colour that actually paints a visible character in an exported SVG.

    Scoped to the terminal matrix, so the fake window chrome Textual draws
    around the screenshot (title bar, traffic lights) is not mistaken for app
    output.
    """
    class_fill = dict(
        re.findall(r"\.(terminal-\d+-r\d+)\s*\{[^}]*?fill:\s*(#[0-9A-Fa-f]{6})", svg)
    )
    body = svg.partition("-matrix")[2]
    used = set()
    for cls, text in re.findall(
        r'<text[^>]*class="(terminal-\d+-r\d+)"[^>]*>(.*?)</text>', body, re.S
    ):
        if text.replace("&#160;", " ").strip():
            used.add(class_fill.get(cls, ""))
    return {colour for colour in used if colour}


class TestRenderedAmberIsReserved:
    """The source-level guards cannot see colour that Textual supplies itself.

    `test_signal_appears_only_on_the_allowed_selectors` matches the token name
    SIGNAL in theme.py. Textual's default footer key cap is #ffa62b, which is
    neither the string "SIGNAL" nor the hex #f4b23e, so it passed every guard
    while sitting on all six screens. It is perceptually amber, and the design
    rests on amber meaning exposed secret material, so it broke the rule the
    guards exist to protect. This one renders the app and asserts on pixels.

    Checking theme.py's CSS instead would not have caught it: the colour was
    never in our stylesheet.
    """

    # #ffa62b, the regression this test exists for, is 25.0 from SIGNAL.
    # ERROR is the nearest legitimate token at 91.8. 50 separates them with
    # roughly 2x margin either side.
    NEAR_DISTANCE = 50.0

    async def _render_steps(self) -> dict[int, set[str]]:
        app = MorpheusWizard()
        rendered = {}
        async with app.run_test(size=(110, 38)) as pilot:
            app._state.mode = Mode.ENCRYPT
            app._state.input_text = "review canary"
            app._state.password = "T3st!Passw0rd#Str0ng"
            app._state.password_confirm = "T3st!Passw0rd#Str0ng"
            app._state.output = "MORPHEUS-v1:c2FtcGxlIGNpcGhlcnRleHQ="
            app._state.completed_steps.add(STEP_OUTPUT)
            for index in range(TOTAL_STEPS):
                app._goto_step(index)
                await pilot.pause()
                assert app._current_step == index, (
                    f"step {index + 1} was refused; the guard would silently "
                    f"check step {app._current_step + 1} twice"
                )
                rendered[index] = fills_on_rendered_glyphs(app.export_screenshot())
        return rendered

    def test_the_distance_threshold_separates_the_regression_from_the_palette(self):
        """Pin the threshold, so widening it later is a visible decision."""
        assert rgb_distance("#ffa62b", theme.SIGNAL) < self.NEAR_DISTANCE
        assert rgb_distance(theme.ERROR, theme.SIGNAL) > self.NEAR_DISTANCE

    @pytest.mark.asyncio
    async def test_no_near_amber_renders_outside_the_output_step(self):
        rendered = await self._render_steps()

        offenders = []
        for index in range(STEP_OUTPUT):
            for colour in sorted(rendered[index]):
                distance = rgb_distance(colour, theme.SIGNAL)
                if distance < self.NEAR_DISTANCE:
                    offenders.append(
                        f"step {index + 1}: {colour} is {distance:.1f} from SIGNAL"
                    )
        assert not offenders, (
            "amber is reserved for exposed secret material, and these render "
            "close enough to read as amber:\n  " + "\n  ".join(offenders)
        )

    @pytest.mark.asyncio
    async def test_the_output_step_uses_the_signal_token_itself(self):
        """Step 6 may show amber, but only the real token, and it must show it.

        The second half matters: without it this whole class passes when the
        output step renders no amber at all, which is what happened when the
        screenshot script silently captured step 5 twice.
        """
        rendered = await self._render_steps()
        near = {
            colour
            for colour in rendered[STEP_OUTPUT]
            if rgb_distance(colour, theme.SIGNAL) < self.NEAR_DISTANCE
        }
        assert near == {theme.SIGNAL}, (
            f"the output step should render SIGNAL ({theme.SIGNAL}) and no "
            f"other near-amber; got {sorted(near) or 'no amber at all'}"
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
