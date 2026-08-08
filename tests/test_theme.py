"""Guards for the terminal visual system.

Current spec: docs/design/2026-08-05-terminal-visual-system-v2.md, which
supersedes the 2026-07-28 document for token values and sidebar styling.
"""

import math
import re
from pathlib import Path
from typing import NamedTuple

import pytest
from textual.widgets import Checkbox

from morpheus_crypt.ui import sidebar, theme
from morpheus_crypt.ui.app import MorpheusWizard
from morpheus_crypt.ui.state import STEP_OUTPUT, STEP_PASSWORD, TOTAL_STEPS, Mode
from tests.support import settle

# The spec pins an exact value for each token, and the CSS variable each token
# is published as. Kept module level so the value test, the completeness check
# and the CSS guards below share one source of truth.
#
# The guards need token NAMES, not values: SELECTED and BORDER_FOCUS are both
# #ecebe6, and hex cannot tell a selection from a focus ring. The stylesheet
# names its colours as Textual variables, so the names are present in
# WIZARD_CSS itself and these guards parse real CSS. They used to parse
# theme.py's source text and reconstruct string concatenation, which was blind
# to `"""+SIGNAL+"""` written without spaces and named the wrong selector for
# several ordinary reformattings.
SPEC_TOKENS = {
    "BG": "#0e0e11", "SURFACE_CURRENT": "#1c1e24",
    "BORDER": "#212124", "BORDER_STRONG": "#303032",
    "BORDER_FOCUS": "#ecebe6", "TEXT": "#f1f0ec", "TEXT_2": "#a3a29b",
    "TEXT_3": "#8f8d84", "TEXT_4": "#5f5e58", "SELECTED": "#ecebe6",
    "SIGNAL": "#f4b23e", "ERROR": "#e5594f", "ACCENT": "#4bb3d4",
}

# Python token name -> the CSS variable it is published as. The `m-` prefix is
# load-bearing: Textual 8.2.8 defines $text, $border and $error itself, so the
# unprefixed names would repoint every Textual widget rather than our own rules.
TOKEN_VARS = {
    "BG": "$m-bg", "SURFACE_CURRENT": "$m-surface-current",
    "BORDER": "$m-border", "BORDER_STRONG": "$m-border-strong",
    "BORDER_FOCUS": "$m-border-focus", "TEXT": "$m-text", "TEXT_2": "$m-text-2",
    "TEXT_3": "$m-text-3", "TEXT_4": "$m-text-4", "SELECTED": "$m-selected",
    "SIGNAL": "$m-signal", "ERROR": "$m-error",
}

# ACCENT has no CSS variable on purpose: it tints one glyph inside a row's text,
# which is Rich markup, not CSS. See the note in theme.py's _VARS block.
TOKENS_WITHOUT_CSS_VARS = {"ACCENT"}


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


def stylesheet_body(css: str = None) -> str:
    """WIZARD_CSS with the `$m-*: #hex;` declaration block taken out.

    Those lines are the one place a hex may appear and the one place a variable
    name is a definition rather than a use, so tests about the rules themselves
    look at what is left.
    """
    css = theme.WIZARD_CSS if css is None else css
    return re.sub(r"^\$[\w-]+:[^;]*;\n?", "", css, flags=re.M)


class Declaration(NamedTuple):
    """One `property: value` pair, attributed to one fully resolved selector."""

    selector: str
    prop: str
    value: str

    def __str__(self) -> str:
        return f"{self.selector} {{ {self.prop}: {self.value}; }}"


def _resolve(raw: str, parents: tuple[str, ...]) -> tuple[str, ...]:
    """Expand one selector list against its enclosing selectors.

    A grouped selector yields one entry per comma-separated part, so a
    declaration under `#output-area, #countdown-label` is attributed to both
    rather than to the literal string with the comma in it. A nested part
    containing `&` is substituted into the parent; one without is a descendant.
    """
    parts = [" ".join(part.split()) for part in raw.split(",")]
    parts = [part for part in parts if part]
    if not parents:
        return tuple(parts)
    return tuple(
        part.replace("&", parent) if "&" in part else f"{parent} {part}"
        for parent in parents
        for part in parts
    )


def declarations(css: str = None) -> list[Declaration]:
    """Parse the stylesheet into declarations, tracking nesting by brace depth.

    Counting braces rather than matching line shapes is what makes the guards
    survive reformatting. The previous parser read a line ending in `{` as a
    selector and everything else as a declaration, so a trailing comment after
    the brace, a brace on its own line, a declaration sharing the selector's
    line, a grouped selector or a nested block each silently misattributed the
    rules that followed.

    Declarations at depth 0 are the variable definitions themselves and are not
    usages, so they are skipped: `$m-signal: #f4b23e;` defines the accent, it
    does not spend it.
    """
    css = theme.WIZARD_CSS if css is None else css
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)  # comments are not usage

    found: list[Declaration] = []
    stack: list[tuple[str, ...]] = []
    buf: list[str] = []

    def flush() -> None:
        text = "".join(buf).strip()
        del buf[:]
        if not text or not stack:
            return
        prop, _, value = text.partition(":")
        for selector in stack[-1]:
            found.append(
                Declaration(selector, " ".join(prop.split()), " ".join(value.split()))
            )

    for char in css:
        if char == "{":
            raw = "".join(buf).strip()
            del buf[:]
            stack.append(_resolve(raw, stack[-1] if stack else ()))
        elif char == "}":
            flush()
            if stack:
                stack.pop()
        elif char == ";":
            flush()
        else:
            buf.append(char)

    if stack:
        raise AssertionError(f"unbalanced braces in WIZARD_CSS: {stack[-1]} left open")
    return found


def rules_using(token_name: str) -> list[Declaration]:
    """Every declaration whose value references the variable for a token.

    The variable name is matched with a trailing `(?![\\w-])` guard rather than
    `\\b`, because `\\b` treats the hyphen in `$m-text-2` as a boundary and would
    report every use of it as a use of `$m-text`.

    Spacing is irrelevant here: `color:$m-signal;` and `color: $m-signal;` parse
    to the same declaration, so the no-spaces spelling cannot slip past.
    """
    var = TOKEN_VARS[token_name]
    pattern = re.compile(rf"{re.escape(var)}(?![\w-])")
    return [decl for decl in declarations() if pattern.search(decl.value)]


def selectors_using(token_name: str) -> set[str]:
    return {decl.selector for decl in rules_using(token_name)}


class TestPaletteContrast:
    def test_every_text_token_passes_aa_on_every_surface(self):
        """Against each surface text can land on, not just against BG.

        This used to check `theme.BG` alone, which answered the real question
        only while there was one surface. Adding the current-step row fill made
        it insufficient without making it fail, which is the dangerous shape for
        a guard: still green, no longer sufficient.

        Extending it earned its place immediately. A candidate fill of #16242e
        put ERROR at 4.43:1, below AA, and the sweep for the lightest fill that
        keeps every token AA stopped at #1f2127 with ERROR on 4.50 exactly.
        SURFACE_CURRENT sits one step back from that edge.
        """
        failures = []
        for surface_name in sorted(theme.SURFACE_TOKENS):
            surface = getattr(theme, surface_name)
            for name in sorted(theme.TEXT_TOKENS):
                value = getattr(theme, name)
                ratio = contrast(value, surface)
                if ratio < 4.5:
                    failures.append(
                        f"{name} ({value}) is {ratio:.2f}:1 on "
                        f"{surface_name} ({surface}), needs >= 4.5"
                    )
        assert not failures, "\n".join(failures)

    def test_the_surface_list_covers_every_declared_background(self):
        """A surface added to the palette but not to SURFACE_TOKENS is unguarded.

        Without this, the contrast walk above silently stops covering the new
        one, which is exactly how the single-surface version of it went stale.
        """
        backgrounds = {
            name
            for name, value in vars(theme).items()
            if name.isupper() and isinstance(value, str) and value.startswith("#")
            and (name == "BG" or name.startswith("SURFACE"))
        }
        assert backgrounds == set(theme.SURFACE_TOKENS), (
            "a background token is not covered by the contrast guard: "
            f"{sorted(backgrounds ^ set(theme.SURFACE_TOKENS))}"
        )

    def test_text_4_fails_aa_and_is_excluded_from_the_text_token_list(self):
        """TEXT_4 failing AA is deliberate, not a bug to fix by brightening it.

        It is therefore kept out of TEXT_TOKENS, which bounds it to decoration
        and non-focusable disabled controls rather than informational text.
        """
        assert contrast(theme.TEXT_4, theme.BG) < 4.5
        assert "TEXT_4" not in theme.TEXT_TOKENS


class TestThePaletteSurvives256Colours:
    """Validated in truecolor, but the report came from a 256-colour terminal.

    The Raspberry Pi that prompted this revision runs `TERM=xterm-256color` with
    `COLORTERM` unset, so Rich quantises every token to the nearest of 256
    entries before it reaches the screen. Every ratio measured elsewhere in this
    file is therefore a ratio for a colour that terminal never shows.

    Quantisation moves things: TEXT_3 lands on #808080 and drops from 5.79:1 to
    4.74:1, and ERROR lands on #d75f5f. Both still clear AA, but neither does so
    by the margin the truecolor numbers suggest, and a future token chosen for a
    truecolor ratio could pass every other guard here while failing on the
    hardware that reported the bug.
    """

    @staticmethod
    def _as_256(value: str) -> str:
        from rich.color import Color, ColorSystem
        triplet = (Color.parse(value)
                   .downgrade(ColorSystem.EIGHT_BIT)
                   .get_truecolor())
        return f"#{triplet.red:02x}{triplet.green:02x}{triplet.blue:02x}"

    def test_every_text_token_still_passes_aa_once_quantised(self):
        background = self._as_256(theme.BG)
        failures = []
        for name in sorted(theme.TEXT_TOKENS):
            ratio = contrast(self._as_256(getattr(theme, name)), background)
            if ratio < 4.5:
                failures.append(f"{name} falls to {ratio:.2f}:1 at 256 colours")
        assert not failures, "\n".join(failures)

    # Pairs whose whole job is to be told apart. TEXT_3 serves both completed and
    # locked deliberately, so it is absent: those two are separated by marker, per
    # the spec's structure-first rule, not by colour.
    MUST_STAY_DISTINCT = [
        ("SELECTED", "TEXT_2"),   # current step label vs an available one
        ("TEXT_2", "TEXT_3"),     # available vs completed
        ("ACCENT", "SIGNAL"),     # "you are here" vs "secret material on screen"
        ("ACCENT", "ERROR"),
        ("SIGNAL", "ERROR"),
    ]

    @pytest.mark.parametrize("first,second", MUST_STAY_DISTINCT)
    def test_meaningful_pairs_do_not_collapse_onto_one_colour(self, first, second):
        a, b = getattr(theme, first), getattr(theme, second)
        assert self._as_256(a) != self._as_256(b), (
            f"{first} ({a}) and {second} ({b}) both quantise to "
            f"{self._as_256(a)} on a 256-colour terminal, so they carry the same "
            f"meaning to anyone reading one"
        )


class TestHierarchySurvivesWithoutColour:
    """The sidebar must stay readable when colour does not arrive.

    This exists because of a report from a Raspberry Pi 4 over SSH: "you cannot
    see the sections". The palette was not broken, every token passed AA. The
    sidebar simply expressed its states almost entirely through three warm greys
    sitting close together, and two of the states were styled identically.

    Contrast ratios cannot catch that, and neither can the rendered-palette pin:
    both would stay green while the list read as one undifferentiated block on a
    terminal that flattens colour. So the property asserted here is the one that
    actually matters, that state is legible with colour removed.
    """

    def test_the_four_step_states_use_four_distinct_markers(self):
        markers = [sidebar.STATE_MARKERS[s] for s in
                   (sidebar.CURRENT, sidebar.COMPLETED,
                    sidebar.AVAILABLE, sidebar.LOCKED)]
        assert len(set(markers)) == 4, (
            f"two step states share a marker ({markers}), so they are "
            f"indistinguishable once colour is gone"
        )

    def test_every_row_shows_its_step_number_in_every_state(self):
        """Keys 1-6 jump to a step, so hiding the number hides the affordance.

        Completed rows are the ones a user goes back through, which is exactly
        where dropping the number would cost most.
        """
        for state in (sidebar.CURRENT, sidebar.COMPLETED,
                      sidebar.AVAILABLE, sidebar.LOCKED):
            for step in range(sidebar.TOTAL_STEPS):
                text = sidebar.row_text(step, state)
                assert f" {step + 1} " in text, (
                    f"step {step + 1} in state {state!r} does not show its "
                    f"number: {text.splitlines()[0]!r}"
                )

    def test_stripping_colour_still_separates_the_states(self):
        """Belt and braces: render each state with markup removed and compare.

        The marker test above reads the table; this reads what a row actually
        produces, so re-pointing `row_text` at one glyph would fail here even if
        the table stayed diverse.
        """
        seen = {}
        for state in (sidebar.CURRENT, sidebar.COMPLETED,
                      sidebar.AVAILABLE, sidebar.LOCKED):
            plain = re.sub(r"\[/?[^\]]*\]", "", sidebar.row_text(0, state))
            first_line = plain.splitlines()[0]
            assert first_line not in seen, (
                f"states {seen[first_line]!r} and {state!r} render the same row "
                f"once colour is stripped: {first_line!r}"
            )
            seen[first_line] = state


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

    def test_the_css_variables_carry_the_token_values(self):
        """The variable block is generated, so this pins that it stays generated.

        Hand-editing a hex into the declarations would give the CSS a second
        source of truth that the Python constants no longer control, and every
        other guard here reads the constants.
        """
        declared = dict(re.findall(r"^(\$[\w-]+):\s*(#[0-9a-f]{6});$",
                                   theme.WIZARD_CSS, re.M))
        expected = {var: SPEC_TOKENS[name] for name, var in TOKEN_VARS.items()}
        assert declared == expected

    def test_the_stylesheet_body_contains_no_raw_hex(self):
        """Every colour in a rule goes through a variable, so the guards see it.

        A hex spliced straight into a declaration is invisible to every
        name-matching guard in this file, which is exactly how an accent
        violation would get through.
        """
        assert re.findall(r"#[0-9A-Fa-f]{6}\b", stylesheet_body()) == []

    def test_no_declared_variable_is_unused(self):
        """A variable nothing references is a token the guards cannot police."""
        body = stylesheet_body()
        unused = [
            var for var in TOKEN_VARS.values()
            if not re.search(rf"{re.escape(var)}(?![\w-])", body)
        ]
        assert unused == []

    def test_every_token_either_has_a_css_variable_or_is_listed_as_not_having_one(self):
        """No token may quietly drop out of the CSS guards.

        ACCENT legitimately has no variable, because it is applied as markup on a
        glyph. That exemption is written down here rather than inferred, so a
        future token cannot go unguarded merely by being left out of TOKEN_VARS.
        """
        covered = set(TOKEN_VARS) | TOKENS_WITHOUT_CSS_VARS
        assert covered == set(SPEC_TOKENS), (
            "token(s) neither published as a CSS variable nor exempted: "
            f"{sorted(covered ^ set(SPEC_TOKENS))}"
        )


class TestTheAccentStaysOnWizardState:
    """ACCENT means "you are here", the way SIGNAL means "secret on screen".

    SIGNAL is confined by selector guards because it lives in CSS. ACCENT lives
    in Rich markup instead, so the equivalent boundary is which module may name
    it. Confining it to the sidebar keeps it a statement about wizard state
    rather than decoration that spreads.
    """

    def test_only_the_sidebar_applies_the_accent(self):
        ui = Path(theme.__file__).parent
        offenders = sorted(
            path.relative_to(ui).as_posix()
            for path in ui.rglob("*.py")
            if path.name not in ("theme.py", "sidebar.py")
            and re.search(r"\bACCENT\b", path.read_text(encoding="utf-8"))
        )
        assert offenders == [], (
            f"ACCENT is referenced outside the sidebar: {offenders}. It marks "
            f"wizard state; anything else needs its own token and its own rule."
        )

    def test_the_accent_is_not_the_secret_material_colour(self):
        assert theme.ACCENT != theme.SIGNAL, (
            "amber must stay unique to exposed secret material"
        )


class TestRestrictedTokenUsage:
    """Which selectors may reference the two restricted tokens.

    SIGNAL marks exposed secret material and nothing else; TEXT_4 is below AA
    and must not render informational text. The first test pins the exact
    selector set for both, which also guards the parser: one that silently
    matched nothing would otherwise make every rule here pass while checking
    nothing.
    """

    # The sites the accent rule sanctions (spec §4), all of them exposed secret
    # material: the output pane, its auto-clear countdown, and a password field
    # the user has chosen to unmask. `Input.-revealed` is a class the checkbox
    # handler applies, so it is amber only while the text is legible.
    #
    # The last two entries are the selection bands over those same fields, and
    # they are not new sites. A selection repaints the text it covers, so
    # without them highlighting a revealed password or the output pane drops
    # the accent for as long as the highlight lasts, which is the one case the
    # rule exists to cover. Textual selects an Input's whole value on focus, so
    # for the password field this is the default state, not an edge case. Five
    # selectors, still three sites.
    SIGNAL_SELECTORS = {
        "#output-area",
        "#countdown-label",
        "Input.-revealed",
        "Input.-revealed > .input--selection",
        "#output-area > .text-area--selection",
    }

    # Sanctioned TEXT_4 sites, for three reasons:
    #   .section-divider    decoration, a rule glyph rather than a string
    #   #btn-next:disabled  non-focusable disabled control, WCAG 1.4.3 exempt
    #   the three scroll panes  scrollbar chrome, not text
    #
    # The scroll panes arrived with the fix for content that could not be
    # scrolled to at 100x30. A scrollbar is a position indicator and carries no
    # string, so 1.4.3 does not reach it; TEXT_4 is the hover and active lift
    # over a BORDER_STRONG thumb, which is the smallest step that still reads as
    # a response to the pointer. It is deliberately not SIGNAL: the accent means
    # exposed secret material, and a scrollbar is never that.
    TEXT_4_SELECTORS = {
        ".section-divider",
        "#btn-next:disabled",
        "#step-container",
        "#output-area",
        "#input-editor",
    }

    def test_the_restricted_tokens_are_used_on_exactly_the_sanctioned_selectors(self):
        """Both directions at once, which also makes the parser non-vacuous.

        This replaces an older `test_the_parser_actually_matches_something`,
        which asserted only that the match list was non-empty. Pinning the exact
        selector set is strictly stronger: a parser that matched nothing fails
        here too, and so does one that quietly drops a sanctioned site. The
        equality is deliberate in the other direction as well, so deleting the
        amber on the output pane is a decision that has to be made here rather
        than a silent loss of the one place the accent earns its meaning.
        """
        assert selectors_using("SIGNAL") == self.SIGNAL_SELECTORS
        assert selectors_using("TEXT_4") == self.TEXT_4_SELECTORS

    def test_signal_appears_only_on_the_allowed_selectors(self):
        offenders = [
            str(decl)
            for decl in rules_using("SIGNAL")
            if decl.selector not in self.SIGNAL_SELECTORS
        ]
        assert not offenders, (
            "amber is reserved for exposed secret material:\n  "
            + "\n  ".join(offenders)
        )

    def test_text_4_renders_no_informational_text(self):
        offenders = [
            str(decl)
            for decl in rules_using("TEXT_4")
            if decl.prop == "color" and decl.selector not in self.TEXT_4_SELECTORS
        ]
        ratio = contrast(theme.TEXT_4, theme.BG)
        assert not offenders, (
            f"TEXT_4 is {ratio:.2f}:1 and must not render informational text:\n  "
            + "\n  ".join(offenders)
        )


def _signal_selectors(css: str) -> set[str]:
    pattern = re.compile(r"\$m-signal(?![\w-])")
    return {decl.selector for decl in declarations(css) if pattern.search(decl.value)}


class TestTheGuardsSurviveReformatting:
    """Reformatting a rule must not change the verdict; hiding one must not either.

    This class is the reason the stylesheet names its colours as CSS variables.
    The guards used to parse theme.py's source text and rebuild the Python
    concatenation from it, which meant they keyed off the shape of a line: a
    line ending in `{` was a selector, anything else was a declaration. Every
    reformatting below broke that, two of them by reporting a violation against
    a selector that was not the one the declaration belonged to. Counting braces
    over real CSS makes the whole class structurally impossible.
    """

    OUTPUT_RULE = """#output-area {
    height: 10;
    min-height: 6;
    color: $m-signal;
}"""

    INPUT_RULE = """Input {
    background: $m-bg;
    border: heavy $m-border;
    color: $m-text;
}"""

    REVEALED_RULE = """Input.-revealed {
    color: $m-signal;
}"""

    TITLE_ANCHOR = ".step-title {\n    color: $m-text;"

    @pytest.mark.parametrize(
        "reformatting",
        [
            pytest.param(
                """#output-area {  /* pane holding exposed secret material */
    height: 10;
    min-height: 6;
    color: $m-signal;
}""",
                id="trailing-comment-after-brace",
            ),
            pytest.param(
                """#output-area
{
    height: 10;
    min-height: 6;
    color: $m-signal;
}""",
                id="brace-on-its-own-line",
            ),
            pytest.param(
                """#output-area { color: $m-signal;
    height: 10;
    min-height: 6;
}""",
                id="declaration-on-the-selector-line",
            ),
            pytest.param(
                """#output-area, #countdown-label {
    color: $m-signal;
}

#output-area {
    height: 10;
    min-height: 6;
}""",
                id="grouped-selector",
            ),
        ],
    )
    def test_reformatting_a_sanctioned_rule_keeps_it_sanctioned(self, reformatting):
        mutated = theme.WIZARD_CSS.replace(self.OUTPUT_RULE, reformatting)
        assert mutated != theme.WIZARD_CSS, "the rule this test reformats has moved"
        assert _signal_selectors(mutated) == TestRestrictedTokenUsage.SIGNAL_SELECTORS

    def test_a_nested_block_is_resolved_against_its_parent(self):
        """`&.-revealed` inside `Input` is `Input.-revealed`, which is sanctioned.

        The old parser read the nested selector literally and reported a
        violation against `&.-revealed`, a selector that does not exist.
        """
        nested = """Input {
    background: $m-bg;
    border: heavy $m-border;
    color: $m-text;
    &.-revealed {
        color: $m-signal;
    }
}"""
        mutated = theme.WIZARD_CSS.replace(self.INPUT_RULE, nested)
        mutated = mutated.replace(self.REVEALED_RULE, "")
        # Checks the exact standalone rule is gone, rather than the substring
        # "Input.-revealed": the sanctioned selection rule is a different rule
        # that legitimately contains that substring, and a `.replace()` whose
        # anchor had drifted would otherwise pass here by doing nothing.
        assert self.REVEALED_RULE not in mutated, "the standalone rule should be gone"
        assert "&.-revealed" in mutated, "the nested form should have replaced it"
        assert _signal_selectors(mutated) == TestRestrictedTokenUsage.SIGNAL_SELECTORS

    def test_a_comment_naming_the_token_is_not_a_usage(self):
        commented = "/* $m-signal is spent here and nowhere else */\n" + self.OUTPUT_RULE
        mutated = theme.WIZARD_CSS.replace(self.OUTPUT_RULE, commented)
        # Without this the test passes by doing nothing: a `.replace()` whose
        # anchor has drifted is a no-op, and the assert below then re-checks the
        # unmutated stylesheet, which of course still passes. Every sibling here
        # carries the same guard.
        assert mutated != theme.WIZARD_CSS, "the rule this test comments has moved"
        assert _signal_selectors(mutated) == TestRestrictedTokenUsage.SIGNAL_SELECTORS

    @pytest.mark.parametrize(
        "violation",
        [
            # The evasion that started this: identical CSS, no spaces to key off.
            pytest.param(".step-title {\n    color:$m-signal;", id="no-spaces"),
            pytest.param(".step-title {\n    color: $m-signal;", id="ordinary-spacing"),
            pytest.param(
                ".step-title {\n    &:hover { color:$m-signal; }\n    color: $m-text;",
                id="buried-in-a-nested-block",
            ),
        ],
    )
    def test_an_accent_violation_is_caught_however_it_is_written(self, violation):
        mutated = theme.WIZARD_CSS.replace(self.TITLE_ANCHOR, violation, 1)
        assert mutated != theme.WIZARD_CSS, "the rule this test mutates has moved"
        offenders = _signal_selectors(mutated) - TestRestrictedTokenUsage.SIGNAL_SELECTORS
        assert offenders, "an accent violation went unnoticed"

    def test_a_violation_hidden_in_a_grouped_selector_is_caught(self):
        """Grouping an unsanctioned selector onto a sanctioned rule is not a loophole."""
        mutated = theme.WIZARD_CSS.replace(
            "#output-area {\n    height: 10;",
            "#output-area, .step-title {\n    color: $m-signal;\n}\n\n"
            "#output-area {\n    height: 10;",
            1,
        )
        assert ".step-title" in _signal_selectors(mutated)

    def test_unbalanced_braces_are_an_error_rather_than_a_silent_pass(self):
        with pytest.raises(AssertionError, match="unbalanced braces"):
            declarations(theme.WIZARD_CSS + "\n.oops {\n")


def _rgb(hex_colour: str) -> tuple[int, int, int]:
    h = hex_colour.lstrip("#")
    return tuple(int(h[i:i + 2], 16) for i in (0, 2, 4))


def rgb_distance(a: str, b: str) -> float:
    """Plain Euclidean RGB distance. Crude, but enough to catch 'looks amber'."""
    return math.dist(_rgb(a), _rgb(b))


# The exporter wraps every screenshot in a fake macOS window. The app's own
# output is the group clipped to the terminal, so that group is the boundary
# between what we are responsible for and what the exporter owns.
_TERMINAL_CONTENT = re.compile(
    r'<g[^>]*clip-path="url\(#terminal-\d+-clip-terminal\)"[^>]*>'
)


def terminal_content(svg: str) -> str:
    """The part of an exported SVG the app drew, with the fake window removed.

    Everything before this group is the exporter's chrome and none of it is
    ours: #292929 the window frame, #c5c8c6 the window title, and #ff5f57,
    #febc2e and #28c840 the three traffic-light dots. #febc2e is an amber
    roughly 30 from SIGNAL and looks alarming in a raw grep over the SVGs, which
    is why the scoping is load-bearing rather than tidiness. None of the five is
    on screen in the running app and none must ever be "fixed".
    """
    match = _TERMINAL_CONTENT.search(svg)
    assert match, (
        "the terminal content group is missing, so this would scan the fake "
        "window chrome as if it were app output; the exporter's SVG shape has "
        "probably changed"
    )
    return svg[match.end():]


def fills_on_rendered_cells(svg: str) -> set[str]:
    """Every colour that paints a visible cell: glyph fills and cell backgrounds.

    Backgrounds are not optional here. Reading only <text> fills made this blind
    to exactly the regression the palette guards exist for: Textual paints a
    selected row by filling the cell, so deleting the rule that repoints the
    primary-blue selection band changed no glyph fill at all and the guard came
    back byte-identical. A cell background is a <rect fill=...> inside the
    terminal group, so both are collected.
    """
    class_fill = dict(
        re.findall(r"\.(terminal-\d+-r\d+)\s*\{[^}]*?fill:\s*(#[0-9A-Fa-f]{6})", svg)
    )
    body = terminal_content(svg)
    used = set()
    for cls, text in re.findall(
        r'<text[^>]*class="(terminal-\d+-r\d+)"[^>]*>(.*?)</text>', body, re.S
    ):
        if text.replace("&#160;", " ").strip():
            used.add(class_fill.get(cls, ""))
    used |= set(re.findall(r'<rect[^>]*fill="(#[0-9A-Fa-f]{6})"', body))
    return {colour.lower() for colour in used if colour}


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
            # record_output, not a bare assignment: it stamps the inputs that
            # produced the result, which is what marks it current. A bare
            # assignment leaves it fingerprint-less and so permanently stale.
            app._state.record_output("MORPHEUS-v1:c2FtcGxlIGNpcGhlcnRleHQ=")
            app._state.completed_steps.add(STEP_OUTPUT)
            for index in range(TOTAL_STEPS):
                app._goto_step(index)
                await settle(app, pilot)
                assert app._current_step == index, (
                    f"step {index + 1} was refused; the guard would silently "
                    f"check step {app._current_step + 1} twice"
                )
                rendered[index] = fills_on_rendered_cells(app.export_screenshot())
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

    @pytest.mark.asyncio
    async def test_a_revealed_password_is_amber_and_a_masked_one_is_not(self):
        """The third sanctioned site, and the only one behind a toggle.

        Both halves matter. Asserting only the revealed state passes just as
        well on a field that is amber permanently, which would put the accent
        on screen while nothing secret is legible and drain it of meaning.

        `test_no_near_amber_renders_outside_the_output_step` covers the masked
        default across every step; this pins the transition itself.
        """
        app = MorpheusWizard()
        async with app.run_test(size=(110, 38)) as pilot:
            app._state.mode = Mode.ENCRYPT
            app._state.input_text = "review canary"
            app._state.password = "T3st!Passw0rd#Str0ng"
            app._state.password_confirm = "T3st!Passw0rd#Str0ng"
            app._goto_step(STEP_PASSWORD)
            await settle(app, pilot)
            assert app._current_step == STEP_PASSWORD, (
                "the password step was refused; this would assert on whatever "
                "step happened to be showing"
            )

            masked = fills_on_rendered_cells(app.export_screenshot())
            app.query_one("#show-pwd-check", Checkbox).value = True
            await settle(app, pilot)
            revealed = fills_on_rendered_cells(app.export_screenshot())

        assert theme.SIGNAL not in masked, (
            "a masked password field shows bullets, not secret material, and "
            "must not take the accent"
        )
        assert theme.SIGNAL in revealed, (
            f"a revealed password is exposed secret material and must render "
            f"SIGNAL ({theme.SIGNAL}); got {sorted(revealed)}"
        )


class TestRenderedPaletteIsClosed:
    """Every colour on screen is a token, or one of five values we chose to keep.

    A primary-blue selection band and a green check glyph shipped because
    Textual paints through component classes that theme.py's type selectors
    never reached. Nothing caught it: the CSS guards read our stylesheet, and
    those colours were never in it. This pins the whole rendered set instead,
    so the next one fails here rather than on screen.

    Cell backgrounds count, not just glyphs. This class was blind to them until
    a mutation showed that deleting the selection-band rule changed no glyph
    fill at all, because Textual paints a selected row by filling the cell. The
    one regression named at the top of this docstring was invisible to the test
    written for it. See `fills_on_rendered_cells`.

    The five below are deliberate. All are structural chrome inside widget
    frames, none carries meaning, and none renders informational text:

      #242f38  $panel            toggle side bars, the ▐ ▌ around a check
      #000f18  $panel-darken-2   the unchecked glyph, hidden against $panel
      #191919  $border-blurred   unfocused widget borders
      #777778  $foreground 50%   the Select ▼ arrow, composited onto BG
      #17171a  $boost over BG    white 4% on our own background, near-BG fill

    Repointing them means overriding component classes for no visible gain, and
    each override is a thing to recheck on every Textual upgrade. Left as-is on
    purpose; this test is where that decision is recorded.

    Two values that used to render were repointed rather than kept, because
    neither met the bar above. Textual's #1e1e1e sat behind the Select's chosen
    value: a second surface, cooler than ours, against a system whose first rule
    is one background. Its #e0e0e0 was the caret, which carries meaning. Both
    now come from tokens. The arrow above moved from #7f7f7f to #777778 as a
    consequence: it is `$foreground 50%`, so it composites against whatever sits
    behind it, and that is now BG rather than Textual's panel.
    """

    KEPT_WIDGET_INTERNALS = {
        "#242f38", "#000f18", "#191919", "#777778", "#17171a",
    }

    async def _all_rendered_colours(self) -> set[str]:
        rendered = set()
        for colours in (await TestRenderedAmberIsReserved()._render_steps()).values():
            rendered |= colours
        return rendered

    @pytest.mark.asyncio
    async def test_no_colour_renders_that_is_neither_token_nor_documented(self):
        rendered = await self._all_rendered_colours()
        allowed = set(SPEC_TOKENS.values()) | self.KEPT_WIDGET_INTERNALS
        assert rendered - allowed == set(), (
            "these render on screen and come from neither a token nor the "
            "documented keep-list, which is how the blue selection band got "
            f"in: {sorted(rendered - allowed)}"
        )

    @pytest.mark.asyncio
    async def test_the_keep_list_has_no_dead_entries(self):
        """A stale keep-list would silently widen what the test above permits."""
        rendered = await self._all_rendered_colours()
        dead = self.KEPT_WIDGET_INTERNALS - rendered
        assert dead == set(), (
            "these are on the keep-list but no longer render; drop them rather "
            f"than leave the allowance open: {sorted(dead)}"
        )


class TestAllColoursGoThroughTokens:
    """theme.py's token block is the only place a colour may be a literal.

    The other guards match token names, so a raw hex literal bypasses them all.
    """

    def test_no_hex_literals_outside_the_token_block(self):
        pkg = Path(__file__).resolve().parent.parent / "morpheus"
        offenders = []
        for path in sorted(pkg.rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            if path.name == "theme.py":
                # The token block legitimately defines the palette.
                source = source.partition("WIZARD_CSS = ")[2]
            for match in re.findall(r"#[0-9A-Fa-f]{6}\b", source):
                offenders.append(f"{path.relative_to(pkg.parent)}: {match}")
        assert not offenders, (
            "colours must come from theme tokens, not hex literals:\n  "
            + "\n  ".join(offenders)
        )
