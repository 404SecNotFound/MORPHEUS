# Terminal Visual System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the Matrix black-and-green TUI palette with Replicant's warm-graphite `signal-instrument` system, where amber marks exposed secret material and nothing else.

**Architecture:** `morpheus/ui/theme.py` holds 16 colour tokens and ~480 lines of Textual CSS built by string concatenation. The tokens are referenced 104 times inside that file and nowhere else, so renaming them is free. Three other files carry hardcoded hex that a token-only edit would miss. Two guard tests are added so the palette cannot silently regress.

**Tech Stack:** Python 3.10+, Textual 8.x CSS, pytest.

**Spec:** [2026-07-28-terminal-visual-system.md](2026-07-28-terminal-visual-system.md)

> Saved to `docs/design/` rather than `docs/superpowers/plans/`, because that path is gitignored in this repo (it held internal notes that must not publish).

---

## File Structure

| File | Responsibility | Action |
|---|---|---|
| `morpheus/ui/theme.py` | colour tokens + all wizard CSS | rewrite token block, re-point 104 interpolations |
| `morpheus/ui/app.py` | top-bar title markup | replace hardcoded hex, fix stale version label |
| `morpheus/ui/steps/password.py` | strength ramp, match indicator | replace 7 hardcoded hex |
| `tests/test_theme.py` | **new** palette guard tests | create |
| `tests/test_gui.py` | 4 assertions on old ramp hex | update |
| `scripts/check_contrast.py` | **new** standalone contrast report | create |

### Token mapping

`ACCENT_DIM` and `DISABLED` are each used as **both** a text colour and a border colour. A blanket rename makes text unreadable (`#303032` on `#0e0e11` is 1.46:1), so those two split by role.

| Old token | New token | Value | Note |
|---|---|---|---|
| `BG` | `BG` | `#0e0e11` | |
| `SURFACE` | `BG` | `#0e0e11` | collapse; borders separate regions |
| `ELEVATED` | `BG` | `#0e0e11` | collapse |
| `BORDER` | `BORDER` | `#212124` | `rgba(255,255,255,.08)` composited |
| `BORDER_BRIGHT` | `BORDER_FOCUS` | `#ecebe6` | |
| `TEXT_PRIMARY` | `TEXT` | `#f1f0ec` | |
| `TEXT_BODY` | `TEXT_2` | `#a3a29b` | |
| `TEXT_SECONDARY` | `TEXT_3` | `#8f8d84` | |
| `TEXT_DIM` | `TEXT_3` | `#8f8d84` | |
| `DISABLED` (as text, focusable) | `TEXT_3` | `#8f8d84` | locked sidebar steps carry prose and are `can_focus=True`, so AA applies |
| `DISABLED` (as text, non-focusable) | `TEXT_4` | `#5f5e58` | disabled button labels; WCAG 1.4.3 exempts inactive components |
| `DISABLED` (as background) | `BG` | `#0e0e11` | |
| `ACCENT` | `SELECTED` | `#ecebe6` | |
| `ACCENT_HOVER` | `TEXT` | `#f1f0ec` | |
| `ACCENT_DIM` (as text) | `TEXT_2` | `#a3a29b` | |
| `ACCENT_DIM` (as border) | `BORDER_STRONG` | `#303032` | |
| `SUCCESS` | *deleted* | | dead: 0 uses in CSS |
| `WARNING` (`#countdown-label`) | `SIGNAL` | `#f4b23e` | the accent case |
| `WARNING` (`.warning-text`) | `ERROR` | `#e5594f` | amber stays reserved |
| `ERROR` | `ERROR` | `#e5594f` | |

---

## Task 1: Contrast guard test and the new token block

**Files:**
- Create: `tests/test_theme.py`
- Modify: `morpheus/ui/theme.py:1-24`

- [ ] **Step 1: Write the failing test**

```python
"""Guards for the terminal visual system (docs/design/2026-07-28-terminal-visual-system.md)."""

from morpheus.ui import theme


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


# Every token that is ever used to render a string, per the spec.
TEXT_TOKENS = ["TEXT", "TEXT_2", "TEXT_3", "SELECTED", "SIGNAL", "ERROR"]


class TestPaletteContrast:
    def test_every_text_token_passes_wcag_aa(self):
        for name in TEXT_TOKENS:
            value = getattr(theme, name)
            ratio = contrast(value, theme.BG)
            assert ratio >= 4.5, f"{name} ({value}) is {ratio:.2f}:1 on BG, needs >= 4.5"

    def test_text_4_is_decoration_only_and_not_exported_as_text(self):
        """TEXT_4 fails AA by design, so it must never be used for a string."""
        assert contrast(theme.TEXT_4, theme.BG) < 4.5
        assert "TEXT_4" not in theme.TEXT_TOKENS

    def test_signal_is_the_documented_amber(self):
        assert theme.SIGNAL == "#f4b23e"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_theme.py -v`
Expected: FAIL with `AttributeError: module 'morpheus.ui.theme' has no attribute 'TEXT'`

- [ ] **Step 3: Replace the token block**

Replace `morpheus/ui/theme.py` lines 1 to 24 with:

```python
"""Theme tokens and CSS for the MORPHEUS wizard UI.

Visual system: docs/design/2026-07-28-terminal-visual-system.md
Translated from Replicant's `signal-instrument` spec. Warm graphite surfaces,
one semantic accent, data brighter than chrome.
"""

from __future__ import annotations

# -- Surfaces ----------------------------------------------------------------
# One background only. Replicant's four surface tiers sit 1.06-1.10:1 apart,
# which reads as depth in a browser (large fills, hairlines, shadows) and as one
# flat colour in a terminal. Borders carry elevation here instead.
BG              = "#0e0e11"    # warm graphite, deliberately not blue-black

# Borders are Replicant's alpha hairlines composited onto BG, since Textual has
# no alpha channel.
BORDER          = "#212124"    # rgba(255,255,255,.08) over BG
BORDER_STRONG   = "#303032"    # rgba(255,255,255,.14) over BG
BORDER_FOCUS    = "#ecebe6"    # focus needs to be unmistakable; see the spec

# -- Text tiers --------------------------------------------------------------
# Data is the brightest thing on screen; chrome recedes. This replaces
# Replicant's mono-vs-sans distinction, which a terminal cannot express.
TEXT            = "#f1f0ec"    # data and values          16.90:1 AAA
TEXT_2          = "#a3a29b"    # body prose                7.52:1 AAA
TEXT_3          = "#8f8d84"    # uppercase micro-labels    5.79:1 AA
TEXT_4          = "#5f5e58"    # DECORATION ONLY, never a string   2.96:1

# -- Semantic ----------------------------------------------------------------
SELECTED        = "#ecebe6"    # active step, primary button, selection
SIGNAL          = "#f4b23e"    # EXPOSED SECRET MATERIAL ONLY. Nothing else.
ERROR           = "#e5594f"    # errors, refusals, weak-password floor

# Tokens that may be used to render a string. TEXT_4 is deliberately absent.
TEXT_TOKENS = ["TEXT", "TEXT_2", "TEXT_3", "SELECTED", "SIGNAL", "ERROR"]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_theme.py -v`
Expected: 3 passed. The rest of the suite will fail to import at this point, because the CSS below still references the deleted names. That is expected and Task 2 fixes it.

- [ ] **Step 5: Do not commit yet**

The module does not import cleanly until Task 2 lands. Commit at the end of Task 2.

---

## Task 2: Re-point the CSS to the new tokens

**Files:**
- Modify: `morpheus/ui/theme.py:26-505` (the `WIZARD_CSS` string)

- [ ] **Step 1: Apply the mechanical renames**

These are unambiguous, one role each. Apply across the whole `WIZARD_CSS` string:

| Find | Replace |
|---|---|
| `""" + SURFACE + """` | `""" + BG + """` |
| `""" + ELEVATED + """` | `""" + BG + """` |
| `""" + TEXT_PRIMARY + """` | `""" + TEXT + """` |
| `""" + TEXT_BODY + """` | `""" + TEXT_2 + """` |
| `""" + TEXT_SECONDARY + """` | `""" + TEXT_3 + """` |
| `""" + TEXT_DIM + """` | `""" + TEXT_3 + """` |
| `""" + ACCENT + """` | `""" + SELECTED + """` |
| `""" + ACCENT_HOVER + """` | `""" + TEXT + """` |
| `""" + BORDER_BRIGHT + """` | `""" + BORDER_FOCUS + """` |

- [ ] **Step 2: Apply the six role-dependent replacements by hand**

A blanket rename here produces unreadable text. Each line number is from the current file.

```
line  93  .sidebar-item.--completed   color:  ACCENT_DIM  ->  TEXT_2
line  97  .sidebar-item.--locked      color:  DISABLED    ->  TEXT_3   (see note)
line 182  #btn-next                   border: ACCENT_DIM  ->  BORDER_STRONG
line 190  #btn-next:disabled          background: DISABLED -> BG
line 191  #btn-next:disabled          color:  TEXT_DIM    ->  TEXT_4
line 192  #btn-next:disabled          border: DISABLED    ->  BORDER
line 199  #btn-run                    border: ACCENT_DIM  ->  BORDER_STRONG
line 444  #btn-copy                   border: ACCENT_DIM  ->  BORDER_STRONG
line 483  #copy-pwd                   color:  ACCENT_DIM  ->  TEXT_2
```

The two "disabled" sites resolve differently, and this is the easiest thing to get wrong:

- **Line 97, `.sidebar-item.--locked`, takes `TEXT_3`, not `TEXT_4`.** It looks like a
  disabled control but is not one. `sidebar.py:80-81` renders a step name and description
  through it, and `SidebarItem` is declared `can_focus=True`, making it focusable
  informational text. WCAG 1.4.3's inactive-component exemption does not cover that, so
  `TEXT_4` at 2.96:1 is a real accessibility failure. `TEXT_3` gives 5.79:1 and still reads
  as the dimmest of the three sidebar states (current `#ecebe6`, completed `#a3a29b`,
  locked `#8f8d84`).
- **Line 191, `#btn-next:disabled`, does take `TEXT_4`.** The label belongs to a genuinely
  inactive control, is WCAG-exempt, and should look unavailable. Note this is an exception
  to the Step 4 table, which maps `TEXT_DIM` to `TEXT_3`: apply Step 4 first, then correct
  this one line.

- [ ] **Step 3: Apply the two semantic decisions**

```
line 416  .warning-text     color: WARNING -> ERROR
          Password-strength warnings are a severity signal, not live secret
          material. Amber must stay reserved.

line 468  #countdown-label  color: WARNING -> SIGNAL
          This is the accent case: the auto-clear countdown means a secret is
          on screen right now.
```

- [ ] **Step 4: Point the output pane at SIGNAL**

The Output step renders the ciphertext or decrypted plaintext, which is the primary accent case. `#output-area` is at line 420 and currently declares only `height` and `min-height`, so add a `color`:

```
#output-area {
    height: 10;
    min-height: 6;
    color: """ + SIGNAL + """;
}
```

- [ ] **Step 5: Verify no stale token names remain**

Run: `grep -nE '\+ (SURFACE|ELEVATED|TEXT_PRIMARY|TEXT_BODY|TEXT_SECONDARY|TEXT_DIM|DISABLED|ACCENT|ACCENT_HOVER|ACCENT_DIM|SUCCESS|WARNING|BORDER_BRIGHT) \+' morpheus/ui/theme.py`
Expected: no output.

- [ ] **Step 6: Run the full suite**

Run: `python -m pytest tests/ -q`
Expected: 281 passed (278 existing plus the 3 from Task 1).

- [ ] **Step 7: Commit**

```bash
git add morpheus/ui/theme.py tests/test_theme.py
git commit -m "feat(ui): adopt the warm-graphite terminal visual system

Replaces the Matrix palette with Replicant's signal-instrument tokens.
Amber is reserved for exposed secret material; generic active and selected
states use near-white. Surface tiers collapse to a single background because
they sit 1.06-1.10:1 apart and read as one flat colour in a terminal, so
borders carry elevation instead.

Adds tests/test_theme.py, which fails the build if any token used for text
drops below WCAG AA on the background."
```

---

## Task 3: Fix the hardcoded title in app.py

**Files:**
- Modify: `morpheus/ui/app.py:95`

- [ ] **Step 1: Read the current line**

```python
yield Static("[bold #00FF41]MORPHEUS[/] [#007018]v2.0[/]", id="top-title")
```

Two problems: Matrix hex that a theme edit cannot reach, and a `v2.0` label that is wrong now the version is 2.1.0.

- [ ] **Step 2: Replace it**

```python
yield Static(
    f"[bold {theme.TEXT}]MORPHEUS[/] [{theme.TEXT_3}]v{__version__}[/]",
    id="top-title",
)
```

- [ ] **Step 3: Add the imports**

At the top of `morpheus/ui/app.py`, alongside the existing `from .theme import WIZARD_CSS`:

```python
from .. import __version__
from . import theme
```

- [ ] **Step 4: Verify the version renders**

Run:
```bash
python -c "from morpheus import __version__; print(__version__)"
```
Expected: `2.1.0`

- [ ] **Step 5: Run the suite**

Run: `python -m pytest tests/ -q`
Expected: 281 passed.

- [ ] **Step 6: Commit**

```bash
git add morpheus/ui/app.py
git commit -m "fix(ui): drive the top-bar title from theme tokens and __version__

The title hardcoded Matrix green, which a theme change cannot reach, and a
stale v2.0 label."
```

---

## Task 4: Restyle the password strength ramp

**Files:**
- Modify: `tests/test_gui.py:26,33,40,47`
- Modify: `morpheus/ui/steps/password.py:23-31,203-205`

Per the spec, the ramp drops gold (which would compete with the accent) and carries severity in the label, which is already rendered.

| Score | Old | New | Label |
|---|---|---|---|
| >= 80 | `#00FF41` | `TEXT` `#f1f0ec` | Excellent |
| >= 60 | `#00CC33` | `TEXT` `#f1f0ec` | Strong |
| >= 40 | `#FFD700` | `TEXT_2` `#a3a29b` | Fair |
| >= 20 | `#FF8800` | `ERROR` `#e5594f` | Weak |
| else | `#FF3333` | `ERROR` `#e5594f` | Very weak |

- [ ] **Step 1: Update the failing assertions first**

Assert on **token references, not hex literals**. `tests/test_theme.py` documents why hex
matching is unsound here: `SELECTED` and `BORDER_FOCUS` are both `#ecebe6`, so hex cannot
distinguish two tokens sharing a value. It also already owns exact-value pinning, so
asserting hex here duplicates that badly and makes a harmless palette re-tune fail as a
password-widget regression. Asserting `theme.ERROR` is not tautological: swapping the source
to `theme.SIGNAL` renders `#f4b23e` and still fails.

Add `from morpheus.ui import theme` to the imports, then replace the four colour assertions:

```python
    def test_weak_renders_error(self):
        bar = StrengthBar()
        bar.score = 20
        rendered = bar.render()
        assert theme.ERROR in rendered
        assert "Weak" in rendered

    def test_fair_renders_secondary(self):
        bar = StrengthBar()
        bar.score = 40
        rendered = bar.render()
        assert theme.TEXT_2 in rendered
        assert "Fair" in rendered

    def test_strong_renders_primary(self):
        bar = StrengthBar()
        bar.score = 60
        rendered = bar.render()
        assert theme.TEXT in rendered
        assert "Strong" in rendered

    def test_excellent_renders_primary(self):
        bar = StrengthBar()
        bar.score = 80
        rendered = bar.render()
        assert theme.TEXT in rendered
        assert "Excellent" in rendered
```

Also add a version regression test. Both stale-`v2.0` bugs shipped because nothing asserted
the version:

```python
    def test_window_title_tracks_the_package_version(self):
        from morpheus import __version__
        assert MorpheusWizard.TITLE.endswith(__version__)
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest tests/test_gui.py -k StrengthBar -v`
Expected: 4 FAILED, each `assert '#e5594f' in rendered` style, because the widget still emits Matrix hex.

- [ ] **Step 3: Update the ramp**

In `morpheus/ui/steps/password.py`, replace lines 23-31:

```python
        if score >= 80:
            color, label = theme.TEXT, "Excellent"
        elif score >= 60:
            color, label = theme.TEXT, "Strong"
        elif score >= 40:
            color, label = theme.TEXT_2, "Fair"
        elif score >= 20:
            color, label = theme.ERROR, "Weak"
        else:
            color, label = theme.ERROR, "Very weak"
```

- [ ] **Step 4: Update the match indicators**

Replace lines 203-205:

```python
            indicator.update(f"[{theme.TEXT}]Match[/]")
        else:
            indicator.update(f"[{theme.ERROR}]No match[/]")
```

- [ ] **Step 5: Add the import**

At the top of `morpheus/ui/steps/password.py`:

```python
from .. import theme
```

- [ ] **Step 6: Run to verify they pass**

Run: `python -m pytest tests/test_gui.py -k StrengthBar -v`
Expected: 5 passed (the four above plus `test_zero_score`).

- [ ] **Step 7: Run the full suite**

Run: `python -m pytest tests/ -q`
Expected: 281 passed.

- [ ] **Step 8: Commit**

```bash
git add morpheus/ui/steps/password.py tests/test_gui.py
git commit -m "feat(ui): restyle the strength ramp to the new palette

Drops gold, which competed with the reserved accent. Severity is carried by
the text label, per the design system's severity-as-text rule."
```

---

## Task 5: Guard against legacy hex returning

**Files:**
- Modify: `tests/test_theme.py`

- [ ] **Step 1: Add the guard test**

Do **not** write this as a blocklist of Matrix-era hex. That only catches yesterday's
mistake. It would not catch `color: #f4b23e` hardcoded into the wrong rule, which is the
live risk now: the amber guard in `TestRestrictedTokenUsage` matches token *names*, so raw
hex slips past it entirely.

Invert it. Forbid any hex literal under `morpheus/` outside the token definitions, which
forces every colour through the token system and closes the legacy hole and the
hardcoded-accent hole with one rule:

```python
import pathlib
import re


class TestAllColoursGoThroughTokens:
    """theme.py is the only place a colour may be written as a literal."""

    def test_no_hex_literals_outside_the_token_block(self):
        pkg = pathlib.Path(__file__).resolve().parent.parent / "morpheus"
        offenders = []
        for path in sorted(pkg.rglob("*.py")):
            source = path.read_text()
            # theme.py legitimately defines the palette; skip only its token block.
            if path.name == "theme.py":
                source = source.partition("WIZARD_CSS = ")[2]
            for lineno, line in enumerate(source.splitlines(), 1):
                for match in re.findall(r"#[0-9A-Fa-f]{6}\b", line):
                    offenders.append(f"{path.relative_to(pkg.parent)}: {match}")
        assert not offenders, (
            "colours must come from theme tokens, not hex literals:\n  "
            + "\n  ".join(offenders)
        )
```

Note the line numbers are approximate for `theme.py` because of the `partition`, which is
acceptable: the message names the file and the offending colour, which is enough to find it.

- [ ] **Step 2: Run it**

Run: `python -m pytest tests/test_theme.py::TestNoLegacyPalette -v`
Expected: PASS if Tasks 2 to 4 are complete. If it FAILS, the output names the exact file, line, and colour still to fix. Fix them and re-run.

- [ ] **Step 3: Run the full suite**

Run: `python -m pytest tests/ -q`
Expected: 282 passed.

- [ ] **Step 4: Commit**

```bash
git add tests/test_theme.py
git commit -m "test(ui): fail the build if Matrix-era hex reappears"
```

---

## Task 6: Standalone contrast report

**Files:**
- Create: `scripts/check_contrast.py`

The spec requires the contrast check be re-runnable when tokens change. The test asserts the floor; this prints the full table for a human.

- [ ] **Step 1: Create the script**

```python
#!/usr/bin/env python3
"""Print the WCAG contrast table for the MORPHEUS palette.

Usage: python scripts/check_contrast.py
Exits non-zero if any token used for text falls below AA on the background.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from morpheus.ui import theme  # noqa: E402


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
    for name in theme.TEXT_TOKENS:
        value = getattr(theme, name)
        ratio = contrast(value, theme.BG)
        mark = grade(ratio)
        if ratio < 4.5:
            failures += 1
            mark += "  <-- below AA"
        print(f"  {name:12} {value}  {ratio:6.2f}:1  {mark}")

    value = theme.TEXT_4
    print(f"\n  {'TEXT_4':12} {value}  {contrast(value, theme.BG):6.2f}:1  "
          f"decoration only, never a string")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 2: Run it**

Run: `python scripts/check_contrast.py`
Expected: every listed token graded AA or AAA, exit 0.

- [ ] **Step 3: Commit**

```bash
git add scripts/check_contrast.py
git commit -m "chore(ui): add a re-runnable palette contrast report"
```

---

## Task 7: Review the result as rendered

Source review cannot tell you whether a terminal palette works. Textual exports the real widget tree to SVG.

**Files:**
- Create: `scripts/screenshot_wizard.py`

- [ ] **Step 1: Create the screenshot script**

```python
#!/usr/bin/env python3
"""Save an SVG screenshot of each wizard step for visual review.

Usage: python scripts/screenshot_wizard.py [outdir]
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from morpheus.ui.app import MorpheusWizard  # noqa: E402
from morpheus.ui.state import Mode  # noqa: E402


async def main(outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    app = MorpheusWizard()
    async with app.run_test(size=(110, 38)) as pilot:
        app._state.mode = Mode.ENCRYPT
        app._state.input_text = "review canary"
        app._state.password = "T3st!Passw0rd#Str0ng"
        app._state.password_confirm = "T3st!Passw0rd#Str0ng"
        for index in range(6):
            app._goto_step(index)
            await pilot.pause()
            name = f"step-{index + 1}.svg"
            app.save_screenshot(filename=name, path=str(outdir))
            print(f"wrote {outdir / name}")


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("build/screens")
    asyncio.run(main(out))
```

- [ ] **Step 2: Run it**

Run: `python scripts/screenshot_wizard.py build/screens`
Expected: six SVG files written. `build/` is already gitignored, so nothing is committed.

- [ ] **Step 3: Open and check each**

Confirm against the spec:
- amber appears **only** on the Output pane text and the countdown label
- the selected step in the rail is near-white, not amber
- micro-labels read as dim grey against near-white data
- focused inputs are clearly distinguishable
- no green remains anywhere

If amber appears anywhere else, that is a bug in Task 2 step 3 or 4. Fix and re-run.

- [ ] **Step 4: Commit the script**

```bash
git add scripts/screenshot_wizard.py
git commit -m "chore(ui): add a wizard screenshot script for visual review"
```

---

## Task 8: Update the CHANGELOG

**Files:**
- Modify: `CHANGELOG.md`

The 2.1.0 entry currently describes the Matrix palette this change replaces.

- [ ] **Step 1: Replace the theme bullet**

Find the `**Matrix dark theme**` bullet under `## [2.1.0]` and replace it:

```markdown
- **Terminal visual system**: Warm-graphite palette translated from Replicant's
  `signal-instrument` design system. Amber `#f4b23e` is reserved for exposed
  secret material (the output pane and its auto-clear countdown); generic active
  and selected states use near-white. Replaces the Matrix black-and-green theme.
  Every token used for text is verified against WCAG AA by `tests/test_theme.py`.
  See `docs/design/2026-07-28-terminal-visual-system.md`.
```

- [ ] **Step 2: Run the full suite one last time**

Run: `python -m pytest tests/ -q`
Expected: 282 passed.

- [ ] **Step 3: Confirm the other gates**

```bash
ruff check morpheus/ tests/
bandit -r morpheus/ -ll -q
python -m pytest tests/ -q --cov --cov-report=term
```
Expected: exit 0, exit 0, and coverage at or above 74.

- [ ] **Step 4: Commit**

```bash
git add CHANGELOG.md
git commit -m "docs: record the terminal visual system in the changelog"
```

---

## Verification checklist

- [ ] 282 tests pass
- [ ] `ruff check morpheus/ tests/` exits 0
- [ ] `bandit -r morpheus/ -ll -q` exits 0
- [ ] coverage at or above 74
- [ ] `python scripts/check_contrast.py` exits 0
- [ ] `grep -rn '#00FF41\|#39FF14\|#FFD700' morpheus/` returns nothing
- [ ] six SVG screenshots reviewed; amber appears only on output text and countdown
- [ ] CHANGELOG 2.1.0 describes the shipped palette
