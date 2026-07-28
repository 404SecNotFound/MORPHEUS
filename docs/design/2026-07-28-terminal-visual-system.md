# MORPHEUS terminal visual system

**Date:** 2026-07-28
**Status:** approved (accent rule: Option A)
**Scope:** the Textual TUI palette and type discipline. No layout or feature changes.
**Source system:** Replicant's `signal-instrument` design spec
(`Replicant/docs/webui-reskin-design.md`)

> Written to `docs/design/` rather than the usual `docs/superpowers/specs/`, because
> `docs/superpowers/` was untracked and gitignored earlier today: it held internal agent
> working notes that should not publish. This is product documentation and is tracked.

---

## 1. Goal

Bring Morpheus onto the same visual system as Replicant so the two products read as one
body of work. Replace the current Matrix black-and-green palette, which conflicts with the
recorded design direction (quiet confidence, 2026-native) and with the CHANGELOG entry for
2.1.0.

This is a translation, not a copy. Replicant's system targets a React/Tailwind web app.
Morpheus's UI is Textual running in a terminal. Sections 4 and 5 record what does not
survive the move and what replaces it.

## 2. What we are adopting

From Replicant's spec, three things carry the identity:

1. **Warm graphite surfaces**, deliberately not blue-black.
2. **One semantic accent** that means exactly one thing, derived from what the product does.
   Everything generic stays neutral. This discipline is what makes the palette read as
   designed rather than decorated.
3. **A tiered text hierarchy** where data is the brightest element on screen and chrome
   recedes.

## 3. Tokens

Background is a single value. See section 5 for why the surface tiers collapse.

| Token | Value | Use | Contrast on `#0e0e11` |
|---|---|---|---|
| `BG` | `#0e0e11` | the only background | n/a |
| `BORDER` | `#212124` | quiet panel edges | 1.20:1 vs bg |
| `BORDER_STRONG` | `#303032` | dividers needing more presence | 1.46:1 vs bg |
| `BORDER_FOCUS` | `#ecebe6` | focused input, active panel | 16.15:1 vs bg |
| `TEXT` | `#f1f0ec` | data, values, the thing the user came for | 16.90:1 AAA |
| `TEXT_2` | `#a3a29b` | body prose, descriptions | 7.52:1 AAA |
| `TEXT_3` | `#8f8d84` | uppercase micro-labels, hints | 5.79:1 AA |
| `TEXT_4` | `#5f5e58` | rules, dividers, and non-focusable disabled controls. **Never informational text** | 2.96:1 fails, by design |
| `SELECTED` | `#ecebe6` | active step, primary button, selection | 16.15:1 AAA |
| `SIGNAL` | `#f4b23e` | **exposed secret material only** | 10.36:1 AAA |
| `ERROR` | `#e5594f` | errors, refusals, weak-password floor | 5.39:1 AA |

Measured with the WCAG 2.1 relative-luminance formula. Every token used for informational
text passes AA or better.

**`TEXT_4` deliberately fails**, so its use is bounded. Two cases only:

1. **Decoration**: rules and dividers, matching Replicant's "decoration only, never body
   text" constraint.
2. **Non-focusable disabled controls**, such as the label on a disabled button. WCAG 1.4.3
   exempts inactive components, and a disabled control should look unavailable.

It must never render informational text, and specifically never text the user can focus.
A locked wizard step is the trap here: it looks inactive but carries a step name and
description and is keyboard-focusable, so it takes `TEXT_3` (5.79:1), not `TEXT_4`.

This bound is enforced by `tests/test_theme.py`, which fails the build if `TEXT_4` appears
in a `color:` declaration outside the allow-list.

**Borders are derived, not invented.** Replicant's borders are alpha hairlines
(`rgba(255,255,255,.08)` and `.14`). Textual has no alpha, so they are composited onto
`#0e0e11` to give the opaque equivalents above: `.08` resolves to `#212124` and `.14` to
`#303032`.

**Focus is the one place we deliberately depart.** At 1.46:1 the stronger hairline is too
faint to answer "what is focused right now" when it is drawn as a glyph stroke rather than a
1px line. Replicant solves this with a separate neutral `:focus-visible` ring, so the
faithful translation is a distinct treatment rather than a darker border: focus uses
`SELECTED` near-white. This keeps focus unmistakable and still obeys the rule that generic
active states are neutral, never amber.

## 4. The accent rule (load-bearing)

**Amber `#f4b23e` means secret material is on screen right now. Nothing else.**

It appears in exactly three places:

- the Output pane while it holds ciphertext or decrypted plaintext
- the auto-clear countdown attached to that output
- the password field when the user has toggled it visible

Everything else that a designer would reach for an accent to express uses near-white
`#ecebe6`: the selected step in the rail, the primary button, focus, active states.

**Why this and not "work in progress".** Replicant's amber tracks its eps readout because
Replicant emits a rated signal; the accent is derived from the product's function. The
literal translation for Morpheus would be "cryptographic work is running", but Argon2id
measures **29 ms** on 2024 hardware, so that state is never visible in practice. An accent
nobody sees cannot carry an identity. Morpheus's defining moment is that a secret is briefly
on screen and then is not, so that is what the accent marks.

**Consequence for the password strength meter.** The current ramp uses five hardcoded
colours including gold `#FFD700`, which would compete with the accent. Under this system the
ramp becomes: Very weak and Weak in `ERROR`, Fair in `TEXT_2`, Strong and Excellent in
`TEXT`. The textual label ("Weak", "Strong") is already rendered and remains the primary
signal, satisfying Replicant's "severity as text, not colour-only" rule.

## 5. What does not survive the translation

**Mono-as-telemetry.** Replicant reserves IBM Plex Mono for data and Plex Sans for chrome.
A terminal is uniformly monospace and the font belongs to the user, so this distinction
cannot be expressed typographically. It is re-encoded as **colour tier plus case**:
micro-labels are uppercase in `TEXT_3`, data is normal case in `TEXT`. The outcome is the
same, data is the brightest element and chrome recedes, by different means.

**The four surface tiers.** Replicant's `--surface` / `--surface-2` / `--elev` measure
1.07:1, 1.06:1 and 1.10:1 against each other. In a browser those separate through large
fills, hairline borders and shadows. A terminal has no shadows, coarse borders, and often a
user-set background or transparency, so they would render as one flat colour. We therefore
keep a single `BG` and let **borders carry elevation**, which is consistent with Replicant's
own "borders quiet, shadows only for elevation" note. Exaggerating the greys to force
separation was rejected: it would diverge from Replicant rather than translate it.

**Radii, shadows, the 34px grid texture, the top vignette, letter-spacing.** None have a
terminal equivalent. Dropped rather than approximated.

## 6. Blast radius

The option chosen was labelled "theme.py only". That is not accurate, and the correction
matters. Hardcoded hex values live outside `theme.py` and would survive a token-only edit:

| Location | What | Action |
|---|---|---|
| `morpheus/ui/theme.py` | 16 tokens + ~480 lines of CSS | rewrite tokens, re-point CSS |
| `morpheus/ui/app.py:95` | `[bold #00FF41]MORPHEUS[/] [#007018]v2.0[/]` | re-point to tokens; also a stale `v2.0` label, now 2.1.0 |
| `morpheus/ui/steps/password.py:23-31` | 5 hardcoded strength-ramp colours | re-point per section 4 |
| `morpheus/ui/steps/password.py:203-205` | Match / No match indicators | re-point to `TEXT` / `ERROR` |
| `tests/test_gui.py:26,33,40,47` | 4 assertions on exact Matrix hex | update to the new ramp |

So: 4 source files and 4 test assertions, not one file and no tests. Still small, and no
widget structure, step flow, or behaviour changes.

`theme.py` exports only `WIZARD_CSS` to `app.py`; the token names are otherwise unreferenced,
so renaming them is free.

## 7. Non-goals

- No layout or step-flow changes. The 6-step wizard is untouched.
- No new components. The "cipher path" panel and instrument-panel readouts discussed during
  design are explicitly deferred.
- No web UI. Reusing Replicant's tokens in a React app is a separate project.
- No light theme. Dark-first, matching Replicant.

## 8. Verification

1. All 294 tests pass. The suite grew from 278 during this work: the 4 updated assertions
   in `test_gui.py` were the smallest part of it, and `tests/test_theme.py` was added to
   hold the guards described below.
2. `ruff` and `bandit` stay at exit 0.
3. Every token used for text is re-checked against `#0e0e11` for AA. The check script lives
   at `scripts/check_contrast.py` so it can be re-run when tokens change.
4. No Matrix-era hex survives. Grep was the plan and it is not sufficient, so this is
   enforced by `tests/test_theme.py` in two layers: the CSS guards require every colour in
   `theme.py` to come from a token, and `TestRenderedPaletteIsClosed` asserts on the
   colours that actually paint glyphs in the exported SVGs. The second layer exists
   because grepping `morpheus/` cannot see colour Textual supplies from its own theme,
   which is where the real regressions were — a primary-blue selection band and a green
   check glyph both survived the rewrite and were caught only by rendering.
5. The running TUI is screenshotted via Textual's SVG export for each of the 6 steps, so the
   result is reviewed as rendered rather than as source.
6. The CHANGELOG 2.1.0 theme entry is updated, since it currently describes the Matrix
   palette this change replaces.
