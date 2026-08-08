# MORPHEUS terminal visual system, revision 2

**Date:** 2026-08-05
**Status:** proposed
**Scope:** the Textual TUI palette, step hierarchy and keyboard step navigation.
No change to the wizard's six steps, its flow, or any cryptographic behaviour.
**Supersedes:** [2026-07-28-terminal-visual-system.md](2026-07-28-terminal-visual-system.md)
for token values and sidebar styling. That document remains the record of the
2026-07-28 change and its reasoning; where the two disagree on a colour, this
one wins.

---

## 1. What prompted this

Reported from a Raspberry Pi 4 over SSH: *"you cannot see the sections, the app
has no life to it, and the arrow keys were not working when I was trying to move
from section to section, so I had to use the mouse."*

Two separate defects, one visual and one functional. Both are reproduced and
measured below rather than taken on description.

## 2. The visual problem, measured

The palette is not broken. Every text token passes AA against the background:
`TEXT_3` at 5.79:1 is the weakest informational token, and the current step uses
`SELECTED` at 16.15:1. The problem is that the sidebar expresses *five different
states* through almost no difference:

| Sidebar state | Today's colour | Today's marker |
|---|---|---|
| current | `SELECTED` bold | `[>]` |
| completed | `TEXT_2` | `[+]` |
| available | `TEXT_3` | `[N]` |
| locked | `TEXT_3` (identical to available) | `[ ]` |
| focused | `SELECTED` reverse | unchanged |

Locked and available are styled identically, so two of the five states are not
distinguishable at all. The markers are all bracketed glyphs of the same width
and weight, so they scan as one texture. The remaining separation is carried by
three warm greys that sit close together.

At the same time the whole UI is one flat plane: the sidebar, the step pane and
the app background are all `#0e0e11`, separated only by a one-cell border.

## 3. What the measurements ruled out

Surface tinting alone cannot fix this. Measured contrast between the proposed
planes:

| Pair | Ratio |
|---|---|
| panel `#0e0e11` vs root `#08080a` | 1.04:1 |
| current-row fill `#101820` vs panel `#0e0e11` | 1.08:1 |

Ratios that low are barely perceptible on a good monitor and effectively invisible
on a small panel over SSH. **Surfaces are therefore reinforcement only.** If the
design leaned on them to answer "I cannot see the sections", the same report would
come back.

This produces the governing rule.

## 4. Principle: structure first, colour second

Every state distinction must survive colour being removed entirely. Marker glyph,
text weight and a solid accent bar carry the hierarchy; fill, tint and hue
reinforce it. A design that needs truecolor to be legible is the defect being
fixed, not the fix.

This is testable, and section 8 makes it a test.

## 5. Tokens

Unchanged: `BG #0e0e11`, `BORDER #212124`, `BORDER_STRONG #303032`,
`BORDER_FOCUS #ecebe6`, `TEXT #f1f0ec`, `TEXT_2 #a3a29b`, `TEXT_3 #8f8d84`,
`TEXT_4 #5f5e58`, `SELECTED #ecebe6`, `SIGNAL #f4b23e`, `ERROR #e5594f`.

Added:

| Token | Value | Purpose |
|---|---|---|
| `BG_BASE` | `#08080a` | app root, beneath the panels |
| `SURFACE_CURRENT` | `#101820` | current sidebar row fill |
| `ACCENT` | `#4bb3d4` | wizard state only: current-step bar and label, completed tick |

**`SIGNAL` (amber) remains exclusively exposed secret material.** That rule does
not move, and `ACCENT` must never appear on a selector sanctioned for `SIGNAL`.
Two meaningful colours now exist and each means exactly one thing: amber says
"this is secret material on screen", accent says "this is where you are".

### Why `SURFACE_CURRENT` is `#101820`

It is not a taste pick. The first candidate, `#16242e`, drops `ERROR` to
**4.43:1**, below AA, so an error rendered on the current row would fail. Every
informational token measured against `#101820`:

| Token | Ratio on `#101820` |
|---|---|
| `ERROR` | 5.00 |
| `TEXT_3` | 5.38 |
| `TEXT_2` | 6.99 |
| `ACCENT` | 7.41 |
| `SIGNAL` | 9.62 |
| `SELECTED` | 14.99 |
| `TEXT` | 15.69 |

`ACCENT #4bb3d4` measures 7.98:1 on `BG` and 8.29:1 on `BG_BASE`.

## 6. Sidebar states

Each row is two lines: label, then short description.

Four step states, each with its own marker. **The step number is always present**,
because `1`-`6` jump directly to a step and hiding the number on completed rows
would hide that affordance exactly where a user is most likely to go back.

| State | Row prefix | Label | Description | Fill |
|---|---|---|---|---|
| current | `▌` bar in `ACCENT`, then number | `SELECTED` bold | `TEXT_2` | `SURFACE_CURRENT` |
| completed | `✓` in `ACCENT`, then number | `TEXT_3` | `TEXT_3` | none |
| available | space, then number | `TEXT_2` | `TEXT_3` | none |
| locked | `·`, then number | `TEXT_3` | `TEXT_3` | none |

So a row reads `▌ 4 Password`, `✓ 2 Settings`, `  3 Input`, `· 6 Output`.

Focus is an **overlay**, not a fifth state: the existing reverse treatment is
retained and composes with whichever of the four the row is in.

Locked and available now differ by marker and label brightness rather than being
identical. Completed recedes rather than sitting level with available, because a
finished step is the one you least need to look at.

`TEXT_4` carries no text in this design. It stays barred from informational text
by the existing guard, and the locked state uses `TEXT_3` for that reason.

## 7. Surfaces and borders

- App root becomes `BG_BASE`. Sidebar and step pane stay `BG`, so the panels read
  as raised.
- The sidebar's right border moves from `BORDER` to `BORDER_STRONG` (`#303032`),
  which is the visible edge doing the work the 1.04:1 tint cannot.

Both are reinforcement under section 4 and neither is load-bearing.

## 8. Keyboard step navigation

### The defect

`Binding("left", "prev_step")` and `Binding("right", "next_step")` are declared
without `priority`, so a focused widget that wants arrows takes them first.
Measured, moving one step with the arrow key:

| Step | Focus lands on | Arrow navigates? |
|---|---|---|
| Mode | `RadioSet` | no |
| Settings | `Select` | yes |
| Input | `RadioSet` | no |
| Password | `Input` | no |
| Review | `Button` | yes |
| Output | `TextArea` | no |

Four of six steps fail, and F1 help advertises "Left/Right Prev/Next step"
regardless, so the app documents behaviour it does not deliver. `Ctrl+E` and
`Ctrl+D` hit this same problem earlier and were fixed with `priority=True`;
Left/Right were left behind.

`priority=True` is **not** available here: it would take Left/Right away from the
password field, where they must move the cursor.

### Choosing a key

The criterion is a key that reaches the app on all six steps, in both directions,
without being claimed by any focused widget. Measured:

| Candidate | Result |
|---|---|
| `ctrl+right` | claimed by `Input` (word jump) |
| `shift+right` | claimed by `Input` (selection) |
| `pageup` | claimed by `TextArea` on Output (scrolling) |
| `ctrl+p` | claimed globally by Textual |
| `alt+left` / `alt+right` | free on all six |
| `f2` / `f3` | free on all six |

### Decision

- **`F2` previous step, `F3` next step**, shown in the footer. Free on all six
  steps, consistent with the existing `F1` help binding, and function keys
  transmit more reliably over SSH than Alt, which many terminals send as a
  special character rather than Meta. The reporter is on SSH, so a fix that is
  itself flaky over SSH is not a fix.
- **`Alt+Left` / `Alt+Right` as hidden aliases.** Verified free, costs two lines,
  and matches the browser-style convention for anyone whose terminal passes Alt
  through.
- **`Left` / `Right` retained unchanged.** They work where nothing claims them and
  cost nothing.
- **F1 help text corrected** to describe what is true, including `Esc` to return
  to the sidebar.

## 9. Test and guard changes

1. **Extend the contrast guard to every (token, surface) pair.**
   `test_every_text_token_passes_aa_against_the_background` measures against `BG`
   only. Once more than one surface exists that guard stops answering the real
   question. Extending it is what caught the `ERROR` failure in section 5, before
   any code changed.
2. **Sanction `ACCENT`** on its state selectors, and assert it never appears on a
   selector sanctioned for `SIGNAL`, mirroring the existing amber guard.
3. **New: state is distinguishable without colour.** Assert the four sidebar step
   states use four distinct row prefixes, so the hierarchy survives a monochrome
   or low-colour terminal. Focus is an overlay and is excluded, since it composes
   with the other four rather than replacing them. This encodes section 4 rather
   than trusting it.
4. **New: step navigation works from every step.** Press the navigation key on
   each of the six steps and assert the step changed. The absence of this test is
   why the defect shipped documented but broken.
5. **Regenerate the six exported SVGs** and re-pin `TestRenderedPaletteIsClosed`,
   which pins the rendered colour set including cell backgrounds.
6. **Update the token-value guard** to the new token list.

## 10. Non-goals

- No change to the six steps, their order, or the wizard flow.
- No change to any cryptographic behaviour, the ciphertext format, or the CLI.
- No new widgets and no layout restructuring beyond the sidebar row treatment and
  the two surface changes in section 7.
- No animation or motion.
- Amber's meaning is not revisited.

## 11. Verification

- Full suite green, `ruff` and `bandit` clean.
- The four new or extended guards in section 9 confirmed red before the change
  and green after, so each is proven capable of failing.
- Screens re-exported and reviewed as rendered, not as source.
- Contrast re-checked with `scripts/check_contrast.py` extended to the new
  surfaces.

## 12. Known limitation

This cannot be verified on the reporter's hardware from here. The design reduces
the dependency on colour fidelity to the point where a 16-colour terminal should
still distinguish all five states by marker and weight, but "should" is doing
real work in that sentence. Confirmation needs a look on the Pi.

The output of `echo "TERM=$TERM COLORTERM=$COLORTERM colors=$(tput colors)"` on
that machine would remove the remaining uncertainty about how much colour
survives the connection.
