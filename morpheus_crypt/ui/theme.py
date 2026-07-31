"""Theme tokens and CSS for the MORPHEUS wizard UI.

Visual system: docs/design/2026-07-28-terminal-visual-system.md
Translated from Replicant's `signal-instrument` spec. Warm graphite surfaces,
one semantic accent, data brighter than chrome.
"""

from __future__ import annotations

# -- Surfaces ----------------------------------------------------------------
# One background only. The source system's four surface tiers sit 1.06-1.10:1
# apart, which reads as depth in a browser (large fills, hairlines, shadows) and
# as one flat colour in a terminal. Borders carry elevation here instead.
BG              = "#0e0e11"    # warm graphite, deliberately not blue-black

# Borders are the source system's alpha hairlines composited onto BG, since
# Textual has no alpha channel.
BORDER          = "#212124"    # rgba(255,255,255,.08) over BG
BORDER_STRONG   = "#303032"    # rgba(255,255,255,.14) over BG
BORDER_FOCUS    = "#ecebe6"    # focus must be unmistakable; see the spec

# -- Text tiers --------------------------------------------------------------
# Data is the brightest thing on screen; chrome recedes. This replaces the
# source system's mono-vs-sans distinction, which a terminal cannot express.
TEXT            = "#f1f0ec"    # data and values          16.90:1 AAA
TEXT_2          = "#a3a29b"    # body prose                7.52:1 AAA
TEXT_3          = "#8f8d84"    # uppercase micro-labels    5.79:1 AA
TEXT_4          = "#5f5e58"    # decoration + disabled controls    2.96:1

# -- Semantic ----------------------------------------------------------------
SELECTED        = "#ecebe6"    # active step, primary button, selection
SIGNAL          = "#f4b23e"    # EXPOSED SECRET MATERIAL ONLY. Nothing else.
ERROR           = "#e5594f"    # errors, refusals, weak-password floor

# Tokens that may render informational text. TEXT_4 is absent by design: it
# fails AA and is bounded to decoration and non-focusable disabled controls.
TEXT_TOKENS = frozenset({"TEXT", "TEXT_2", "TEXT_3", "SELECTED", "SIGNAL", "ERROR"})

# The stylesheet names its colours as Textual CSS variables rather than splicing
# hex in with `""" + BG + """`. The names then survive into WIZARD_CSS itself,
# so the guards in tests/test_theme.py parse real CSS instead of reconstructing
# Python concatenation from this file's source text. That closes two whole
# classes of bug: `"""+SIGNAL+"""` written without spaces was identical Python
# but invisible to the old source parser, and ordinary reformatting (a grouped
# selector, a brace on its own line) made it name the wrong selector.
#
# The `m-` prefix is not decoration. Textual 8.2.8 ships 168 built-in CSS
# variables and `$text`, `$border` and `$error` are three of them, so declaring
# those names unprefixed would silently repoint every Textual widget in the app,
# not just our own rules. Namespacing keeps the blast radius at our stylesheet.
#
# Declared here out of the constants above, so the hex still has exactly one
# home and the Python names stay importable by the steps and the tests.
_VARS = "\n".join(
    f"${name}: {value};"
    for name, value in (
        ("m-bg", BG), ("m-border", BORDER), ("m-border-strong", BORDER_STRONG),
        ("m-border-focus", BORDER_FOCUS), ("m-text", TEXT), ("m-text-2", TEXT_2),
        ("m-text-3", TEXT_3), ("m-text-4", TEXT_4), ("m-selected", SELECTED),
        ("m-signal", SIGNAL), ("m-error", ERROR),
    )
)

# One caution when editing the prose below. bandit's B608 scans string literals
# for SQL and its pattern is `select\\s.*from\\s` with DOTALL, so a `Select`
# selector anywhere above the word "from" anywhere below reads as SELECT ... FROM
# and fails the build at exit 1. Say "mirrors" or "taken out of" instead. The
# finding is spurious, but suppressing it would mean a blanket nosec over 500
# lines of CSS, which is worse than avoiding one word.
WIZARD_CSS = _VARS + """
Screen {
    background: $m-bg;
    layers: base gate;
}

/* The declared minimum terminal, enforced in app.py against MIN_WIDTH and
   MIN_HEIGHT. Below it the sidebar drops step 6 and the labels truncate, so the
   first thing a user saw at the standard 80x24 default was a clipped wizard.
   Nothing was unreachable, which is why this reads as a presentation choice
   rather than a bug, and why it needs stating rather than fixing by reflow: six
   steps of key material and cipher settings do not belong in 24 rows.

   An overlay on its own layer, not a pushed Screen. The wizard stays mounted
   underneath, so dragging the window small and back again loses no input and no
   finished result -- the same property the derived-staleness fix exists to
   protect. A Screen push would also fight the exclusive worker that mounts
   steps.

   No accent here. The window being small is a condition, not an error and not
   exposed secret material, so it takes the ordinary text tiers. */
#size-gate {
    layer: gate;
    display: none;
    width: 100%;
    height: 100%;
    background: $m-bg;
    align: center middle;
    padding: 1 2;
}

#size-gate-title {
    width: 100%;
    text-align: center;
    color: $m-text;
    text-style: bold;
}

#size-gate-detail {
    width: 100%;
    text-align: center;
    color: $m-text-2;
    padding-top: 1;
}

/* Textual answers "what is focused" twice: a border, and
   `background-tint: $foreground 5%`, which lifts the surface to a second
   near-black. The spec allows exactly one background (§1) and makes focus the
   near-white BORDER_FOCUS ring (§5), so the tint is switched off rather than
   repointed. It had never rendered before, because nothing in the wizard ever
   held focus; once a step takes the keyboard it appears on every focusable
   widget. Two off-palette values stop rendering as a result: the lifted
   surface, and the closed dropdown's arrow, which is `$foreground 50%` and so
   composites against whatever sits behind it. */
*:focus {
    background-tint: $m-bg 0%;
}

Header {
    background: $m-bg;
    color: $m-text;
}

Footer {
    background: $m-bg;
    color: $m-text-3;
}

/* Footer renders its bindings through FooterKey, which carries its own
   component classes and its own background. Styling `Footer` alone leaves
   both at Textual's defaults, and the default key cap is a saturated amber
   close enough to the reserved accent to break the "amber means exposed
   secret material" rule on every screen. The key cap is the affordance, so
   it takes TEXT_2; the description is supporting prose, so it takes TEXT_3.
   Guarded by TestRenderedAmberIsReserved, which checks the rendered pixels
   rather than this file. */

FooterKey {
    background: $m-bg;
}

FooterKey .footer-key--key {
    background: $m-bg;
    color: $m-text-2;
    text-style: bold;
}

FooterKey .footer-key--description {
    background: $m-bg;
    color: $m-text-3;
}

FooterKey:hover {
    background: $m-border;
    color: $m-selected;
}

/* Textual draws this divider with `vkey $foreground 20%`, which composites to
   an off-palette grey. Name the token instead. */
FooterKey.-command-palette {
    border-left: vkey $m-border-strong;
}

FooterLabel {
    background: $m-bg;
    color: $m-text-3;
}

/* ── Top bar ────────────────────────────────────────────────────── */

/* height is the outer box in Textual, so border and padding come out of it.
   This was `height: 3; padding: 1 2`, which is 1 border row plus 2 padding
   rows and therefore *zero* content rows: the title and the "Step 3/6"
   indicator were laid out but never painted, and every screen opened with a
   blank three-row band. Vertical padding is gone and the height covers one
   content row plus the border. */
#top-bar {
    dock: top;
    height: 2;
    background: $m-bg;
    color: $m-text-3;
    padding: 0 2;
    border-bottom: heavy $m-border;
}

#top-title {
    width: 1fr;
    color: $m-selected;
    text-style: bold;
}

#top-step {
    width: auto;
    color: $m-text-3;
}

/* ── Sidebar ────────────────────────────────────────────────────── */

#sidebar {
    width: 28;
    background: $m-bg;
    border-right: heavy $m-border;
    padding: 1 0;
    overflow-y: auto;
}

.sidebar-item {
    height: 2;
    padding: 0 1;
    color: $m-text-3;
    margin: 0 0 1 0;
}

.sidebar-item:focus {
    background: $m-bg;
    color: $m-selected;
    text-style: bold reverse;
}

.sidebar-item.--current {
    color: $m-selected;
    text-style: bold;
    background: $m-bg;
}

.sidebar-item.--completed {
    color: $m-text-2;
}

.sidebar-item.--locked {
    color: $m-text-3;
}

/* ── Step panel (right pane) ────────────────────────────────────── */

#step-container {
    width: 1fr;
    height: 1fr;
    padding: 1 2;
    background: $m-bg;
    overflow-y: auto;
}

/* The step panel must size to its content, not to the container.

   `overflow-y: auto` above was doing nothing. The panels are plain `Vertical`
   subclasses with no height rule, so they took the default `1fr` -- exactly
   the container's height. The container therefore saw a child that fitted and
   reported `max_scroll_y == 0`, while that child's own children laid out past
   its bottom edge and composited over the nav bar.

   At the 100x30 minimum this put Settings' Advanced options at rows 35-49 with
   no way to scroll to them, and a click where Pad rendered landed on `btn-back`
   and navigated backwards. Tab still reached them, so the wizard was keyboard
   navigable to controls that were not on screen. `TestControlsAreReachableAtTheMinimum`
   fails if any focusable control stops being scrollable into view. */
#step-container > * {
    height: auto;
}

/* Now that the panes genuinely scroll, a scrollbar renders for the first time,
   and Textual's default one is blue -- the same way the blue selection band got
   in. It is chrome, not content, so it takes the quietest tokens that still
   read: the trough disappears into the pane and the thumb sits at the border
   tier, lifting one step to TEXT_4 only under the pointer. No accent: a
   scrollbar is a position indicator, not a signal, and the accent is reserved. */
#step-container, #output-area, #input-editor {
    scrollbar-background: $m-bg;
    scrollbar-background-hover: $m-bg;
    scrollbar-background-active: $m-bg;
    scrollbar-color: $m-border-strong;
    scrollbar-color-hover: $m-text-4;
    scrollbar-color-active: $m-text-4;
    scrollbar-corner-color: $m-bg;
}

.step-title {
    color: $m-text;
    text-style: bold underline;
    padding: 0 0 1 0;
    width: 100%;
}

.step-subtitle {
    color: $m-text-2;
    padding: 0 0 1 0;
    width: 100%;
}

.step-hint {
    color: $m-text-3;
    padding: 0 0 1 0;
    width: 100%;
    height: auto;
}

.field-label {
    color: $m-text-3;
    width: 16;
    padding: 0 1 0 0;
}

.field-row {
    height: 3;
    layout: horizontal;
    align: left middle;
    margin: 0 0 0 0;
}

.field-help {
    color: $m-text-3;
    padding: 0 0 1 2;
    height: auto;
    width: 100%;
}

/* ── Navigation buttons ─────────────────────────────────────────── */

/* Same border-box arithmetic as #top-bar. A bordered Button occupies 3 rows,
   and `height: 3` here left only 2 after the top border, so Back / Next /
   Execute were clipped to a sliver — the primary navigation of the wizard
   rendered as two stubs above the footer. 4 = 1 border + 3 button rows. */
#nav-bar {
    height: 4;
    layout: horizontal;
    align: center middle;
    padding: 0 2;
    dock: bottom;
    margin-bottom: 1;
    background: $m-bg;
    border-top: heavy $m-border;
}

#nav-bar Button {
    margin: 0 1;
    min-width: 14;
}

#btn-back {
    background: $m-bg;
    color: $m-text-3;
    border: heavy $m-border;
}

#btn-back:hover {
    background: $m-border;
    color: $m-selected;
}

#btn-next {
    background: $m-selected;
    color: $m-bg;
    text-style: bold;
    border: heavy $m-border-strong;
}

#btn-next:hover {
    background: $m-text;
}

/* opacity: 1 overrides Textual's own disabled dimming, which composites the
   widget at 0.7 and produced a colour belonging to no token. TEXT_4 is already
   the documented token for disabled controls, so the disabled state is carried
   by our own colours and the rendered palette stays closed. Only visible once
   the nav bar stopped clipping its buttons; before that the label row was
   never painted. */
#btn-next:disabled {
    background: $m-bg;
    color: $m-text-4;
    border: heavy $m-border;
    opacity: 1;
    text-opacity: 1;
}

#btn-run {
    background: $m-selected;
    color: $m-bg;
    text-style: bold;
    border: heavy $m-border-strong;
}

#btn-run:hover {
    background: $m-text;
}

/* ── Shared widget styles ───────────────────────────────────────── */

Input {
    background: $m-bg;
    border: heavy $m-border;
    color: $m-text;
}

Input:focus {
    border: heavy $m-border-focus;
}

Input.-invalid {
    border: heavy $m-error;
}

/* A revealed password is exposed secret material, so it takes the accent for
   exactly as long as it is legible. Applied by the Show-password checkbox
   handler, not by a pseudo-class: Textual has no selector for `password=False`.
   Masked input keeps TEXT above, because bullets are not secret. */
Input.-revealed {
    color: $m-signal;
}

RadioButton.-on {
    color: $m-selected;
    text-style: bold;
}

TextArea {
    background: $m-bg;
    color: $m-text;
    border: tall $m-border;
}

TextArea:focus {
    border: tall $m-border-focus;
}

/* No border on the outer Select. Textual nests a SelectCurrent inside it that
   carries its own, so bordering both drew two rectangles one cell apart around
   every dropdown — a 62x5 frame wrapping a 60x3 frame, and both went bright
   white on focus. The inner one is the one Textual styles for focus, so the
   outer is the duplicate and is removed. */
Select {
    background: $m-bg;
    border: none;
    color: $m-text;
}

/* The focus ring on a closed dropdown. Textual draws it on the inner
   SelectCurrent rather than on the widget itself, so the rule above never
   reaches it and it stayed at Textual's own $border, a saturated blue. Same
   class of miss as the toggle rules further down: a component the type
   selector cannot see. Invisible until a step started taking focus, because
   the blurred state resolves to a grey that was already accounted for.

   The tint goes here too, and cannot be left to the `*:focus` rule near the
   top: the pseudo-class sits on the outer widget while the tint lands on this
   inner one, so the universal selector never matches it. */
Select:focus > SelectCurrent {
    border: tall $m-border-focus;
    background-tint: $m-bg 0%;
}

SelectOverlay {
    background: $m-bg;
    color: $m-text;
    border: solid $m-border;
}

/* Textual gives SelectCurrent `background: $surface`, a neutral grey. That is a
   second surface, and a cooler one than ours, sitting behind the chosen value.
   This system has one background and lets borders carry elevation, so the panel
   is repointed rather than kept. */
SelectCurrent {
    border: tall $m-border;
    color: $m-text;
    background: $m-bg;
}

Checkbox {
    background: transparent;
    color: $m-text-2;
    padding: 0 0 0 0;
}

Checkbox:focus {
    color: $m-selected;
}

RadioButton {
    background: transparent;
    color: $m-text-2;
}

RadioButton:focus {
    color: $m-selected;
}

RadioSet {
    background: transparent;
    border: none;
}

/* ── Textual widget internals ───────────────────────────────────────
   Textual paints parts of these widgets through component classes, which a
   plain type selector never reaches: the rules above set `color` on Checkbox
   and RadioButton and it had no effect on either the glyph or the selected
   row. Left alone, Textual's own theme supplies the colour, which is how a
   blue selection band and a green bullet survived a palette rewrite. The
   selectors below mirror ToggleButton/RadioSet/SelectCurrent DEFAULT_CSS on
   Textual 8.2.8; check them again on upgrade. */

/* The selected row. Textual fills it with $block-cursor-background, which
   resolves to primary blue and reads as a second accent. Selection is
   near-white here, and on one background it needs no fill at all. */
ToggleButton:focus > .toggle--label,
RadioSet:focus > RadioButton.-selected > .toggle--label,
RadioSet:blur > RadioButton.-selected > .toggle--label {
    background: $m-bg;
    color: $m-selected;
}

/* The check/bullet glyph. Textual's $text-success is a green that means
   nothing in this system; checked is a selection state, so it reads as one. */
ToggleButton.-on > .toggle--button,
RadioSet > RadioButton.-on .toggle--button {
    color: $m-selected;
}

/* The caret. Textual fills the cell with $input-cursor-background, a near-white
   that is close to our own near-white without being it. A caret is not
   structural chrome: it says where typing will land, which is why it is pointed
   at a token rather than added to the rendered keep-list. Both widgets are
   listed because a caret renders only while its field has focus, so leaving
   either one would make the rendered guard pass on which field happened to be
   focused when the screenshot was taken. */
TextArea > .text-area--cursor,
Input > .input--cursor {
    background: $m-selected;
    color: $m-bg;
}

/* The selection band. Textual's Input selects its whole value the moment the
   field takes focus, so this is not an edge case reached by dragging: it is on
   screen every time the user reaches the password step. Left at Textual's
   defaults it painted $primary-lighten-1 at 40% behind the value and
   $foreground on it, neither of which is in the palette, and the rendered
   guard caught them only on the runs where focus won the race.
   BORDER_STRONG reads as a raised band without competing with the caret.
   Listed for both widgets for the same reason as the caret above.
   The two offending values are named by variable rather than quoted as hex:
   a raw literal here would trip the no-raw-hex guard, and writing up a leak
   by quoting it verbatim is how one got re-introduced before. */
TextArea > .text-area--selection,
Input > .input--selection {
    background: $m-border-strong;
    color: $m-text;
}

/* A revealed password is exposed secret material whether or not it happens to
   be selected, so the selection must not repaint it back to ordinary text.
   Without this, selecting a revealed password renders it at TEXT and the
   accent rule silently stops holding exactly where it matters most. */
Input.-revealed > .input--selection {
    color: $m-signal;
}

/* Same rule, same reason, for the other field that holds secret material.
   Selecting the output pane to copy it by hand is an ordinary thing to do, and
   without this the ciphertext loses the accent for exactly as long as it is
   highlighted. SIGNAL on BORDER_STRONG is 7.08:1. */
#output-area > .text-area--selection {
    color: $m-signal;
}

/* The chosen value in a closed Select. Textual routes it through an inner
   Static, so `SelectCurrent { color: ... }` above misses it and the value
   rendered at Textual's default foreground instead of TEXT. */
SelectCurrent.-has-value Static#label {
    color: $m-text;
}

Button {
    background: $m-bg;
    color: $m-text-2;
    border: tall $m-border;
}

Button:hover {
    background: $m-border;
    color: $m-selected;
}

Button:focus {
    border: tall $m-border-focus;
}

Collapsible {
    background: transparent;
    border: none;
    padding: 0 0 0 0;
}

CollapsibleTitle {
    color: $m-text-3;
    background: transparent;
    padding: 1 0 0 0;
}

CollapsibleTitle:hover {
    color: $m-selected;
}

CollapsibleTitle:focus {
    color: $m-selected;
}

/* ── Step-specific ──────────────────────────────────────────────── */

.mode-choice {
    height: auto;
    padding: 1 0;
}

#mode-radio {
    background: transparent;
    border: none;
    padding: 0;
}

#mode-radio RadioButton {
    padding: 0 0 0 0;
    margin: 0 0 1 0;
    height: auto;
}

.settings-section {
    height: auto;
    padding: 0 0 1 0;
}

#input-tabs {
    height: auto;
    padding: 0 0 1 0;
    background: transparent;
    border: none;
}

#input-editor {
    height: 12;
    min-height: 8;
}

#input-stats {
    color: $m-text-3;
    text-align: right;
    height: 1;
    width: 100%;
}

#file-path-input {
    width: 1fr;
}

.password-field {
    width: 40;
}

#strength-bar {
    width: 30;
}

#match-indicator {
    color: $m-selected;
    padding: 0 0 0 2;
}

.review-table {
    height: auto;
    padding: 0 0 1 0;
}

.review-row {
    height: 1;
    layout: horizontal;
    padding: 0 0 0 0;
}

.review-key {
    width: 18;
    color: $m-text-3;
}

.review-val {
    width: 1fr;
    color: $m-text;
}

.warning-text {
    color: $m-error;
    padding: 1 0 0 0;
}

#output-area {
    height: 10;
    min-height: 6;
    color: $m-signal;
}

#output-status {
    height: 1;
    color: $m-text-3;
}

#output-actions {
    height: 3;
    layout: horizontal;
    padding: 1 0 0 0;
}

#output-actions Button {
    min-width: 14;
    margin: 0 1 0 0;
}

#btn-copy {
    background: $m-selected;
    color: $m-bg;
    text-style: bold;
    border: tall $m-border-strong;
}

#btn-copy:hover {
    background: $m-text;
}

#btn-clear {
    background: $m-bg;
    color: $m-error;
    border: tall $m-border;
}

#btn-clear:hover {
    background: $m-bg;
}

#btn-stop-timer {
    background: $m-bg;
    color: $m-text-3;
    border: tall $m-border;
}

#countdown-label {
    color: $m-signal;
    text-style: bold;
    width: auto;
    padding: 0 0 0 2;
}

/* ── Password step buttons ──────────────────────────────────────── */

.pwd-action-btn {
    min-width: 8;
    margin: 0 0 0 1;
}

#copy-pwd {
    background: $m-bg;
    color: $m-text-2;
    border: tall $m-border;
}

#copy-pwd:hover {
    color: $m-selected;
    background: $m-border;
}

#pwd-feedback {
    color: $m-text-3;
    height: auto;
    padding: 0 0 0 0;
}

/* ── Section dividers ───────────────────────────────────────────── */

.section-divider {
    height: 1;
    color: $m-text-4;
    margin: 1 0;
}
"""
