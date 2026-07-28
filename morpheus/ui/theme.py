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

# One caution when editing the prose below. bandit's B608 scans concatenated
# string literals for SQL and its pattern is `select\\s.*from\\s` with DOTALL,
# so a `Select` selector anywhere above the word "from" anywhere below reads as
# SELECT ... FROM and fails the build at exit 1. Say "mirrors" or "taken out of"
# instead. The finding is spurious, but suppressing it would mean a blanket
# nosec over 500 lines of CSS, which is worse than avoiding one word.
WIZARD_CSS = """
Screen {
    background: """ + BG + """;
}

Header {
    background: """ + BG + """;
    color: """ + TEXT + """;
}

Footer {
    background: """ + BG + """;
    color: """ + TEXT_3 + """;
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
    background: """ + BG + """;
}

FooterKey .footer-key--key {
    background: """ + BG + """;
    color: """ + TEXT_2 + """;
    text-style: bold;
}

FooterKey .footer-key--description {
    background: """ + BG + """;
    color: """ + TEXT_3 + """;
}

FooterKey:hover {
    background: """ + BORDER + """;
    color: """ + SELECTED + """;
}

/* Textual draws this divider with `vkey $foreground 20%`, which composites to
   an off-palette grey. Name the token instead. */
FooterKey.-command-palette {
    border-left: vkey """ + BORDER_STRONG + """;
}

FooterLabel {
    background: """ + BG + """;
    color: """ + TEXT_3 + """;
}

/* ── Top bar ────────────────────────────────────────────────────── */

#top-bar {
    dock: top;
    height: 3;
    background: """ + BG + """;
    color: """ + TEXT_3 + """;
    padding: 1 2;
    border-bottom: heavy """ + BORDER + """;
}

#top-title {
    width: 1fr;
    color: """ + SELECTED + """;
    text-style: bold;
}

#top-step {
    width: auto;
    color: """ + TEXT_3 + """;
}

/* ── Sidebar ────────────────────────────────────────────────────── */

#sidebar {
    width: 28;
    background: """ + BG + """;
    border-right: heavy """ + BORDER + """;
    padding: 1 0;
    overflow-y: auto;
}

.sidebar-item {
    height: 2;
    padding: 0 1;
    color: """ + TEXT_3 + """;
    margin: 0 0 1 0;
}

.sidebar-item:focus {
    background: """ + BG + """;
    color: """ + SELECTED + """;
    text-style: bold reverse;
}

.sidebar-item.--current {
    color: """ + SELECTED + """;
    text-style: bold;
    background: """ + BG + """;
}

.sidebar-item.--completed {
    color: """ + TEXT_2 + """;
}

.sidebar-item.--locked {
    color: """ + TEXT_3 + """;
}

/* ── Step panel (right pane) ────────────────────────────────────── */

#step-container {
    width: 1fr;
    height: 1fr;
    padding: 1 2;
    background: """ + BG + """;
    overflow-y: auto;
}

.step-title {
    color: """ + TEXT + """;
    text-style: bold underline;
    padding: 0 0 1 0;
    width: 100%;
}

.step-subtitle {
    color: """ + TEXT_2 + """;
    padding: 0 0 1 0;
    width: 100%;
}

.step-hint {
    color: """ + TEXT_3 + """;
    padding: 0 0 1 0;
    width: 100%;
    height: auto;
}

.field-label {
    color: """ + TEXT_3 + """;
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
    color: """ + TEXT_3 + """;
    padding: 0 0 1 2;
    height: auto;
    width: 100%;
}

/* ── Navigation buttons ─────────────────────────────────────────── */

#nav-bar {
    height: 3;
    layout: horizontal;
    align: center middle;
    padding: 0 2;
    dock: bottom;
    background: """ + BG + """;
    border-top: heavy """ + BORDER + """;
}

#nav-bar Button {
    margin: 0 1;
    min-width: 14;
}

#btn-back {
    background: """ + BG + """;
    color: """ + TEXT_3 + """;
    border: heavy """ + BORDER + """;
}

#btn-back:hover {
    background: """ + BORDER + """;
    color: """ + SELECTED + """;
}

#btn-next {
    background: """ + SELECTED + """;
    color: """ + BG + """;
    text-style: bold;
    border: heavy """ + BORDER_STRONG + """;
}

#btn-next:hover {
    background: """ + TEXT + """;
}

#btn-next:disabled {
    background: """ + BG + """;
    color: """ + TEXT_4 + """;
    border: heavy """ + BORDER + """;
}

#btn-run {
    background: """ + SELECTED + """;
    color: """ + BG + """;
    text-style: bold;
    border: heavy """ + BORDER_STRONG + """;
}

#btn-run:hover {
    background: """ + TEXT + """;
}

/* ── Shared widget styles ───────────────────────────────────────── */

Input {
    background: """ + BG + """;
    border: heavy """ + BORDER + """;
    color: """ + TEXT + """;
}

Input:focus {
    border: heavy """ + BORDER_FOCUS + """;
}

Input.-invalid {
    border: heavy """ + ERROR + """;
}

/* A revealed password is exposed secret material, so it takes the accent for
   exactly as long as it is legible. Applied by the Show-password checkbox
   handler, not by a pseudo-class: Textual has no selector for `password=False`.
   Masked input keeps TEXT above, because bullets are not secret. */
Input.-revealed {
    color: """ + SIGNAL + """;
}

RadioButton.-on {
    color: """ + SELECTED + """;
    text-style: bold;
}

TextArea {
    background: """ + BG + """;
    color: """ + TEXT + """;
    border: tall """ + BORDER + """;
}

TextArea:focus {
    border: tall """ + BORDER_FOCUS + """;
}

Select {
    background: """ + BG + """;
    border: tall """ + BORDER + """;
    color: """ + TEXT + """;
}

Select:focus {
    border: tall """ + BORDER_FOCUS + """;
}

SelectOverlay {
    background: """ + BG + """;
    color: """ + TEXT + """;
    border: solid """ + BORDER + """;
}

SelectCurrent {
    color: """ + TEXT + """;
}

Checkbox {
    background: transparent;
    color: """ + TEXT_2 + """;
    padding: 0 0 0 0;
}

Checkbox:focus {
    color: """ + SELECTED + """;
}

RadioButton {
    background: transparent;
    color: """ + TEXT_2 + """;
}

RadioButton:focus {
    color: """ + SELECTED + """;
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
    background: """ + BG + """;
    color: """ + SELECTED + """;
}

/* The check/bullet glyph. Textual's $text-success is a green that means
   nothing in this system; checked is a selection state, so it reads as one. */
ToggleButton.-on > .toggle--button,
RadioSet > RadioButton.-on .toggle--button {
    color: """ + SELECTED + """;
}

/* The chosen value in a closed Select. Textual routes it through an inner
   Static, so `SelectCurrent { color: ... }` above misses it and the value
   rendered at Textual's default foreground instead of TEXT. */
SelectCurrent.-has-value Static#label {
    color: """ + TEXT + """;
}

Button {
    background: """ + BG + """;
    color: """ + TEXT_2 + """;
    border: tall """ + BORDER + """;
}

Button:hover {
    background: """ + BORDER + """;
    color: """ + SELECTED + """;
}

Button:focus {
    border: tall """ + BORDER_FOCUS + """;
}

Collapsible {
    background: transparent;
    border: none;
    padding: 0 0 0 0;
}

CollapsibleTitle {
    color: """ + TEXT_3 + """;
    background: transparent;
    padding: 1 0 0 0;
}

CollapsibleTitle:hover {
    color: """ + SELECTED + """;
}

CollapsibleTitle:focus {
    color: """ + SELECTED + """;
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
    color: """ + TEXT_3 + """;
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
    color: """ + SELECTED + """;
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
    color: """ + TEXT_3 + """;
}

.review-val {
    width: 1fr;
    color: """ + TEXT + """;
}

.warning-text {
    color: """ + ERROR + """;
    padding: 1 0 0 0;
}

#output-area {
    height: 10;
    min-height: 6;
    color: """ + SIGNAL + """;
}

#output-status {
    height: 1;
    color: """ + TEXT_3 + """;
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
    background: """ + SELECTED + """;
    color: """ + BG + """;
    text-style: bold;
    border: tall """ + BORDER_STRONG + """;
}

#btn-copy:hover {
    background: """ + TEXT + """;
}

#btn-clear {
    background: """ + BG + """;
    color: """ + ERROR + """;
    border: tall """ + BORDER + """;
}

#btn-clear:hover {
    background: """ + BG + """;
}

#btn-stop-timer {
    background: """ + BG + """;
    color: """ + TEXT_3 + """;
    border: tall """ + BORDER + """;
}

#countdown-label {
    color: """ + SIGNAL + """;
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
    background: """ + BG + """;
    color: """ + TEXT_2 + """;
    border: tall """ + BORDER + """;
}

#copy-pwd:hover {
    color: """ + SELECTED + """;
    background: """ + BORDER + """;
}

#pwd-feedback {
    color: """ + TEXT_3 + """;
    height: auto;
    padding: 0 0 0 0;
}

/* ── Section dividers ───────────────────────────────────────────── */

.section-divider {
    height: 1;
    color: """ + TEXT_4 + """;
    margin: 1 0;
}
"""
