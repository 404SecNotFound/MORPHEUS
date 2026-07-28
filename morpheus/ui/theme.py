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
