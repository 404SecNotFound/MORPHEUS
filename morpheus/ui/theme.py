"""Theme tokens and CSS for the MORPHEUS wizard UI — Matrix Edition."""

from __future__ import annotations

# -- Matrix colour palette ---------------------------------------------------
BG              = "#030303"    # Near-black
SURFACE         = "#080C08"    # Green-black surface
ELEVATED        = "#0C140C"    # Elevated card background
BORDER          = "#0D3B0D"    # Green border
BORDER_BRIGHT   = "#00AA28"    # Bright green border (focus / active)

TEXT_PRIMARY     = "#00FF41"   # Classic Matrix phosphor green
TEXT_BODY        = "#00DD36"   # Readable body text
TEXT_SECONDARY   = "#00AA28"   # Labels / secondary info
TEXT_DIM         = "#007018"   # Dim hints
DISABLED         = "#0A2A0A"   # Barely visible

ACCENT          = "#00FF41"    # Bright Matrix green
ACCENT_HOVER    = "#33FF66"    # Hover state
ACCENT_DIM      = "#00CC33"    # Muted accent

SUCCESS         = "#39FF14"    # Neon green
WARNING         = "#FFD700"    # Gold (stands out intentionally)
ERROR           = "#FF3333"    # Red

WIZARD_CSS = """
Screen {
    background: """ + BG + """;
}

Header {
    background: """ + SURFACE + """;
    color: """ + TEXT_PRIMARY + """;
}

Footer {
    background: """ + SURFACE + """;
    color: """ + TEXT_SECONDARY + """;
}

/* ── Top bar ────────────────────────────────────────────────────── */

#top-bar {
    dock: top;
    height: 3;
    background: """ + SURFACE + """;
    color: """ + TEXT_SECONDARY + """;
    padding: 1 2;
    border-bottom: solid """ + BORDER + """;
}

#top-title {
    width: 1fr;
    color: """ + ACCENT + """;
    text-style: bold;
}

#top-step {
    width: auto;
    color: """ + TEXT_SECONDARY + """;
}

/* ── Sidebar ────────────────────────────────────────────────────── */

#sidebar {
    width: 22;
    background: """ + SURFACE + """;
    border-right: solid """ + BORDER + """;
    padding: 1 0;
}

.sidebar-item {
    height: 1;
    padding: 0 1;
    color: """ + TEXT_DIM + """;
}

.sidebar-item.--current {
    color: """ + ACCENT + """;
    text-style: bold;
    background: """ + ELEVATED + """;
}

.sidebar-item.--completed {
    color: """ + ACCENT_DIM + """;
}

.sidebar-item.--locked {
    color: """ + DISABLED + """;
}

/* ── Step panel (right pane) ────────────────────────────────────── */

#step-container {
    width: 1fr;
    height: 1fr;
    padding: 1 3;
    background: """ + BG + """;
    overflow-y: auto;
}

.step-title {
    color: """ + TEXT_PRIMARY + """;
    text-style: bold;
    padding: 0 0 1 0;
    width: 100%;
}

.step-subtitle {
    color: """ + TEXT_SECONDARY + """;
    padding: 0 0 1 0;
    width: 100%;
}

.field-label {
    color: """ + TEXT_SECONDARY + """;
    width: 16;
    padding: 0 1 0 0;
}

.field-row {
    height: 3;
    layout: horizontal;
    align: left middle;
    margin: 0 0 0 0;
}

/* ── Navigation buttons ─────────────────────────────────────────── */

#nav-bar {
    height: 3;
    layout: horizontal;
    align: center middle;
    padding: 0 2;
    dock: bottom;
    background: """ + SURFACE + """;
    border-top: solid """ + BORDER + """;
}

#nav-bar Button {
    margin: 0 1;
    min-width: 14;
}

#btn-back {
    background: """ + ELEVATED + """;
    color: """ + TEXT_SECONDARY + """;
    border: tall """ + BORDER + """;
}

#btn-back:hover {
    background: """ + BORDER + """;
    color: """ + ACCENT + """;
}

#btn-next {
    background: """ + ACCENT + """;
    color: """ + BG + """;
    text-style: bold;
    border: tall """ + ACCENT_DIM + """;
}

#btn-next:hover {
    background: """ + ACCENT_HOVER + """;
}

#btn-next:disabled {
    background: """ + DISABLED + """;
    color: """ + TEXT_DIM + """;
    border: tall """ + DISABLED + """;
}

#btn-run {
    background: """ + ACCENT + """;
    color: """ + BG + """;
    text-style: bold;
    border: tall """ + ACCENT_DIM + """;
}

#btn-run:hover {
    background: """ + ACCENT_HOVER + """;
}

/* ── Shared widget styles ───────────────────────────────────────── */

Input {
    background: """ + ELEVATED + """;
    border: tall """ + BORDER + """;
    color: """ + TEXT_PRIMARY + """;
}

Input:focus {
    border: tall """ + ACCENT + """;
}

Input.-invalid {
    border: tall """ + ERROR + """;
}

TextArea {
    background: """ + ELEVATED + """;
    color: """ + TEXT_PRIMARY + """;
    border: tall """ + BORDER + """;
}

TextArea:focus {
    border: tall """ + ACCENT + """;
}

Select {
    background: """ + ELEVATED + """;
    border: tall """ + BORDER + """;
    color: """ + TEXT_PRIMARY + """;
}

Select:focus {
    border: tall """ + ACCENT + """;
}

SelectOverlay {
    background: """ + ELEVATED + """;
    color: """ + TEXT_PRIMARY + """;
    border: solid """ + BORDER + """;
}

SelectCurrent {
    color: """ + TEXT_PRIMARY + """;
}

Checkbox {
    background: transparent;
    color: """ + TEXT_BODY + """;
    padding: 0 0 0 0;
}

Checkbox:focus {
    color: """ + ACCENT + """;
}

RadioButton {
    background: transparent;
    color: """ + TEXT_BODY + """;
}

RadioButton:focus {
    color: """ + ACCENT + """;
}

RadioSet {
    background: transparent;
    border: none;
}

Button {
    background: """ + ELEVATED + """;
    color: """ + TEXT_BODY + """;
    border: tall """ + BORDER + """;
}

Button:hover {
    background: """ + BORDER + """;
    color: """ + ACCENT + """;
}

Button:focus {
    border: tall """ + ACCENT + """;
}

Collapsible {
    background: transparent;
    border: none;
    padding: 0 0 0 0;
}

CollapsibleTitle {
    color: """ + TEXT_SECONDARY + """;
    background: transparent;
    padding: 1 0 0 0;
}

CollapsibleTitle:hover {
    color: """ + ACCENT + """;
}

CollapsibleTitle:focus {
    color: """ + ACCENT + """;
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
    color: """ + TEXT_SECONDARY + """;
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
    color: """ + ACCENT + """;
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
    color: """ + TEXT_SECONDARY + """;
}

.review-val {
    width: 1fr;
    color: """ + TEXT_PRIMARY + """;
}

.warning-text {
    color: """ + WARNING + """;
    padding: 1 0 0 0;
}

#output-area {
    height: 10;
    min-height: 6;
}

#output-status {
    height: 1;
    color: """ + TEXT_SECONDARY + """;
}

#output-actions {
    height: 3;
    layout: horizontal;
    padding: 1 0 0 0;
}

#output-actions Button {
    margin: 0 1 0 0;
}

#btn-copy {
    background: """ + ACCENT + """;
    color: """ + BG + """;
    text-style: bold;
    border: tall """ + ACCENT_DIM + """;
}

#btn-copy:hover {
    background: """ + ACCENT_HOVER + """;
}

#btn-clear {
    background: """ + ELEVATED + """;
    color: """ + ERROR + """;
    border: tall """ + BORDER + """;
}

#btn-clear:hover {
    background: """ + BORDER + """;
}

#btn-stop-timer {
    background: """ + ELEVATED + """;
    color: """ + TEXT_SECONDARY + """;
    border: tall """ + BORDER + """;
}

#countdown-label {
    color: """ + WARNING + """;
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
    background: """ + ELEVATED + """;
    color: """ + ACCENT_DIM + """;
    border: tall """ + BORDER + """;
}

#copy-pwd:hover {
    color: """ + ACCENT + """;
    background: """ + BORDER + """;
}

#pwd-feedback {
    color: """ + TEXT_DIM + """;
    height: auto;
    padding: 0 0 0 0;
}

/* ── Section dividers ───────────────────────────────────────────── */

.section-divider {
    height: 1;
    color: """ + BORDER + """;
    margin: 1 0;
}
"""
