"""Theme tokens and CSS for the MORPHEUS wizard UI."""

from __future__ import annotations

# -- Colour palette ----------------------------------------------------------
BG = "#0F1115"
SURFACE = "#151A21"
ELEVATED = "#1B2230"
BORDER = "#2A3442"
TEXT_PRIMARY = "#E6EAF2"
TEXT_SECONDARY = "#A9B1C3"
DISABLED = "#5B6476"
ACCENT = "#5B8CFF"
SUCCESS = "#6BCB77"
WARNING = "#E2B93B"
ERROR = "#E05C5C"

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

/* ── Top bar ─────────────────────────────────────────────────── */

#top-bar {
    dock: top;
    height: 1;
    background: """ + SURFACE + """;
    color: """ + TEXT_SECONDARY + """;
    padding: 0 2;
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

/* ── Sidebar ─────────────────────────────────────────────────── */

#sidebar {
    width: 18;
    background: """ + SURFACE + """;
    border-right: tall """ + BORDER + """;
    padding: 1 0;
}

.sidebar-item {
    height: 1;
    padding: 0 1;
    color: """ + TEXT_SECONDARY + """;
}

.sidebar-item.--current {
    color: """ + ACCENT + """;
    text-style: bold;
}

.sidebar-item.--completed {
    color: """ + SUCCESS + """;
}

.sidebar-item.--locked {
    color: """ + DISABLED + """;
}

/* ── Step panel (right pane) ─────────────────────────────────── */

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

/* ── Navigation buttons ──────────────────────────────────────── */

#nav-bar {
    height: 3;
    layout: horizontal;
    align: center middle;
    padding: 0 2;
    dock: bottom;
    background: """ + BG + """;
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
}

#btn-next {
    background: """ + ACCENT + """;
    color: """ + BG + """;
}

#btn-next:hover {
    background: #7BA3FF;
}

#btn-next:disabled {
    background: """ + BORDER + """;
    color: """ + DISABLED + """;
}

#btn-run {
    background: """ + SUCCESS + """;
    color: """ + BG + """;
}

#btn-run:hover {
    background: #85D88F;
}

/* ── Shared widget styles ────────────────────────────────────── */

Input {
    background: """ + ELEVATED + """;
    border: tall """ + BORDER + """;
    color: """ + TEXT_PRIMARY + """;
}

Input:focus {
    border: tall """ + ACCENT + """;
}

TextArea {
    background: """ + ELEVATED + """;
    color: """ + TEXT_PRIMARY + """;
}

Select {
    background: """ + ELEVATED + """;
}

Checkbox {
    background: transparent;
    color: """ + TEXT_PRIMARY + """;
}

RadioButton {
    background: transparent;
    color: """ + TEXT_PRIMARY + """;
}

RadioSet {
    background: transparent;
}

Button {
    background: """ + ELEVATED + """;
    color: """ + TEXT_PRIMARY + """;
    border: tall """ + BORDER + """;
}

/* ── Step-specific ───────────────────────────────────────────── */

.mode-choice {
    height: auto;
    padding: 1 0;
}

.settings-section {
    height: auto;
    padding: 0 0 1 0;
}

#input-tabs {
    height: auto;
    padding: 0 0 1 0;
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
    color: """ + SUCCESS + """;
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

#countdown-label {
    color: """ + WARNING + """;
    text-style: bold;
    width: auto;
    padding: 0 0 0 2;
}
"""
