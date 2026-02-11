"""Dashboard CSS for MORPHEUS — Sampler-inspired dark terminal dashboard.

Design principles (from Sampler):
  - Every panel gets a heavy border with a title in the frame
  - Dark background (#0A0A0A) with bright green (#00FF41) accents
  - Dense layout — everything visible on one screen
  - No wasted space, no scrolling, no hidden panels
"""

from __future__ import annotations

DASHBOARD_CSS = """

/* ══════════════════════════════════════════════════════════════════
   SCREEN
   ══════════════════════════════════════════════════════════════════ */

Screen {
    background: #0A0A0A;
    layout: vertical;
}

/* ══════════════════════════════════════════════════════════════════
   HEADER BAR
   ══════════════════════════════════════════════════════════════════ */

#header-bar {
    dock: top;
    height: 3;
    background: #0F0F0F;
    padding: 1 2;
    border-bottom: heavy #0D3B0D;
}

#header-title {
    width: 1fr;
    color: #00FF41;
    text-style: bold;
}

#header-subtitle {
    width: auto;
    color: #007018;
    text-style: italic;
}

/* ══════════════════════════════════════════════════════════════════
   DASHBOARD GRID
   ══════════════════════════════════════════════════════════════════ */

#dashboard {
    height: 1fr;
    padding: 0 1;
}

#top-row {
    height: auto;
    max-height: 14;
    min-height: 10;
}

#mid-row {
    height: 1fr;
    min-height: 12;
}

/* ══════════════════════════════════════════════════════════════════
   PANEL BASE — every panel gets this
   ══════════════════════════════════════════════════════════════════ */

.panel {
    border: heavy #0D3B0D;
    border-title-color: #00FF41;
    border-title-style: bold;
    border-subtitle-color: #007018;
    border-subtitle-style: italic;
    background: #0D0D0D;
    padding: 0 1;
    margin: 0 0;
    overflow-y: auto;
}

.panel:focus-within {
    border: heavy #00AA28;
}

/* ══════════════════════════════════════════════════════════════════
   MODE PANEL (top-left, narrow)
   ══════════════════════════════════════════════════════════════════ */

#mode-panel {
    width: 24;
    min-width: 20;
}

.panel-hint {
    color: #007018;
    height: 1;
    margin: 0 0 1 0;
}

#mode-radio {
    background: transparent;
    border: none;
    height: auto;
    padding: 0;
}

#mode-radio RadioButton {
    background: transparent;
    color: #00DD36;
    height: auto;
    margin: 0;
    padding: 0;
}

#mode-radio RadioButton:focus {
    color: #00FF41;
    text-style: bold;
}

/* ══════════════════════════════════════════════════════════════════
   SETTINGS PANEL (top-center, flexible)
   ══════════════════════════════════════════════════════════════════ */

#settings-panel {
    width: 1fr;
}

.setting-row {
    height: 3;
    layout: horizontal;
    align: left middle;
}

.setting-label {
    width: 8;
    color: #00AA28;
    padding: 0 1 0 0;
}

.opts-row {
    height: auto;
    layout: horizontal;
    margin: 1 0 0 0;
}

.opts-row Checkbox {
    margin: 0 2 0 0;
    background: transparent;
    color: #00DD36;
    padding: 0;
}

#settings-panel Select {
    width: 1fr;
    max-width: 28;
}

/* ══════════════════════════════════════════════════════════════════
   STATUS PANEL (top-right, narrow)
   ══════════════════════════════════════════════════════════════════ */

#status-panel {
    width: 26;
    min-width: 22;
}

#status-panel Static {
    height: 1;
    color: #00DD36;
}

.status-divider {
    color: #0D3B0D;
    height: 1;
    margin: 1 0;
}

#btn-run {
    width: 100%;
    min-width: 16;
    margin: 0;
    background: #00FF41;
    color: #0A0A0A;
    text-style: bold;
    border: tall #00CC33;
}

#btn-run:hover {
    background: #33FF66;
}

#btn-run:disabled {
    background: #111111;
    color: #333333;
    border: tall #1A1A1A;
}

/* ══════════════════════════════════════════════════════════════════
   INPUT PANEL (mid-left, wider)
   ══════════════════════════════════════════════════════════════════ */

#input-panel {
    width: 2fr;
}

#input-header {
    height: auto;
    margin: 0 0 1 0;
}

#input-tabs {
    height: auto;
    background: transparent;
    border: none;
    width: auto;
    padding: 0;
}

#input-tabs RadioButton {
    background: transparent;
    color: #00DD36;
    height: auto;
    padding: 0;
}

#input-tabs RadioButton:focus {
    color: #00FF41;
}

#input-stats {
    height: 1;
    width: auto;
    color: #007018;
    text-align: right;
    padding: 0 0 0 2;
    dock: right;
}

#input-editor {
    height: 1fr;
    min-height: 4;
    background: #111111;
    color: #00FF41;
    border: tall #0D3B0D;
}

#input-editor:focus {
    border: tall #00AA28;
}

#file-row {
    height: 3;
    layout: horizontal;
    align: left middle;
}

#file-path-input {
    width: 1fr;
}

/* ══════════════════════════════════════════════════════════════════
   PASSWORD PANEL (mid-right, narrower)
   ══════════════════════════════════════════════════════════════════ */

#password-panel {
    width: 1fr;
}

.pwd-row {
    height: 3;
    layout: horizontal;
    align: left middle;
}

.pwd-label {
    width: 5;
    color: #00AA28;
    padding: 0 1 0 0;
}

.pwd-field {
    width: 1fr;
}

.pwd-btn {
    min-width: 8;
    margin: 0 0 0 1;
}

#match-indicator {
    width: auto;
    min-width: 12;
    padding: 0 0 0 1;
}

#show-pwd-check {
    margin: 0 0 1 0;
    background: transparent;
    color: #00DD36;
}

#strength-bar {
    height: 1;
}

#pwd-feedback {
    height: auto;
    color: #007018;
}

/* ══════════════════════════════════════════════════════════════════
   OUTPUT PANEL (bottom, full width)
   ══════════════════════════════════════════════════════════════════ */

#output-panel {
    height: auto;
    max-height: 14;
    min-height: 8;
}

#output-area {
    height: 1fr;
    min-height: 3;
    background: #111111;
    color: #00FF41;
    border: tall #0D3B0D;
}

#output-area:focus {
    border: tall #00AA28;
}

#output-actions {
    height: 3;
    layout: horizontal;
    align: left middle;
    margin: 1 0 0 0;
}

#output-actions Button {
    margin: 0 1 0 0;
    min-width: 10;
}

#btn-copy {
    background: #00FF41;
    color: #0A0A0A;
    text-style: bold;
    border: tall #00CC33;
}

#btn-copy:hover {
    background: #33FF66;
}

#btn-save {
    background: #111111;
    color: #00AA28;
    border: tall #0D3B0D;
}

#btn-save:hover {
    background: #0D3B0D;
    color: #00FF41;
}

#btn-clear {
    background: #111111;
    color: #FF3333;
    border: tall #0D3B0D;
}

#btn-clear:hover {
    background: #2A0A0A;
    color: #FF5555;
}

#btn-stop-timer {
    background: #111111;
    color: #FFD700;
    border: tall #0D3B0D;
}

#btn-stop-timer:hover {
    background: #1A1A0A;
    color: #FFE44D;
}

#countdown-label {
    width: auto;
    padding: 0 0 0 2;
}

/* ══════════════════════════════════════════════════════════════════
   SHARED WIDGET STYLES
   ══════════════════════════════════════════════════════════════════ */

Input {
    background: #111111;
    border: tall #0D3B0D;
    color: #00FF41;
}

Input:focus {
    border: tall #00AA28;
}

TextArea {
    background: #111111;
    color: #00FF41;
}

Select {
    background: #111111;
    border: tall #0D3B0D;
    color: #00FF41;
}

Select:focus {
    border: tall #00AA28;
}

SelectOverlay {
    background: #111111;
    color: #00FF41;
    border: heavy #0D3B0D;
}

SelectCurrent {
    color: #00FF41;
}

Checkbox {
    background: transparent;
    color: #00DD36;
}

Checkbox:focus {
    color: #00FF41;
}

RadioButton {
    background: transparent;
    color: #00DD36;
}

RadioButton:focus {
    color: #00FF41;
}

RadioSet {
    background: transparent;
    border: none;
}

Button {
    background: #111111;
    color: #00DD36;
    border: tall #0D3B0D;
}

Button:hover {
    background: #0D3B0D;
    color: #00FF41;
}

Button:focus {
    border: tall #00AA28;
}

Footer {
    background: #0F0F0F;
    color: #00AA28;
}
"""
