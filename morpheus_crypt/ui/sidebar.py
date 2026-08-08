"""Left sidebar — shows wizard steps with completion / current markers.

Keyboard-navigable: Up/Down arrows to highlight, Enter to select,
or press 1-6 to jump directly to a step.
"""

from __future__ import annotations

from textual.containers import Vertical
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import Static

from . import theme
from .state import STEP_LABELS, TOTAL_STEPS, WizardState

STEP_DESCRIPTIONS_SHORT = [
    "Encrypt or Decrypt",
    "Cipher & KDF options",
    "Text or file input",
    "Set your password",
    "Confirm & execute",
    "View result",
]

# The four step states, and the glyph that identifies each one.
#
# These carry the hierarchy. Colour reinforces them and must not be the only
# thing separating two states: the report that prompted this was a Raspberry Pi
# over SSH where the greys read as one value, and a 16-colour terminal would do
# the same. Every glyph here is distinct, so the list stays readable with colour
# stripped entirely. `tests/test_theme.py` asserts that distinctness rather than
# trusting this comment.
#
# The step number is always shown, whatever the state. Keys 1-6 jump directly to
# a step, and hiding the number on completed rows would hide that affordance in
# exactly the place someone goes looking to change an earlier answer.
CURRENT, COMPLETED, AVAILABLE, LOCKED = "current", "completed", "available", "locked"

STATE_MARKERS = {
    CURRENT: "▌",    # left half block, a solid bar down the row
    COMPLETED: "✓",  # check
    AVAILABLE: " ",
    LOCKED: "·",     # middle dot
}

# Only these two states tint their marker. Available and locked inherit the row
# colour, so the accent stays a statement about wizard state rather than
# decoration sprayed down the column.
_ACCENTED = (CURRENT, COMPLETED)


def row_text(step: int, state: str) -> str:
    """The two lines of one sidebar row: marker, number, label, then description.

    The label carries the row's own colour; the description is pinned dim. They
    are one `Static`, so CSS cannot tell them apart and only markup can. Without
    that split every row is a single flat block of grey, which is what "you
    cannot see the sections" described: nothing on the row was brighter than
    anything else, so the step names had nothing to stand out against.
    """
    marker = STATE_MARKERS[state]
    if state in _ACCENTED:
        marker = f"[{theme.ACCENT}]{marker}[/]"
    return (
        f" {marker} {step + 1} {STEP_LABELS[step]}\n"
        f"     [{theme.TEXT_3}]{STEP_DESCRIPTIONS_SHORT[step]}[/]"
    )


class SidebarItem(Static, can_focus=True):
    """Single sidebar entry — focusable, selectable with Enter."""

    class Selected(Message):
        """Fired when user presses Enter on a sidebar item."""

        def __init__(self, step: int) -> None:
            super().__init__()
            self.step = step

    def __init__(self, step: int, text: str, **kw) -> None:
        super().__init__(text, **kw)
        self._step = step

    def key_enter(self) -> None:
        self.post_message(self.Selected(self._step))


class Sidebar(Vertical):
    """Vertical list of step labels with visual state indicators."""

    current_step: reactive[int] = reactive(0)

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(id="sidebar", **kw)
        self._state = state

    def compose(self):
        for i in range(TOTAL_STEPS):
            yield SidebarItem(
                step=i,
                text=row_text(i, AVAILABLE),
                id=f"sb-{i}",
                classes="sidebar-item",
            )

    def refresh_indicators(self, current: int) -> None:
        self.current_step = current
        for i in range(TOTAL_STEPS):
            item = self.query_one(f"#sb-{i}", SidebarItem)
            item.remove_class("--current", "--completed", "--locked")

            if i == current:
                state = CURRENT
                item.add_class("--current")
            elif i in self._state.completed_steps:
                state = COMPLETED
            elif self._state.is_step_unlocked(i):
                state = AVAILABLE
            else:
                state = LOCKED

            if state is COMPLETED:
                item.add_class("--completed")
            elif state is LOCKED:
                item.add_class("--locked")

            item.update(row_text(i, state))
