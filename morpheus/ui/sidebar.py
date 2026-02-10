"""Left sidebar — shows wizard steps with completion / current markers.

Keyboard-navigable: Up/Down arrows to highlight, Enter to select,
or press 1-6 to jump directly to a step.
"""

from __future__ import annotations

from textual.containers import Vertical
from textual.message import Message
from textual.reactive import reactive
from textual.widgets import Static

from .state import STEP_LABELS, TOTAL_STEPS, WizardState


STEP_DESCRIPTIONS_SHORT = [
    "Encrypt or Decrypt",
    "Cipher & KDF options",
    "Text or file input",
    "Set your password",
    "Confirm & execute",
    "View result",
]


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
        for i, label in enumerate(STEP_LABELS):
            desc = STEP_DESCRIPTIONS_SHORT[i]
            yield SidebarItem(
                step=i,
                text=f"  [{i + 1}] {label}\n      {desc}",
                id=f"sb-{i}",
                classes="sidebar-item",
            )

    def refresh_indicators(self, current: int) -> None:
        self.current_step = current
        for i in range(TOTAL_STEPS):
            item = self.query_one(f"#sb-{i}", SidebarItem)
            label = STEP_LABELS[i]
            desc = STEP_DESCRIPTIONS_SHORT[i]
            item.remove_class("--current", "--completed", "--locked")

            if i == current:
                item.update(f"  [>] {label}\n      {desc}")
                item.add_class("--current")
            elif i in self._state.completed_steps:
                item.update(f"  [+] {label}\n      {desc}")
                item.add_class("--completed")
            elif self._state.is_step_unlocked(i):
                item.update(f"  [{i + 1}] {label}\n      {desc}")
            else:
                item.update(f"  [ ] {label}\n      {desc}")
                item.add_class("--locked")
