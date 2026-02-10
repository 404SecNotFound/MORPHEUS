"""Left sidebar — shows wizard steps with completion / current markers."""

from __future__ import annotations

from textual.containers import Vertical
from textual.reactive import reactive
from textual.widgets import Static

from .state import STEP_LABELS, TOTAL_STEPS, WizardState


class SidebarItem(Static):
    """Single sidebar entry like '✓ Mode' or '▸ Input'."""


class Sidebar(Vertical):
    """Vertical list of step labels with visual state."""

    current_step: reactive[int] = reactive(0)

    def __init__(self, state: WizardState, **kw) -> None:
        super().__init__(id="sidebar", **kw)
        self._state = state

    def compose(self):
        for i, label in enumerate(STEP_LABELS):
            yield SidebarItem(
                f"  {i + 1} {label}",
                id=f"sb-{i}",
                classes="sidebar-item",
            )

    def refresh_indicators(self, current: int) -> None:
        self.current_step = current
        for i in range(TOTAL_STEPS):
            item = self.query_one(f"#sb-{i}", SidebarItem)
            label = STEP_LABELS[i]
            item.remove_class("--current", "--completed", "--locked")

            if i == current:
                item.update(f"  ▸ {label}")
                item.add_class("--current")
            elif i in self._state.completed_steps:
                item.update(f"  ✓ {label}")
                item.add_class("--completed")
            elif self._state.is_step_unlocked(i):
                item.update(f"  {i + 1} {label}")
            else:
                item.update(f"  {i + 1} {label}")
                item.add_class("--locked")
