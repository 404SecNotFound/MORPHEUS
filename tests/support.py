"""Shared helpers for the tests that drive the real Textual app."""

from __future__ import annotations


async def settle(app, pilot) -> None:
    """Wait until the step panel is mounted and focus has landed on it.

    A single `pause()` samples the frame part-way through a step change. The
    panel is mounted by an exclusive worker and the keyboard is handed to it by
    a `call_after_refresh` that the worker schedules once mounting is done, so
    one pause catches the step's first control focused only if it happens to
    win the turn.

    Two symptoms came out of that. The rendered palette guards failed about one
    run in five, because a focused `Input` paints a selection band and so the
    palette differed between runs. `TestStepContentTakesFocus` then failed
    every time under `--cov`, whose slower turns meant focus had reliably *not*
    landed yet, which is the more honest version of the same bug.

    Settling on "focus stopped changing" rather than a fixed number of pauses
    is deliberate. A fixed count is a magic number that silently stops being
    enough the next time a step gains a widget or the run gets slower, and the
    symptom is exactly the two failures above. If focus never settles this
    raises rather than letting the caller assert against a half-painted frame.

    Stability alone was not enough, though. "Focus stopped changing" is also
    true while focus is *still on the sidebar* and the `call_after_refresh`
    handoff has not been scheduled yet — a transient stable state, not the end
    state. On the Windows CI runner that window is wide enough to hit, and
    `TestStepContentTakesFocus` failed there intermittently while passing
    everywhere else. So the wait is for the actual postcondition every caller
    depends on: focus has left the sidebar *and* then stopped moving.

    The sidebar is the right thing to test against rather than the step panel,
    because Review composes only Static text and hands the keyboard to its
    Execute button in the nav bar, which is outside the panel.
    """
    await app.workers.wait_for_complete()
    sidebar = app.query_one("#sidebar")
    previous = object()
    for _ in range(40):
        await pilot.pause()
        current = app.focused
        landed = current is not None and sidebar not in current.ancestors
        if landed and current is previous:
            return
        previous = current
    raise AssertionError(
        "focus never landed off the sidebar and settled, so the frame would be "
        f"sampled mid-change; last saw {app.focused!r}"
    )
