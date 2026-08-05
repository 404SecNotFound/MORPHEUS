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
    sidebar = app.query_one("#sidebar")
    await _await_focus(
        app, pilot,
        lambda w: w is not None and sidebar not in w.ancestors,
        "landed off the sidebar and settled",
    )


async def settle_on_sidebar(app, pilot) -> None:
    """The mirror of `settle`, for the paths that deliberately focus the sidebar.

    Escape is meant to hand the keyboard *back* to the sidebar, so those tests
    want the opposite postcondition. Using `settle` there would raise, and
    using a bare `pause()` reintroduces exactly the race `settle` exists to
    remove — just in the other direction.
    """
    sidebar = app.query_one("#sidebar")
    await _await_focus(
        app, pilot,
        lambda w: w is not None and sidebar in w.ancestors,
        "landed on the sidebar and settled",
    )


async def settle_on(app, pilot, widget_id: str) -> None:
    """Wait for one named widget to hold focus.

    Needed where focus moves *within* one region, such as Tab stepping along
    the sidebar. Both `settle` and `settle_on_sidebar` are already satisfied
    before such a move starts, so they can return on the pre-move widget; only
    naming the target is precise enough.
    """
    await _await_focus(
        app, pilot,
        lambda w: w is not None and w.id == widget_id,
        f"landed on #{widget_id} and settled",
    )


async def settle_until(pilot, predicate, description: str, limit: int = 40) -> None:
    """Pump frames until `predicate()` holds, for postconditions that are not focus.

    `settle` and its siblings all wait on where the keyboard is. A click needs
    something different: the postcondition is the widget's *own state*, and that
    lands a frame or more after the click is posted, because the click becomes a
    message, the widget toggles when it processes it, and the change is only
    visible afterwards.

    `pilot.click(...)` followed by a single `pause()` samples exactly one frame
    and therefore passes only when the toggle happens to win that turn. It did
    on Linux and macOS every time, and failed on the Windows runner as
    "#pad-check did not toggle when clicked" with `assert False != False`, which
    reads like a broken checkbox rather than a test sampling too early.

    This is the same fix as `settle`, one layer along: wait for the thing the
    caller is about to assert on, not for a fixed number of frames. A count is a
    magic number that stops being enough as soon as a step gains a widget or the
    runner gets slower, which is precisely how this surfaced.
    """
    for _ in range(limit):
        await pilot.pause()
        if predicate():
            return
    raise AssertionError(
        f"{description} never became true within {limit} frames, so the frame "
        f"would be sampled before the change landed"
    )


async def _await_focus(app, pilot, predicate, description: str) -> None:
    """Pump frames until `predicate(app.focused)` holds on two consecutive ones.

    Both halves matter. The predicate alone can be satisfied mid-flight while
    focus is still moving; stability alone is satisfied by any transient
    resting place, which is the bug described above.
    """
    await app.workers.wait_for_complete()
    previous = object()
    for _ in range(40):
        await pilot.pause()
        current = app.focused
        if predicate(current) and current is previous:
            return
        previous = current
    raise AssertionError(
        f"focus never {description}, so the frame would be sampled mid-change; "
        f"last saw {app.focused!r}"
    )
