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
    """
    await app.workers.wait_for_complete()
    previous = object()
    for _ in range(12):
        await pilot.pause()
        current = app.focused
        if current is previous:
            return
        previous = current
    raise AssertionError(
        "focus never settled, so the frame would be sampled mid-change; "
        f"last saw {app.focused!r}"
    )
