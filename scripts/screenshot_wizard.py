#!/usr/bin/env python3
"""Save an SVG screenshot of each wizard step for visual review.

Usage: python scripts/screenshot_wizard.py [outdir]

Exits non-zero if any two steps render identically. That check is not
decoration: the first version of this script drove `_goto_step(STEP_OUTPUT)`
without seeding `completed_steps`, the app refused the jump, and step 6
silently re-captured step 5 while the script still reported success. A
verification tool that returns green for something it never looked at is
worse than no tool, so identical output is now a hard failure.

Captures are taken from a settled frame, not from the first one available.
A single `pilot.pause()` is one hop short of settled once a step change moves
focus: Textual's `Footer` redraws its key bar from a `call_after_refresh`, so
the frame immediately after the change can still show the previous step's
bindings. Sampling mid-transition made steps 4 and 6 hash two different ways
across runs while the app itself was deterministic — `Screen.active_bindings`
was identical every time. `settle` waits for the export to stop changing, so
what lands on disk is what a user would actually be looking at.
"""

import asyncio
import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from morpheus.ui.app import MorpheusWizard  # noqa: E402
from morpheus.ui.state import STEP_OUTPUT, TOTAL_STEPS, Mode  # noqa: E402

# Plausible stand-in for ciphertext so the output step has something to render.
# Not a real secret; this script is run by hand and writes only to build/.
SAMPLE_OUTPUT = (
    "MORPHEUS-v1:YWVzLTI1Ni1nY206YXJnb24yaWQ6c2FsdD1RUkJ4T0hkM2JYWjZaMlZ0"
    "TkdSNU9XSnJjM1JuY0E9PTppdj1kM1oyY0dOMGRXNXpiWFJyOmN0PWJIWnhkbTVvTjNS"
    "MGEzTjZaSFp4Y0hkdmEyeDZjM1JuY0dGM2NtVjBlWFZwYjNBOVBRPT06dGFnPU9IZDJj"
    "R3AwZG5ORVoyNXpjWEIz"
)


async def settle(app, pilot, limit: int = 8) -> None:
    """Pause until two consecutive exports agree, or `limit` pauses pass.

    Deliberately compares rendered output rather than counting pauses: the
    number needed is a property of whatever Textual defers internally, and a
    magic number here would quietly stop being enough on an upgrade.
    """
    previous = None
    for _ in range(limit):
        await pilot.pause()
        current = app.export_screenshot()
        if current == previous:
            return
        previous = current
    raise SystemExit(
        f"the screen was still changing after {limit} pauses; capturing it "
        "would record whichever frame happened to win"
    )


# 110x40, not the 110x38 used before. Settings is the tallest step at 31 rows
# of content, and at 38 the viewport is 29, so every capture of step 2 silently
# cut the last two rows off and the documentation showed a truncated screen.
# 40 is the smallest height at which all six steps fit without scrolling; going
# taller only adds dead space to the sparse steps.
CAPTURE_SIZE = (110, 40)


async def capture(outdir: Path) -> list[Path]:
    outdir.mkdir(parents=True, exist_ok=True)
    app = MorpheusWizard()
    written: list[Path] = []
    async with app.run_test(size=CAPTURE_SIZE) as pilot:
        app._state.mode = Mode.ENCRYPT
        app._state.input_text = "review canary"
        app._state.password = "T3st!Passw0rd#Str0ng"
        app._state.password_confirm = "T3st!Passw0rd#Str0ng"
        # The output step is gated on the run having happened, so seed both the
        # result and the completion marker or `_goto_step` refuses the jump.
        #
        # It must go through `record_output`, not a plain assignment to
        # `.output`. Staleness is derived by comparing `output_fingerprint`
        # against the current inputs, so an assignment leaves the fingerprint
        # unset, the result reads as stale, and step 6 stays locked. This
        # script did assign directly, which was correct before staleness moved
        # from event-driven to derived, and silently stopped working after.
        app._state.record_output(SAMPLE_OUTPUT)
        app._state.completed_steps.add(STEP_OUTPUT)
        for index in range(TOTAL_STEPS):
            app._goto_step(index)
            await settle(app, pilot)
            if app._current_step != index:
                raise SystemExit(
                    f"step {index + 1} was refused: the app stayed on step "
                    f"{app._current_step + 1}. Seed more state before capturing."
                )
            name = f"step-{index + 1}.svg"
            app.save_screenshot(filename=name, path=str(outdir))
            written.append(outdir / name)
            print(f"wrote {outdir / name}")
    return written


def check_distinct(paths: list[Path]) -> int:
    """Fail if any two captures are byte-identical."""
    seen: dict[str, Path] = {}
    collisions = []
    for path in paths:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest in seen:
            collisions.append(f"{path.name} is byte-identical to {seen[digest].name}")
        else:
            seen[digest] = path
    if collisions:
        print("\nFAIL: steps did not render distinctly:", file=sys.stderr)
        for collision in collisions:
            print(f"  {collision}", file=sys.stderr)
        print(
            "\nA duplicate means a step was never captured. Check that "
            "`_goto_step` accepted the jump.",
            file=sys.stderr,
        )
        return 1
    print(f"\nok: {len(paths)} steps rendered distinctly")
    return 0


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("build/screens")
    return check_distinct(asyncio.run(capture(out)))


if __name__ == "__main__":
    raise SystemExit(main())
