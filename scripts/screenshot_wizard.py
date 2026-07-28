#!/usr/bin/env python3
"""Save an SVG screenshot of each wizard step for visual review.

Usage: python scripts/screenshot_wizard.py [outdir]
"""

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from morpheus.ui.app import MorpheusWizard  # noqa: E402
from morpheus.ui.state import Mode  # noqa: E402


async def main(outdir: Path) -> None:
    outdir.mkdir(parents=True, exist_ok=True)
    app = MorpheusWizard()
    async with app.run_test(size=(110, 38)) as pilot:
        app._state.mode = Mode.ENCRYPT
        app._state.input_text = "review canary"
        app._state.password = "T3st!Passw0rd#Str0ng"
        app._state.password_confirm = "T3st!Passw0rd#Str0ng"
        for index in range(6):
            app._goto_step(index)
            await pilot.pause()
            name = f"step-{index + 1}.svg"
            app.save_screenshot(filename=name, path=str(outdir))
            print(f"wrote {outdir / name}")


if __name__ == "__main__":
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("build/screens")
    asyncio.run(main(out))
