"""Entropy accounting for physical dice used as key material.

Written after the 2026-07-30 COLDCARD disclosure. A firmware bug routed seed
generation through MicroPython's software PRNG instead of the device's hardware
RNG: Mk2 and Mk3 seeds landed at roughly 40 bits of effective search space
against an intended 128, and Mk4, Q and Mk5 at roughly 72. Around 594 BTC moved
in a 25-minute sweep, and the confirmed total had reached roughly 1,367 BTC by
2026-08-02.

Users who had added at least 50 private dice rolls were not considered at risk,
because the firmware hashed those rolls in alongside the device's own output.
Physical dice survived a total failure of the vendor's generator. That is the
whole argument for counting rolls properly, and it is what this module is for.

**Scope, deliberately narrow.** This module computes bits. It does not generate,
derive, store or display key material, and it produces no seed, mnemonic or
passphrase. Generating a wallet seed belongs on an air-gapped device with a
screen you trust, not in a tool that runs on a general-purpose machine beside a
browser -- solving a vendor-RNG problem by moving seed generation onto a laptop
trades a known weakness for a worse one.

**What arithmetic cannot check.** The figures here are an upper bound that holds
only if the rolls were fair, independent, ordered and private. A shaved or
weighted die yields less than `log2(sides)` per roll. Re-rolling a result you
dislike, reading a handful of dice thrown together in sorted order, or letting
anyone photograph the sequence all reduce the real figure below what this reports
-- in the sorted case, drastically. Hashing does not help: SHA-256 over 50 rolls
returns 256 bits of output carrying 129 bits of entropy.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

from .errors import ConfigurationError

# The floor a seed must clear, and the target worth aiming at. These are the
# figures the COLDCARD advisory uses, so a reader with both open sees one set of
# numbers rather than two.
FLOOR_BITS = 128
TARGET_BITS = 256


def bits_per_roll(sides: int) -> float:
    """Entropy contributed by one roll of a fair *sides*-faced die."""
    if not isinstance(sides, int) or isinstance(sides, bool):
        raise ConfigurationError(f"die faces must be a whole number, got {sides!r}")
    if sides < 2:
        # A one-faced die yields zero bits, so no number of rolls ever reaches a
        # target. Returning 0.0 would make `rolls_for_bits` divide by zero and
        # report something, which is worse than refusing outright.
        raise ConfigurationError(
            f"a die needs at least 2 faces to carry any entropy, got {sides}"
        )
    return math.log2(sides)


def bits_from_rolls(rolls: int, sides: int = 6) -> float:
    """Total entropy from *rolls* independent throws of a *sides*-faced die."""
    if not isinstance(rolls, int) or isinstance(rolls, bool):
        raise ConfigurationError(f"roll count must be a whole number, got {rolls!r}")
    if rolls < 0:
        raise ConfigurationError(f"roll count cannot be negative, got {rolls}")
    return rolls * bits_per_roll(sides)


def rolls_for_bits(target_bits: float, sides: int = 6) -> int:
    """Fewest throws of a *sides*-faced die reaching *target_bits*.

    The ceiling is taken against the measured total rather than the raw
    quotient. Dividing and rounding up is the obvious implementation and it is
    wrong at the boundary: a quotient that lands a hair above an integer through
    floating-point error asks for one roll more than the target needs. Stepping
    back while the target is still met costs one comparison and removes the
    entire class of off-by-one.
    """
    if target_bits < 0:
        raise ConfigurationError(f"target cannot be negative, got {target_bits}")
    per_roll = bits_per_roll(sides)
    if target_bits == 0:
        return 0
    n = math.ceil(target_bits / per_roll)
    while n > 0 and (n - 1) * per_roll >= target_bits:
        n -= 1
    while n * per_roll < target_bits:
        n += 1
    return n


@dataclass(frozen=True)
class DiceAssessment:
    """A verdict on a roll count, with the remedy attached.

    `shortfall_to_floor` is carried because a verdict without a remedy leaves
    the user doing the arithmetic that this module exists to do for them.
    """

    rolls: int
    sides: int
    bits_per_roll: float
    total_bits: float
    meets_floor: bool
    meets_target: bool
    rolls_for_floor: int
    rolls_for_target: int
    shortfall_to_floor: int


def assess_dice(rolls: int, sides: int = 6) -> DiceAssessment:
    """Measure *rolls* of a *sides*-faced die against the floor and the target."""
    total = bits_from_rolls(rolls, sides)
    per_roll = bits_per_roll(sides)
    need_floor = rolls_for_bits(FLOOR_BITS, sides)
    need_target = rolls_for_bits(TARGET_BITS, sides)
    return DiceAssessment(
        rolls=rolls,
        sides=sides,
        bits_per_roll=per_roll,
        total_bits=total,
        meets_floor=total >= FLOOR_BITS,
        meets_target=total >= TARGET_BITS,
        rolls_for_floor=need_floor,
        rolls_for_target=need_target,
        shortfall_to_floor=max(0, need_floor - rolls),
    )
