"""Tests for physical-dice entropy accounting.

The numbers here are pinned against Coinkite's 2026-07-30 advisory, because that
is the document a user will have open beside this tool. Where our arithmetic and
their prose disagree, the test records the disagreement rather than rounding it
away -- see `test_ninety_nine_rolls_falls_just_short_of_256_bits`.
"""

import contextlib
import io
import math
import re

import pytest

from morpheus_crypt.cli import run_cli
from morpheus_crypt.core.entropy import (
    FLOOR_BITS,
    TARGET_BITS,
    assess_dice,
    bits_from_rolls,
    bits_per_roll,
    rolls_for_bits,
)
from morpheus_crypt.core.errors import ConfigurationError


class TestBitsPerRoll:
    def test_a_fair_d6_carries_log2_six_bits(self):
        assert bits_per_roll(6) == pytest.approx(2.584962500721156)

    def test_a_coin_carries_exactly_one_bit(self):
        assert bits_per_roll(2) == 1.0

    def test_a_power_of_two_die_is_exact(self):
        """No floating-point drift where the answer is representable."""
        assert bits_per_roll(4) == 2.0
        assert bits_per_roll(8) == 3.0

    @pytest.mark.parametrize("sides", [1, 0, -6])
    def test_a_die_with_fewer_than_two_faces_is_refused(self, sides):
        """A one-faced die yields zero bits, so no number of rolls ever suffices.

        Returning 0.0 would let `rolls_for_bits` divide by zero and report an
        answer, which is worse than refusing.
        """
        with pytest.raises(ConfigurationError):
            bits_per_roll(sides)


class TestBitsFromRolls:
    def test_no_rolls_is_no_entropy(self):
        assert bits_from_rolls(0, 6) == 0.0

    def test_fifty_d6_rolls_clears_the_128_bit_floor(self):
        """Coinkite's stated threshold: 50 to 98 rolls give at least 128 bits."""
        assert bits_from_rolls(50, 6) == pytest.approx(129.248, abs=0.001)
        assert bits_from_rolls(50, 6) >= FLOOR_BITS

    def test_forty_nine_d6_rolls_does_not(self):
        """The boundary is real: one roll short is short."""
        assert bits_from_rolls(49, 6) < FLOOR_BITS

    def test_ninety_nine_rolls_falls_just_short_of_256_bits(self):
        """Coinkite says 99 rolls give "approximately 256 bits". It is 255.9.

        Pinned deliberately. The gap is 0.09 bits and of no practical
        consequence, but this tool reports measured figures, and a reader
        comparing our output against the advisory should find the difference
        explained rather than quietly rounded into agreement.
        """
        bits = bits_from_rolls(99, 6)
        assert bits == pytest.approx(255.911, abs=0.001)
        assert bits < TARGET_BITS
        assert TARGET_BITS - bits < 0.1

    def test_one_hundred_rolls_clears_it(self):
        assert bits_from_rolls(100, 6) >= TARGET_BITS

    def test_rolls_accumulate_linearly(self):
        assert bits_from_rolls(20, 6) == pytest.approx(2 * bits_from_rolls(10, 6))

    @pytest.mark.parametrize("rolls", [-1, -50])
    def test_a_negative_roll_count_is_refused(self, rolls):
        with pytest.raises(ConfigurationError):
            bits_from_rolls(rolls, 6)


class TestRollsForBits:
    def test_fifty_d6_rolls_are_needed_for_128_bits(self):
        """Matches the advisory's 50-roll threshold exactly."""
        assert rolls_for_bits(128, 6) == 50

    def test_one_hundred_d6_rolls_are_needed_for_256_bits(self):
        """Not 99. See test_ninety_nine_rolls_falls_just_short_of_256_bits."""
        assert rolls_for_bits(256, 6) == 100

    def test_coin_flips_map_one_to_one(self):
        assert rolls_for_bits(128, 2) == 128
        assert rolls_for_bits(256, 2) == 256

    def test_zero_bits_needs_no_rolls(self):
        assert rolls_for_bits(0, 6) == 0

    def test_a_negative_target_is_refused(self):
        with pytest.raises(ConfigurationError):
            rolls_for_bits(-1, 6)

    @pytest.mark.parametrize(
        "sides,target",
        [(s, t) for s in (2, 3, 4, 6, 8, 10, 12, 16, 20, 100)
         for t in (1, 8, 64, 127, 128, 129, 255, 256, 512)],
    )
    def test_the_answer_always_actually_reaches_the_target(self, sides, target):
        """The round trip that matters, over every die and target we support.

        `ceil` on a floating-point quotient is where an off-by-one hides: a
        quotient of 49.999999999 rounds to 50 correctly, but one of 50.000000001
        rounds to 51 and silently asks for a roll nobody needs. Asserting both
        directions pins it: the answer suffices, and one fewer does not.
        """
        n = rolls_for_bits(target, sides)
        assert bits_from_rolls(n, sides) >= target
        if n > 0:
            assert bits_from_rolls(n - 1, sides) < target

    @pytest.mark.parametrize("sides", [2, 3, 5, 6, 7, 10, 12, 20])
    @pytest.mark.parametrize("n", [1, 11, 15, 22, 30, 50, 99, 100, 128])
    def test_a_target_taken_from_a_roll_count_returns_that_roll_count(self, sides, n):
        """The round trip a user actually performs, and where naive ceil breaks.

        Ask for exactly the bits that *n* rolls produce and the answer must be
        *n*, not n+1. `math.ceil(target / per_roll)` fails this: the product and
        the quotient do not round-trip in binary floating point, so the quotient
        lands a hair above *n* and rounds up. Measured over d2 to d64 for the
        first 400 roll counts, plain ceil gets 1205 of them wrong -- every one
        of them demanding a roll the user does not need. d3 at 11 rolls is the
        smallest case.

        Not a cosmetic defect. This tool exists to tell someone when they may
        stop rolling, and dice sessions are long and tedious enough that a
        spurious extra roll is exactly the instruction a person ignores.
        """
        target = bits_from_rolls(n, sides)
        assert rolls_for_bits(target, sides) == n


class TestAssessDice:
    def test_below_the_floor_is_not_blessed(self):
        a = assess_dice(20, 6)
        assert a.meets_floor is False
        assert a.meets_target is False

    def test_fifty_rolls_meets_the_floor_but_not_the_target(self):
        a = assess_dice(50, 6)
        assert a.meets_floor is True
        assert a.meets_target is False

    def test_one_hundred_rolls_meets_both(self):
        a = assess_dice(100, 6)
        assert a.meets_floor is True
        assert a.meets_target is True

    def test_it_reports_what_is_still_needed(self):
        """A verdict without a remedy makes the user do the arithmetic."""
        a = assess_dice(20, 6)
        assert a.rolls_for_floor == 50
        assert a.rolls_for_target == 100
        assert a.shortfall_to_floor == 30

    def test_nothing_is_owed_once_the_floor_is_met(self):
        assert assess_dice(50, 6).shortfall_to_floor == 0
        assert assess_dice(200, 6).shortfall_to_floor == 0

    def test_the_assessment_carries_the_die_it_was_made_for(self):
        """Bits alone are ambiguous; 128 bits from d2 is 128 rolls, not 50."""
        a = assess_dice(128, 2)
        assert a.sides == 2
        assert a.rolls == 128
        assert a.meets_floor is True

    def test_a_five_digit_number_is_nowhere_near_the_floor(self):
        """The question that prompted this module, answered in its own terms.

        Five decimal digits is 100,000 possibilities. Expressed as d10 rolls
        that is five rolls, and the assessment must refuse it rather than
        describe it as merely weak.

        For scale: the COLDCARD Mk3 bug left about 40 bits and cost 594 BTC.
        This is 16.6.
        """
        a = assess_dice(5, 10)
        assert a.total_bits == pytest.approx(math.log2(100_000), abs=1e-9)
        assert a.total_bits < 17
        assert a.meets_floor is False
        assert a.rolls_for_floor == 39


class TestDiceEntropyCLI:
    """The command surface: exit codes, and that it emits no key material."""

    @staticmethod
    def _run(argv):
        out, err = io.StringIO(), io.StringIO()
        code = 0
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                run_cli(argv)
            except SystemExit as exc:
                code = exc.code or 0
        return code, out.getvalue(), err.getvalue()

    def test_enough_rolls_exits_zero(self):
        code, out, _ = self._run(["--dice-entropy", "50"])
        assert code == 0
        assert "129.2 bits" in out

    def test_too_few_rolls_exits_nonzero(self):
        """A shortfall has to be actionable from a script, not just readable."""
        code, out, _ = self._run(["--dice-entropy", "20"])
        assert code == 1
        assert "NOT ENOUGH" in out
        assert "Roll 30 more" in out

    def test_the_boundary_is_the_advisory_boundary(self):
        assert self._run(["--dice-entropy", "49"])[0] == 1
        assert self._run(["--dice-entropy", "50"])[0] == 0

    def test_it_reports_the_gap_the_advisory_rounds_away(self):
        """99 rolls is 255.9 bits, not 256. The output must say so."""
        code, out, _ = self._run(["--dice-entropy", "99"])
        assert code == 0
        assert "255.9 bits" in out
        assert "0.1 bits short of 256" in out

    def test_a_bad_die_is_refused_cleanly(self):
        """Regression: this raised NameError through the catch-all handler.

        `_run_dice_entropy` caught `MorpheusError`, which cli.py does not
        import, so a one-faced die produced "unexpected failure: NameError"
        and told the user to file a bug about their own typo.
        """
        code, _, err = self._run(["--dice-entropy", "10", "--dice-sides", "1"])
        assert code == 1
        assert "at least 2 faces" in err
        assert "NameError" not in err
        assert "This is a bug" not in err

    def test_a_negative_count_is_refused_cleanly(self):
        code, _, err = self._run(["--dice-entropy", "-5"])
        assert code == 1
        assert "cannot be negative" in err
        assert "NameError" not in err

    def test_coin_flips_are_supported(self):
        code, out, _ = self._run(["--dice-entropy", "128", "--dice-sides", "2"])
        assert code == 0
        assert "128 x d2" in out
        assert "1.000 bits" in out

    def test_it_never_asks_for_or_emits_roll_values(self):
        """The command takes a count. It must not look like it wants a sequence.

        A tool that accepted the rolls themselves would be asking the user to
        type key material into a networked computer, which is the exact thing
        the dice procedure exists to avoid.
        """
        code, out, _ = self._run(["--dice-entropy", "100"])
        assert code == 0
        # No seed, mnemonic, hex blob or base64 payload anywhere in the output.
        assert not re.search(r"\b[0-9a-f]{32,}\b", out)
        assert not re.search(r"\b[A-Za-z0-9+/]{40,}={0,2}\b", out)
        for word in ("seed", "mnemonic", "passphrase", "private key"):
            assert word not in out.lower(), f"output mentions {word!r}"

    def test_the_caveats_travel_with_the_number(self):
        """The figure is an upper bound; shipping it bare would overstate it."""
        _, out, _ = self._run(["--dice-entropy", "100"])
        for caveat in ("weighted", "re-rolling", "sorted order", "Hashing"):
            assert caveat in out


class TestTheVerdictExplainsItselfInPlainLanguage:
    """The verdict has to mean something to a reader who does not know bits.

    Everything else in this output is arithmetic aimed at someone who already
    accepts that entropy is the thing to worry about. That reader is not the
    one at risk. The person who needs this most rolls a die twenty times,
    reads "51.7 bits", has no idea whether that is good, and stops.

    So each verdict carries one line saying what it means in ordinary words,
    and the strong verdict additionally says when to stop. A count that has
    already cleared 256 bits cannot be improved by rolling further: a 24-word
    seed holds 256 bits and the rest is discarded by the format. Someone
    diligent enough to roll 300 times was previously told "Strong" and left to
    assume the extra 200 rolls bought them something.
    """

    _run = staticmethod(TestDiceEntropyCLI._run)

    def test_strong_says_what_strong_means(self):
        code, out, _ = self._run(["--dice-entropy", "100"])
        assert code == 0
        assert "Nobody can guess this" in out

    def test_overshooting_names_the_rolls_that_did_nothing(self):
        """300 rolls is 775 bits into a container that holds 256."""
        code, out, _ = self._run(["--dice-entropy", "300"])
        assert code == 0
        assert "100 rolls was enough" in out
        assert "other 200 added nothing" in out

    def test_hitting_the_target_exactly_is_not_called_wasteful(self):
        """The boundary: 100 rolls is the answer, not an overshoot."""
        _, out, _ = self._run(["--dice-entropy", "100"])
        assert "added nothing" not in out

    def test_the_waste_notice_counts_in_rolls_of_the_die_actually_used(self):
        """A coin needs 256 flips, so 300 wastes 44, not 200."""
        _, out, _ = self._run(["--dice-entropy", "300", "--dice-sides", "2"])
        assert "256 rolls was enough" in out
        assert "other 44 added nothing" in out

    def test_clearing_only_the_floor_says_it_is_usable_but_not_full(self):
        code, out, _ = self._run(["--dice-entropy", "50"])
        assert code == 0
        assert "Safe to use" in out

    def test_falling_short_says_what_that_costs(self):
        code, out, _ = self._run(["--dice-entropy", "20"])
        assert code == 1
        assert "Keep rolling" in out

    def test_the_plain_line_never_replaces_the_number(self):
        """Plain language is added alongside the arithmetic, not instead of it.

        Someone who does read bits must lose nothing, or this trade has made
        the tool worse for the audience it already served.
        """
        _, out, _ = self._run(["--dice-entropy", "300"])
        assert "775.5 bits" in out
        assert "2.585 bits" in out
        assert "300 x d6" in out
