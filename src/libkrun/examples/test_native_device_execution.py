"""Pure clock-correlation and KVM-TSC-DEADLINE-EARLY policy regressions.

Upstream context: https://lkml.rescloud.iu.edu/2312.2/06707.html
Revisit on kernel updates and 2026-12-01 per docs/native-execution-probe.md.
"""
from pathlib import Path
import unittest

from native_device_execution import ClockCorrelation, timer_delivery_observation


class TimerDeliveryTests(unittest.TestCase):
    def test_signed_counter_wrap_and_non_blocking_classification(self):
        cases = (
            (100, 99, -1, "known-host-limitation"),
            (100, 100, 0, "not-observed"),
            (100, 101, 1, "not-observed"),
            (1, (1 << 64) - 1, -2, "known-host-limitation"),
            ((1 << 64) - 1, 1, 2, "not-observed"),
        )
        for deadline, actual, delta, status in cases:
            with self.subTest(deadline=deadline, actual=actual):
                original = {"words": [0] * 23, "rates": [1000] * 3}
                sample = {"words": [0] * 23}
                original["words"][7] = deadline
                sample["words"][18] = actual
                record = timer_delivery_observation(
                    original, sample, "future", "child",
                    Path("source.json"), Path("child.json"), {},
                )
                self.assertEqual(record["signed_delta_ticks"], delta)
                self.assertEqual(record["status"], status)
                self.assertFalse(record["blocking"])


class ClockCorrelationTests(unittest.TestCase):
    @staticmethod
    def sample(tsc, mono_before, mono_after):
        return {"tsc_before": tsc, "mono_before": mono_before, "mono_after": mono_after}

    def test_retained_pause_pair_preserves_original_guest_conversion(self):
        # whole-machine-timer-exception-02/execution-source/guest.log, sequences 1-6.
        original = [
            self.sample(284727456, 59086353, 59652143),
            self.sample(658424808, 162891212, 162891552),
            self.sample(1020508344, 263470030, 264009770),
            self.sample(1383289020, 364242488, 364242808),
            self.sample(1744585416, 464602646, 467096267),
            self.sample(2117382264, 568157385, 568880936),
        ]
        relation = ClockCorrelation(original)
        original_record = relation.record()
        # The failed consecutive pair, sequences 238-239, crosses source resume.
        before = self.sample(90008944162, 24982491756, 24982492856)
        after = self.sample(149458011153, 41496129350, 41496129620)
        ticks = after["tsc_before"] - before["tsc_before"]
        low_ns = after["mono_before"] - before["mono_after"]
        self.assertLess(ticks * 1000000, low_ns * 3599999 - 1000000)
        high_ns = after["mono_after"] - before["mono_before"]
        # Retained original kernel clocksource mult=4660340, shift=24.
        self.assertLessEqual(low_ns * (1 << 24), ticks * 4660340)
        self.assertLessEqual(ticks * 4660340, high_ns * (1 << 24))
        relation.observe([before, after])
        record = relation.record()
        self.assertEqual(record["original_brackets"], original_record["original_brackets"])
        self.assertEqual(record["original_ticks_per_ns"], original_record["original_ticks_per_ns"])
        self.assertGreaterEqual(relation.lower, relation.original_bounds[0])
        self.assertLessEqual(relation.upper, relation.original_bounds[1])

    def test_common_intercept_rejects_jump_despite_unchanged_local_rate(self):
        relation = ClockCorrelation([self.sample(0, 0, 1), self.sample(1000, 1000, 1001)])
        with self.assertRaisesRegex(RuntimeError, "affine relation changed"):
            relation.observe([self.sample(2100, 2000, 2001), self.sample(3100, 3000, 3001)])

    def test_original_slope_rejects_later_rate_change(self):
        relation = ClockCorrelation([self.sample(0, 0, 1), self.sample(1000, 1000, 1001)])
        with self.assertRaisesRegex(RuntimeError, "affine relation changed"):
            relation.observe([self.sample(4000, 2000, 2001)])

    def test_child_observations_can_arrive_before_source_guest_time(self):
        relation = ClockCorrelation([self.sample(0, 0, 1), self.sample(1000, 1000, 1001)])
        relation.observe([self.sample(4000, 4000, 4001)])
        relation.observe([self.sample(2000, 2000, 2001), self.sample(2000, 2000, 2001)])
        self.assertEqual(relation.record()["observed_brackets"], 4)

    def test_overlapping_brackets_still_constrain_one_affine_relation(self):
        relation = ClockCorrelation([self.sample(0, 0, 10), self.sample(1000, 1000, 1010)])
        relation.observe([self.sample(1001, 1000, 1010)])
        with self.assertRaisesRegex(RuntimeError, "affine relation changed"):
            relation.observe([self.sample(3000, 1000, 1010)])

    def test_missing_separation_and_backwards_brackets_fail_closed(self):
        for samples in ([], [self.sample(1, 1, 2)],
                        [self.sample(1, 1, 4), self.sample(2, 2, 5)],
                        [self.sample(1, 4, 3)],
                        [self.sample(100, 100, 101), self.sample(200, 50, 51)]):
            with self.subTest(samples=samples):
                with self.assertRaises(RuntimeError):
                    ClockCorrelation(samples)


if __name__ == "__main__":
    unittest.main()
