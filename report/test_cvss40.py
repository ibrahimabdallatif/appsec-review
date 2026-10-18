"""Unit tests for cvss40.py. Run: python -I test_cvss40.py"""
import io
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.dont_write_bytecode = True  # keep the skill folder free of __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cvss40  # noqa: E402

BASE = "AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


def metrics(**changes):
    parsed = cvss40.parse_vector(BASE)
    parsed.update(changes)
    return parsed


class ParseVectorTest(unittest.TestCase):
    def test_with_and_without_prefix(self):
        self.assertEqual(cvss40.parse_vector(BASE), cvss40.parse_vector("CVSS:4.0/" + BASE))

    def test_adds_unscored_defaults(self):
        parsed = cvss40.parse_vector(BASE)
        self.assertEqual((parsed["E"], parsed["CR"], parsed["IR"], parsed["AR"]), ("A", "H", "H", "H"))

    def test_missing_metric(self):
        with self.assertRaisesRegex(ValueError, "missing metrics: SA"):
            cvss40.parse_vector(BASE.replace("/SA:N", ""))

    def test_extra_metric(self):
        with self.assertRaisesRegex(ValueError, "remove: E"):
            cvss40.parse_vector(BASE + "/E:P")

    def test_v31_scope_rejected(self):
        with self.assertRaisesRegex(ValueError, "remove: S"):
            cvss40.parse_vector(BASE + "/S:C")

    def test_invalid_value(self):
        with self.assertRaisesRegex(ValueError, "invalid values: UI:R"):
            cvss40.parse_vector(BASE.replace("UI:N", "UI:R"))

    def test_subsequent_safety_not_a_base_value(self):
        with self.assertRaisesRegex(ValueError, "SI:S"):
            cvss40.parse_vector(BASE.replace("SI:N", "SI:S"))


class NormalizeTest(unittest.TestCase):
    def test_orders_and_prefixes(self):
        shuffled = "SA:N/SI:N/SC:N/VA:H/VI:H/VC:H/UI:N/PR:N/AT:N/AC:L/AV:N"
        self.assertEqual(cvss40.normalize(shuffled), "CVSS:4.0/" + BASE)


class EqTest(unittest.TestCase):
    def test_eq1(self):
        self.assertEqual(cvss40.eq1(metrics()), 0)
        self.assertEqual(cvss40.eq1(metrics(PR="L")), 1)
        self.assertEqual(cvss40.eq1(metrics(AV="P")), 2)
        self.assertEqual(cvss40.eq1(metrics(AV="L", PR="L", UI="P")), 2)

    def test_eq2(self):
        self.assertEqual(cvss40.eq2(metrics()), 0)
        self.assertEqual(cvss40.eq2(metrics(AT="P")), 1)
        self.assertEqual(cvss40.eq2(metrics(AC="H")), 1)

    def test_eq3(self):
        self.assertEqual(cvss40.eq3(metrics()), 0)
        self.assertEqual(cvss40.eq3(metrics(VC="L", VI="N")), 1)
        self.assertEqual(cvss40.eq3(metrics(VC="L", VI="L", VA="L")), 2)

    def test_eq4(self):
        self.assertEqual(cvss40.eq4(metrics(SI="S")), 0)
        self.assertEqual(cvss40.eq4(metrics(SC="H")), 1)
        self.assertEqual(cvss40.eq4(metrics(SC="L")), 2)

    def test_eq5(self):
        self.assertEqual([cvss40.eq5(metrics(E=e)) for e in "APU"], [0, 1, 2])

    def test_eq6(self):
        self.assertEqual(cvss40.eq6(metrics()), 0)
        self.assertEqual(cvss40.eq6(metrics(VC="L", VI="L", VA="L")), 1)
        self.assertEqual(cvss40.eq6(metrics(CR="M", IR="M", AR="M")), 1)

    def test_macro_vector(self):
        self.assertEqual(cvss40.macro_vector(metrics()), (0, 0, 0, 2, 0, 0))


class LowerScoresTest(unittest.TestCase):
    def test_lookup_shifted(self):
        self.assertEqual(cvss40.lookup_shifted((0, 0, 0, 0, 0, 0)), 10)
        self.assertEqual(cvss40.lookup_shifted((0, 0, 0, 0, 0, 0), 5), 9.9)
        self.assertIsNone(cvss40.lookup_shifted((2, 0, 0, 0, 0, 0), 0))

    def test_eq3eq6_from_00_takes_higher(self):
        self.assertEqual(cvss40.eq3eq6_lower_score((0, 0, 0, 0, 0, 0)), 9.9)

    def test_eq3eq6_paths(self):
        self.assertEqual(cvss40.eq3eq6_lower_score((0, 0, 1, 0, 0, 0)), cvss40.LOOKUP["001001"])
        self.assertEqual(cvss40.eq3eq6_lower_score((0, 0, 0, 0, 0, 1)), cvss40.LOOKUP["001001"])
        self.assertEqual(cvss40.eq3eq6_lower_score((0, 0, 1, 0, 0, 1)), cvss40.LOOKUP["002001"])
        self.assertIsNone(cvss40.eq3eq6_lower_score((0, 0, 2, 0, 0, 1)))

    def test_lower_scores(self):
        self.assertEqual(cvss40.lower_scores((0, 0, 0, 2, 0, 0)),
                         [cvss40.LOOKUP["100200"], cvss40.LOOKUP["010200"], cvss40.LOOKUP["000201"], None,
                          cvss40.LOOKUP["000210"]])


class DistanceTest(unittest.TestCase):
    def test_max_vectors_combine_parts(self):
        combos = cvss40.max_vectors((1, 1, 0, 2, 0, 0))
        self.assertEqual(len(combos), 6)
        self.assertEqual(combos[0]["AV"], "A")
        self.assertEqual(combos[0]["SC"], "L")

    def test_distances_from(self):
        distances = cvss40.distances_from(metrics(PR="L"), metrics())
        self.assertAlmostEqual(distances["PR"], 0.1)
        self.assertEqual(distances["AV"], 0)

    def test_severity_distances_skips_exceeded_max(self):
        distances = cvss40.severity_distances(metrics(PR="L"), (1, 0, 0, 2, 0, 0))
        self.assertTrue(all(value >= 0 for value in distances.values()))
        self.assertEqual(distances["PR"], 0)

    def test_eq_distances(self):
        distances = dict.fromkeys(cvss40.LEVELS, 0.1)
        self.assertEqual([round(d, 1) for d in cvss40.eq_distances(distances)], [0.3, 0.2, 0.6, 0.3, 0])

    def test_max_depths(self):
        depths = cvss40.max_depths((0, 1, 1, 2, 0, 1))
        self.assertEqual([round(d, 1) for d in depths[:4]], [0.1, 0.2, 0.8, 0.4])
        self.assertIsNone(depths[4])


class MeanDropTest(unittest.TestCase):
    def test_skips_missing_lower(self):
        self.assertAlmostEqual(cvss40.mean_drop(9.0, [8.0, None], [0.1, 0.5], [0.2, 0.2]), 0.5)

    def test_eq5_counts_but_adds_nothing(self):
        self.assertAlmostEqual(cvss40.mean_drop(9.0, [8.0, 7.0], [0.2, 0], [0.2, None]), 0.5)

    def test_no_lower_at_all(self):
        self.assertEqual(cvss40.mean_drop(9.0, [None, None], [0.1, 0.1], [0.2, 0.2]), 0)


class RoundingTest(unittest.TestCase):
    def test_half_up(self):
        self.assertEqual(cvss40.round_half_up(6.25), 6.3)
        self.assertEqual(cvss40.round_half_up(6.35), 6.4)
        self.assertEqual(cvss40.round_half_up(6.24), 6.2)


class ScoreTest(unittest.TestCase):
    def test_no_impact(self):
        self.assertTrue(cvss40.has_no_impact(metrics(VC="N", VI="N", VA="N")))
        self.assertFalse(cvss40.has_no_impact(metrics(VC="N", VI="N", VA="N", SA="L")))

    def test_known_scores(self):
        for vector, expected in cvss40.KNOWN.items():
            self.assertEqual(cvss40.base_score(vector), expected, vector)

    def test_prefixed_vector(self):
        self.assertEqual(cvss40.base_score("CVSS:4.0/" + BASE), 9.3)

    def test_rating(self):
        self.assertEqual([cvss40.rating(s) for s in (10.0, 9.0, 8.9, 7.0, 6.9, 4.0, 3.9, 0.1, 0.0)],
                         ["Critical", "Critical", "High", "High", "Medium", "Medium", "Low", "Low",
                          "Informational"])


class MainTest(unittest.TestCase):
    def run_main(self, args):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cvss40.main(args)
        return code, out.getvalue()

    def test_scores_vector(self):
        code, out = self.run_main([BASE])
        self.assertEqual(code, 0)
        self.assertIn("CVSS:4.0/" + BASE, out)
        self.assertIn("9.3  Critical", out)

    def test_selftest_passes(self):
        code, out = self.run_main(["--selftest"])
        self.assertEqual(code, 0)
        self.assertIn("passed", out)

    def test_no_args(self):
        self.assertEqual(self.run_main([])[0], 2)


if __name__ == "__main__":
    unittest.main()
