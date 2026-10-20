"""Unit tests for run_stats.py. Run: python -I test_run_stats.py"""
import contextlib
import io
import os
import sys
import unittest

sys.dont_write_bytecode = True  # keep the skill folder free of __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_stats as elapsed  # noqa: E402


def run(args, clock):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        code = elapsed.main(args, clock=clock)
    return code, out.getvalue().strip()


class NowTest(unittest.TestCase):
    def test_returns_positive_int(self):
        value = elapsed.now()
        self.assertIsInstance(value, int)
        self.assertGreater(value, 0)


class ParseStartTest(unittest.TestCase):
    def test_parses_with_whitespace(self):
        self.assertEqual(elapsed.parse_start(" 1700000000\n"), 1700000000)

    def test_rejects_non_numbers_and_non_positive(self):
        for text in ("abc", "", "0", "-5", "1.5"):
            with self.assertRaises(ValueError, msg=text):
                elapsed.parse_start(text)


class ResumeStartTest(unittest.TestCase):
    def test_moves_start_by_wait(self):
        self.assertEqual(elapsed.resume_start(1000, 1100, 1400), 1300)

    def test_no_wait(self):
        self.assertEqual(elapsed.resume_start(1000, 1100, 1100), 1000)

    def test_clock_behind_pause_counts_as_no_wait(self):
        self.assertEqual(elapsed.resume_start(1000, 1100, 1050), 1000)

    def test_pause_before_start_rejected(self):
        with self.assertRaises(ValueError):
            elapsed.resume_start(1000, 900, 1200)


class FormatDurationTest(unittest.TestCase):
    def test_seconds_only(self):
        self.assertEqual(elapsed.format_duration(45), "45s")

    def test_minutes_pad_seconds(self):
        self.assertEqual(elapsed.format_duration(725), "12m 05s")

    def test_hours(self):
        self.assertEqual(elapsed.format_duration(3729), "1h 02m 09s")

    def test_zero_and_negative(self):
        self.assertEqual(elapsed.format_duration(0), "0s")
        self.assertEqual(elapsed.format_duration(-10), "0s")


class FormatTokensTest(unittest.TestCase):
    def test_thousands(self):
        self.assertEqual(elapsed.format_tokens(1234567), "1,234,567")
        self.assertEqual(elapsed.format_tokens(0), "0")


class ParseCountTest(unittest.TestCase):
    def test_number_with_commas(self):
        self.assertEqual(elapsed.parse_count(" 12,500 "), 12500)

    def test_dash_is_unknown(self):
        self.assertIsNone(elapsed.parse_count("-"))

    def test_rejects_bad_values(self):
        for text in ("abc", "-5", "1.5", ""):
            with self.assertRaises(ValueError, msg=text):
                elapsed.parse_count(text)


class TokenUsageTest(unittest.TestCase):
    def test_budget_drop_plus_subagents(self):
        self.assertEqual(elapsed.token_usage(1000000, 880000, [30000, 45000]),
                         {"main": 120000, "subagents": 75000, "subagent_count": 2, "total": 195000})

    def test_unknown_budget(self):
        usage = elapsed.token_usage(None, None, [5000])
        self.assertIsNone(usage["main"])
        self.assertEqual(usage["total"], 5000)

    def test_budget_increase_counts_as_zero(self):
        self.assertEqual(elapsed.token_usage(100, 200, [])["main"], 0)


class DescribeUsageTest(unittest.TestCase):
    def test_known_main(self):
        text = elapsed.describe_usage(elapsed.token_usage(1000000, 880000, [30000]))
        self.assertEqual(text, "main session 120,000 | 1 subagent(s) 30,000 | total 150,000")

    def test_unknown_main(self):
        text = elapsed.describe_usage(elapsed.token_usage(None, None, [30000]))
        self.assertIn("not shown by this session", text)
        self.assertIn("(subagents only)", text)


class TokensCommandTest(unittest.TestCase):
    def test_prints_summary(self):
        code, out = run(["--tokens", "1000000", "880000", "30000"], lambda: 0)
        self.assertEqual(code, 0)
        self.assertIn("total 150,000", out)

    def test_unknown_budget_dashes(self):
        code, out = run(["--tokens", "-", "-", "30000", "20000"], lambda: 0)
        self.assertEqual(code, 0)
        self.assertIn("2 subagent(s) 50,000", out)

    def test_bad_input(self):
        self.assertEqual(run(["--tokens", "x", "1"], lambda: 0)[0], 2)
        self.assertEqual(run(["--tokens", "1"], lambda: 0)[0], 2)
        self.assertEqual(run(["--tokens", "10", "5", "-"], lambda: 0)[0], 2)


class MainTest(unittest.TestCase):
    def test_start_prints_clock(self):
        self.assertEqual(run(["--start"], lambda: 1000), (0, "1000"))

    def test_elapsed_since_start(self):
        self.assertEqual(run(["1000"], lambda: 1125), (0, "2m 05s"))

    def test_pause_prints_clock(self):
        self.assertEqual(run(["--pause"], lambda: 1100), (0, "1100"))

    def test_resume_prints_new_start(self):
        self.assertEqual(run(["--resume", "1000", "1100"], lambda: 1400), (0, "1300"))

    def test_wait_excluded_from_elapsed(self):
        _, new_start = run(["--resume", "1000", "1100"], lambda: 1400)
        self.assertEqual(run([new_start], lambda: 1425), (0, "2m 05s"))

    def test_resume_bad_input(self):
        self.assertEqual(run(["--resume", "1000"], lambda: 1400)[0], 2)
        self.assertEqual(run(["--resume", "1000", "soon"], lambda: 1400)[0], 2)
        self.assertEqual(run(["--resume", "1000", "900"], lambda: 1400)[0], 2)

    def test_bad_start(self):
        code, _ = run(["soon"], lambda: 1000)
        self.assertEqual(code, 2)

    def test_usage(self):
        code, _ = run([], lambda: 1000)
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
