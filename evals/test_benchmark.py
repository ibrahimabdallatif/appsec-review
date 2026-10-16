"""Unit tests for benchmark.py. Run: python -I test_benchmark.py"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True  # keep the skill folder free of __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import benchmark  # noqa: E402


def expected(id_="otp", min_severity="critical", paths=("auth.ts",), text=r"otp", **extra):
    item = {"id": id_, "min_severity": min_severity, "paths_any": list(paths), "text": text}
    item.update(extra)
    return item


def finding(key="auth/hardcoded-otp", title="Fixed OTP", decision="confirmed", severity="critical",
            paths=("src/auth.ts",), **extra):
    item = {"key": key, "title": title, "decision": decision, "severity": severity, "paths": list(paths)}
    item.update(extra)
    return item


class SeverityRankTest(unittest.TestCase):
    def test_order(self):
        self.assertLess(benchmark.severity_rank("warning"), benchmark.severity_rank("critical"))
        self.assertEqual(benchmark.severity_rank(None), -1)


class CheckBenchmarkTest(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(benchmark.check_benchmark({"expected": [expected()]}), [])

    def test_empty(self):
        self.assertTrue(benchmark.check_benchmark({"expected": []}))

    def test_bad_severity_regex_and_missing_key(self):
        bad = expected(min_severity="huge", text="(")
        del bad["paths_any"]
        errors = " ".join(benchmark.check_benchmark({"expected": [bad]}))
        self.assertIn("min_severity", errors)
        self.assertIn("bad regex", errors)
        self.assertIn("paths_any", errors)


class FindingTextTest(unittest.TestCase):
    def test_joins_key_and_title(self):
        self.assertEqual(benchmark.finding_text({"key": "a/b", "title": "T"}), "a/b T")


class MatchesTest(unittest.TestCase):
    def test_path_and_text(self):
        self.assertTrue(benchmark.matches(expected(), finding()))

    def test_text_case_insensitive(self):
        self.assertTrue(benchmark.matches(expected(text="OTP"), finding(key="x", title="fixed otp")))

    def test_wrong_path(self):
        self.assertFalse(benchmark.matches(expected(), finding(paths=("src/other.ts",))))

    def test_wrong_text(self):
        self.assertFalse(benchmark.matches(expected(text="cors"), finding()))


class EffectiveTest(unittest.TestCase):
    def test_needs_confirmation_uses_if_confirmed(self):
        nc = finding(decision="needs_confirmation", severity=None, severity_if_confirmed="bug")
        self.assertEqual(benchmark.effective(nc), ("bug", "needs_confirmation"))

    def test_confirmed(self):
        self.assertEqual(benchmark.effective(finding()), ("critical", "confirmed"))


class CandidateRankTest(unittest.TestCase):
    def test_confirmed_beats_rejected_and_needs_confirmation(self):
        rejected = finding(decision="rejected", severity=None)
        nc = finding(decision="needs_confirmation", severity=None, severity_if_confirmed="critical")
        confirmed = finding(severity="warning")
        best = max([rejected, nc, confirmed], key=benchmark.candidate_rank)
        self.assertIs(best, confirmed)


class ClassifyTest(unittest.TestCase):
    def test_missed(self):
        self.assertEqual(benchmark.classify(expected(), None), "missed")

    def test_found(self):
        self.assertEqual(benchmark.classify(expected(), finding()), "found")

    def test_downgraded(self):
        self.assertEqual(benchmark.classify(expected(), finding(severity="bug")), "downgraded")

    def test_rejected(self):
        self.assertEqual(benchmark.classify(expected(), finding(decision="rejected", severity=None)), "rejected")

    def test_needs_confirmation_flagged_only_when_expected_confirmed(self):
        nc = finding(decision="needs_confirmation", severity=None, severity_if_confirmed="critical")
        self.assertEqual(benchmark.classify(expected(), nc), "found")
        self.assertEqual(benchmark.classify(expected(expect_confirmed=True), nc), "needs_confirmation")


class ScoreTest(unittest.TestCase):
    def test_results_and_extras(self):
        bench = {"expected": [expected(), expected(id_="cors", min_severity="bug", paths=("main.ts",), text="cors")]}
        ledger = {"findings": [finding(), finding(key="logs/x", title="Tokens in logs", paths=("app.module.ts",))]}
        scored = benchmark.score(bench, ledger)
        self.assertEqual([r["status"] for r in scored["results"]], ["found", "missed"])
        self.assertEqual(scored["extras"], ["logs/x"])

    def test_rejected_extras_not_listed(self):
        ledger = {"findings": [finding(key="q", title="nothing", decision="rejected", severity=None)]}
        self.assertEqual(benchmark.score({"expected": [expected()]}, ledger)["extras"], [])


class RecallTest(unittest.TestCase):
    def test_counts_found_and_needs_confirmation(self):
        results = [{"status": "found", "human_confirmed": True}, {"status": "needs_confirmation",
                   "human_confirmed": False}, {"status": "missed", "human_confirmed": True}]
        self.assertEqual(benchmark.recall(results), (2, 3))
        self.assertEqual(benchmark.recall(results, only_confirmed=True), (1, 2))


class FormatReportTest(unittest.TestCase):
    def test_contains_recall_and_extras(self):
        scored = benchmark.score({"expected": [expected(human_confirmed=True)]}, {"findings": [finding()]})
        text = benchmark.format_report(scored)
        self.assertIn("Recall: 1/1", text)
        self.assertIn("human-confirmed findings: 1/1", text)
        self.assertIn("Extra findings not in the benchmark (0)", text)


class MainTest(unittest.TestCase):
    def write(self, data):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(data, handle)
        handle.close()
        self.addCleanup(os.remove, handle.name)
        return handle.name

    def run_main(self, args):
        with contextlib.redirect_stdout(io.StringIO()):
            return benchmark.main(args)

    def test_usage(self):
        self.assertEqual(self.run_main([]), 2)

    def test_all_found_returns_0(self):
        self.assertEqual(self.run_main([self.write({"expected": [expected()]}),
                                        self.write({"findings": [finding()]})]), 0)

    def test_missed_returns_1(self):
        self.assertEqual(self.run_main([self.write({"expected": [expected()]}), self.write({"findings": []})]), 1)

    def test_bad_benchmark_returns_2(self):
        self.assertEqual(self.run_main([self.write({"expected": []}), self.write({"findings": []})]), 2)


if __name__ == "__main__":
    unittest.main()
