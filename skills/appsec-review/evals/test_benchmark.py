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


def absent(id_="admin-guard", paths=("admin.ts",), text=r"admin"):
    return {"id": id_, "paths_any": list(paths), "text": text}


class CheckAbsentTest(unittest.TestCase):
    def test_valid_decoy(self):
        self.assertEqual(benchmark.check_benchmark({"expected": [expected()], "absent": [absent()]}), [])

    def test_decoy_missing_key_and_bad_regex(self):
        bad = absent(text="(")
        del bad["paths_any"]
        errors = " ".join(benchmark.check_benchmark({"expected": [expected()], "absent": [bad]}))
        self.assertIn("absent admin-guard: missing 'paths_any'", errors)
        self.assertIn("bad regex", errors)


class CheckMatcherTest(unittest.TestCase):
    def test_reports_missing_keys(self):
        self.assertEqual(benchmark.check_matcher({"text": "x"}, "e", ("id", "text")), ["e: missing 'id'"])


class CheckExpectedTest(unittest.TestCase):
    def test_valid_and_bad_severity(self):
        self.assertEqual(benchmark.check_expected(expected()), [])
        self.assertIn("min_severity", " ".join(benchmark.check_expected(expected(min_severity="x"))))


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


def admin_finding(decision="confirmed", key="admin/no-guard"):
    severity = None if decision == "rejected" else "bug"
    return finding(key=key, title="Admin route has no guard", decision=decision, severity=severity,
                   paths=("src/admin.ts",))


class DecoyTest(unittest.TestCase):
    def test_is_reported(self):
        self.assertTrue(benchmark.is_reported(finding()))
        self.assertFalse(benchmark.is_reported(finding(decision="rejected")))

    def test_classify_decoy(self):
        self.assertEqual(benchmark.classify_decoy([]), "clean")
        self.assertEqual(benchmark.classify_decoy([admin_finding("rejected")]), "rejected")
        self.assertEqual(benchmark.classify_decoy([admin_finding("rejected"), admin_finding()]), "reported")

    def test_score_decoys_marks_used(self):
        used, hit = set(), admin_finding()
        decoys = benchmark.score_decoys({"absent": [absent()]}, [hit, finding()], used)
        self.assertEqual(decoys, [{"id": "admin-guard", "status": "reported", "matched": ["admin/no-guard"]}])
        self.assertEqual(used, {id(hit)})

    def test_score_without_absent(self):
        self.assertEqual(benchmark.score({"expected": [expected()]}, {"findings": []})["decoys"], [])

    def test_decoy_hit_is_not_an_extra(self):
        scored = benchmark.score({"expected": [expected()], "absent": [absent()]},
                                 {"findings": [finding(), admin_finding()]})
        self.assertEqual(scored["extras"], [])
        self.assertEqual(len(benchmark.false_positives(scored)), 1)

    def test_precision(self):
        bench = {"expected": [expected(), expected(id_="cors", paths=("main.ts",), text="cors")],
                 "absent": [absent()]}
        scored = benchmark.score(bench, {"findings": [finding(severity="bug"), admin_finding()]})
        self.assertEqual(benchmark.precision(scored), (1, 2))

    def test_format_decoys(self):
        bench = {"expected": [expected()], "absent": [absent(), absent(id_="safe-sql", paths=("db.ts",))]}
        lines = benchmark.format_decoys(benchmark.score(bench, {"findings": [finding(), admin_finding()]}))
        text = "\n".join(lines)
        self.assertIn("FALSE-POSITIVE     admin-guard", text)
        self.assertIn("<- admin/no-guard", text)
        self.assertIn("CLEAN              safe-sql", text)
        self.assertIn("False positives: 1/2 decoys reported", text)
        self.assertIn("Precision on labelled findings: 1/2", text)

    def test_format_decoys_empty(self):
        self.assertEqual(benchmark.format_decoys({"results": [], "decoys": []}), [])


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


def scored_run(statuses, extras=(), decoys=()):
    results = [{"id": "e%d" % i, "status": st, "min_severity": "bug", "human_confirmed": False}
               for i, st in enumerate(statuses)]
    decoy_results = [{"id": "d%d" % i, "status": st, "matched": []} for i, st in enumerate(decoys)]
    return {"results": results, "decoys": decoy_results, "extras": list(extras)}


class DecoyStabilityTest(unittest.TestCase):
    def setUp(self):
        self.runs = [scored_run(["found"], decoys=["reported", "clean"]),
                     scored_run(["found"], decoys=["rejected", "clean"])]

    def test_decoy_counts(self):
        self.assertEqual(benchmark.decoy_counts(self.runs), {"d0": 1, "d1": 0})

    def test_format_decoy_stability(self):
        text = "\n".join(benchmark.format_decoy_stability(self.runs))
        self.assertIn("FALSE-POSITIVE d0                         1/2 runs", text)
        self.assertIn("Decoys never reported: 1/2", text)

    def test_no_decoys(self):
        self.assertEqual(benchmark.format_decoy_stability([scored_run(["found"])]), [])


class StabilityTest(unittest.TestCase):
    def setUp(self):
        self.runs = [scored_run(["found", "found", "missed"], ["x", "y"]),
                     scored_run(["found", "missed", "missed"], ["x"]),
                     scored_run(["needs_confirmation", "found", "rejected"], ["x"])]

    def test_is_hit(self):
        self.assertTrue(benchmark.is_hit({"status": "needs_confirmation"}))
        self.assertFalse(benchmark.is_hit({"status": "downgraded"}))

    def test_hit_counts(self):
        counts = benchmark.hit_counts(self.runs)
        self.assertEqual([counts[k]["hits"] for k in ("e0", "e1", "e2")], [3, 2, 0])
        self.assertEqual(counts["e2"]["statuses"], {"missed": 2, "rejected": 1})

    def test_extra_counts(self):
        self.assertEqual(benchmark.extra_counts(self.runs), {"x": 3, "y": 1})

    def test_stability_label(self):
        self.assertEqual([benchmark.stability_label(h, 3) for h in (3, 1, 0)], ["STABLE", "FLAKY", "LOST"])

    def test_misses_text(self):
        self.assertEqual(benchmark.misses_text({"found": 2, "missed": 1}), " (missed 1)")
        self.assertEqual(benchmark.misses_text({"found": 3}), "")

    def test_format_stability(self):
        text = benchmark.format_stability(self.runs)
        self.assertIn("STABLE  e0", text)
        self.assertIn("FLAKY   e1                         2/3 runs (missed 1)", text)
        self.assertIn("LOST    e2", text)
        self.assertIn("Found in every run: 1/3", text)
        self.assertIn("Mean recall per run: 1.7/3", text)
        self.assertIn("Extras reported by some runs only (1): y 1/3", text)


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

    def test_stable_runs_return_0(self):
        bench = self.write({"expected": [expected()]})
        run = self.write({"findings": [finding()]})
        self.assertEqual(self.run_main([bench, run, run]), 0)

    def test_flaky_runs_return_1(self):
        bench = self.write({"expected": [expected()]})
        self.assertEqual(self.run_main([bench, self.write({"findings": [finding()]}),
                                        self.write({"findings": []})]), 1)

    def test_reported_decoy_returns_1(self):
        bench = self.write({"expected": [expected()], "absent": [absent()]})
        self.assertEqual(self.run_main([bench, self.write({"findings": [finding(), admin_finding()]})]), 1)

    def test_rejected_decoy_returns_0(self):
        bench = self.write({"expected": [expected()], "absent": [absent()]})
        run = self.write({"findings": [finding(), admin_finding("rejected")]})
        self.assertEqual(self.run_main([bench, run]), 0)

    def test_decoy_in_one_of_many_runs_returns_1(self):
        bench = self.write({"expected": [expected()], "absent": [absent()]})
        clean = self.write({"findings": [finding()]})
        noisy = self.write({"findings": [finding(), admin_finding()]})
        self.assertEqual(self.run_main([bench, clean, noisy]), 1)

    def test_bad_benchmark_returns_2(self):
        self.assertEqual(self.run_main([self.write({"expected": []}), self.write({"findings": []})]), 2)


if __name__ == "__main__":
    unittest.main()
