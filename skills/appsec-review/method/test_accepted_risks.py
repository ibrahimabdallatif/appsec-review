"""Unit tests for accepted_risks.py. Run: python -I test_accepted_risks.py"""
import datetime
import os
import sys
import unittest

sys.dont_write_bytecode = True  # keep the skill folder free of __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import accepted_risks as ar  # noqa: E402

TODAY = datetime.date(2026, 10, 16)


def entry(**fields):
    base = {"id": "legacy-idor", "paths_any": ["src/legacy/Orders"], "text": "order.*(owner|idor)",
            "max_severity": "bug", "reason": "endpoint removed next release", "accepted_by": "security review",
            "expires": "2026-12-31"}
    base.update(fields)
    return base


def finding(key="orders/idor", title="Order id not bound to caller", severity="bug",
            paths=("src/legacy/OrdersController.java:42",)):
    return {"key": key, "title": title, "decision": "confirmed", "severity": severity, "paths": list(paths)}


def severity_of(item):
    return item["severity"]


class ParseDateTest(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(ar.parse_date("2026-12-31"), datetime.date(2026, 12, 31))

    def test_invalid(self):
        for value in ("2026-13-01", "31/12/2026", "2026-1-1", None, 20261231, "2026-12-31T00:00"):
            self.assertIsNone(ar.parse_date(value), value)


class HelpersTest(unittest.TestCase):
    def test_is_valid_regex(self):
        self.assertTrue(ar.is_valid_regex("a|b"))
        self.assertFalse(ar.is_valid_regex("("))
        self.assertFalse(ar.is_valid_regex(None))

    def test_is_text_list(self):
        self.assertTrue(ar.is_text_list(["a"]))
        for value in ([], "a", ["a", ""], [1]):
            self.assertFalse(ar.is_text_list(value), value)

    def test_duplicate_ids(self):
        self.assertEqual(ar.duplicate_ids([entry(), entry(), entry(id="x")]), ["legacy-idor"])

    def test_more_severe(self):
        self.assertTrue(ar.more_severe("critical", "bug"))
        self.assertFalse(ar.more_severe("bug", "bug"))
        self.assertFalse(ar.more_severe("warning", "bug"))


class CheckEntryTest(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(ar.check_entry(entry()), [])

    def test_not_an_object(self):
        self.assertEqual(ar.check_entry("x"), ["accepted: every entry must be an object"])

    def test_missing_fields(self):
        errors = ar.check_entry(entry(reason="", expires=None))
        self.assertEqual(errors, ["accepted legacy-idor: missing 'reason'",
                                  "accepted legacy-idor: missing 'expires'"])

    def test_bad_values(self):
        errors = ar.check_entry(entry(paths_any="src/", text="(", max_severity="high", expires="soon"))
        self.assertEqual(len(errors), 4)
        self.assertIn("paths_any", errors[0])
        self.assertIn("regex", errors[1])
        self.assertIn("max_severity", errors[2])
        self.assertIn("YYYY-MM-DD", errors[3])


class CheckAcceptedTest(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(ar.check_accepted({"accepted": [entry(), entry(id="other")]}), [])

    def test_empty_list_is_valid(self):
        self.assertEqual(ar.check_accepted({"accepted": []}), [])

    def test_bad_top_level(self):
        for doc in ([], {}, {"accepted": {}}):
            self.assertEqual(len(ar.check_accepted(doc)), 1, doc)

    def test_duplicates(self):
        self.assertEqual(ar.check_accepted({"accepted": [entry(), entry()]}),
                         ["accepted: duplicate id 'legacy-idor'"])

    def test_non_object_entry_skips_duplicate_check(self):
        self.assertEqual(ar.check_accepted({"accepted": ["x"]}), ["accepted: every entry must be an object"])


class MatchesTest(unittest.TestCase):
    def test_path_and_text(self):
        self.assertTrue(ar.matches(entry(), finding()))

    def test_text_matches_key_or_title_ignoring_case(self):
        self.assertTrue(ar.matches(entry(text="ORDERS/IDOR"), finding(title="x")))
        self.assertTrue(ar.matches(entry(text="bound to caller"), finding(key="k")))

    def test_wrong_path(self):
        self.assertFalse(ar.matches(entry(), finding(paths=["src/api/OrdersController.java:42"])))

    def test_wrong_text(self):
        self.assertFalse(ar.matches(entry(), finding(key="orders/sqli", title="SQL injection in search")))

    def test_no_paths(self):
        self.assertFalse(ar.matches(entry(), finding(paths=())))

    def test_entry_for_first_match(self):
        first, second = entry(id="a"), entry(id="b")
        self.assertIs(ar.entry_for(finding(), [entry(id="z", text="nothing"), first, second]), first)
        self.assertIsNone(ar.entry_for(finding(), []))


class WhyStillBlockingTest(unittest.TestCase):
    def test_waived(self):
        self.assertIsNone(ar.why_still_blocking(entry(), "bug", TODAY))
        self.assertIsNone(ar.why_still_blocking(entry(expires="2026-10-16"), "warning", TODAY))

    def test_expired(self):
        note = ar.why_still_blocking(entry(expires="2026-10-15"), "bug", TODAY)
        self.assertEqual(note, "acceptance 'legacy-idor' expired 2026-10-15")

    def test_above_accepted_severity(self):
        note = ar.why_still_blocking(entry(), "critical", TODAY)
        self.assertEqual(note, "above acceptance 'legacy-idor' (accepted up to bug)")


class WaiverForTest(unittest.TestCase):
    def test_waived(self):
        self.assertEqual(ar.waiver_for(finding(), "bug", [entry()], TODAY), entry())

    def test_not_waived(self):
        self.assertIsNone(ar.waiver_for(finding(), "critical", [entry()], TODAY))
        self.assertIsNone(ar.waiver_for(finding(), "bug", [entry(expires="2026-01-01")], TODAY))
        self.assertIsNone(ar.waiver_for(finding(), "bug", [], TODAY))


class ApplyTest(unittest.TestCase):
    def test_splits_waived_and_blocking(self):
        accepted = finding()
        unmatched = finding(key="cards/sqli", title="SQL injection", paths=["src/Cards.java:9"])
        escalated = finding(key="orders/idor-admin", severity="critical")
        still, waived = ar.apply([accepted, unmatched, escalated], [entry()], severity_of, TODAY)
        self.assertEqual(waived, [(accepted, entry())])
        self.assertEqual([(f["key"], note) for f, note in still],
                         [("cards/sqli", None),
                          ("orders/idor-admin", "above acceptance 'legacy-idor' (accepted up to bug)")])

    def test_no_entries(self):
        still, waived = ar.apply([finding()], [], severity_of, TODAY)
        self.assertEqual((len(still), waived), (1, []))


class UnusedTest(unittest.TestCase):
    def test_unused(self):
        used, stale = entry(id="used"), entry(id="stale", paths_any=["src/removed/"])
        self.assertEqual(ar.unused([used, stale], [finding()]), [stale])


if __name__ == "__main__":
    unittest.main()
