"""Unit tests for sarif.py. Run: python -I test_sarif.py"""
import json
import os
import sys
import unittest

sys.dont_write_bytecode = True  # keep the skill folder free of __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sarif  # noqa: E402


def finding(key="cards/idor", decision="confirmed", severity="critical", paths=("src/Cards.java:42",), **fields):
    base = {"key": key, "title": "Card id not bound to caller", "decision": decision, "severity": severity,
            "paths": list(paths)}
    base.update(fields)
    return base


def severity_of(item):
    if item["decision"] == "needs_confirmation":
        return item["severity_if_confirmed"]
    return None if item["decision"] == "rejected" else item["severity"]


def ledger(findings):
    return {"repo": "cards", "source_ref": "abc123", "profile": "standard", "findings": list(findings)}


ENTRY = {"id": "a", "reason": "fix in Q1", "accepted_by": "security review", "expires": "2027-01-31"}


class SplitLocationTest(unittest.TestCase):
    def test_forms(self):
        self.assertEqual(sarif.split_location("src/A.java"), ("src/A.java", None, None))
        self.assertEqual(sarif.split_location("src/A.java:42"), ("src/A.java", 42, None))
        self.assertEqual(sarif.split_location("src/A.java:42-50"), ("src/A.java", 42, 50))

    def test_colon_inside_path(self):
        self.assertEqual(sarif.split_location("src/a:b/A.java:7"), ("src/a:b/A.java", 7, None))
        self.assertEqual(sarif.split_location("src/a:b/A.java"), ("src/a:b/A.java", None, None))


class RegionTest(unittest.TestCase):
    def test_regions(self):
        self.assertEqual(sarif.region(None, None), {"startLine": 1})
        self.assertEqual(sarif.region(4, None), {"startLine": 4})
        self.assertEqual(sarif.region(4, 9), {"startLine": 4, "endLine": 9})
        self.assertEqual(sarif.region(9, 4), {"startLine": 9})


class LocationTest(unittest.TestCase):
    def test_location(self):
        physical = sarif.location("src\\A.java:3")["physicalLocation"]
        self.assertEqual(physical["artifactLocation"], {"uri": "src/A.java", "uriBaseId": "SRCROOT"})
        self.assertEqual(physical["region"], {"startLine": 3})


class MessageTest(unittest.TestCase):
    def test_confirmed(self):
        self.assertEqual(sarif.message(finding(), "critical"), "Card id not bound to caller (confirmed)")

    def test_needs_confirmation(self):
        item = finding(decision="needs_confirmation", severity=None, severity_if_confirmed="bug")
        self.assertEqual(sarif.message(item, "bug"),
                         "Card id not bound to caller (needs confirmation; bug if confirmed)")

    def test_message_omits_attack_text(self):
        item = finding(attack="Authorization: Bearer super-secret-token-value")
        text = sarif.message(item, "warning")
        self.assertNotIn("super-secret-token-value", text)
        self.assertNotIn("Bearer", text)
        self.assertNotIn("Authorization", text)


class RuleTest(unittest.TestCase):
    def test_rule(self):
        rule = sarif.rule(finding(), "bug")
        self.assertEqual(rule["id"], "cards/idor")
        self.assertEqual(rule["defaultConfiguration"], {"level": "error"})
        self.assertEqual(rule["properties"]["security-severity"], "7.5")

    def test_levels_cover_every_severity(self):
        self.assertEqual(set(sarif.LEVELS), set(sarif.SECURITY_SEVERITY))


class SuppressionTest(unittest.TestCase):
    def test_suppression(self):
        self.assertEqual(sarif.suppression(ENTRY), {
            "kind": "external", "status": "accepted",
            "justification": "fix in Q1 (accepted by security review until 2027-01-31)"})


class ResultsForTest(unittest.TestCase):
    def test_one_result_per_path(self):
        results = sarif.results_for(finding(paths=["a.ts:1", "b.ts:2"]), "warning", None)
        self.assertEqual([r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results],
                         ["a.ts", "b.ts"])
        self.assertEqual(results[0]["level"], "warning")
        self.assertEqual(results[0]["partialFingerprints"], {"appsecReviewKey/v1": "cards/idor|a.ts"})
        self.assertNotIn("suppressions", results[0])

    def test_fingerprint_ignores_line(self):
        first = sarif.results_for(finding(paths=["a.ts:1"]), "bug", None)[0]
        moved = sarif.results_for(finding(paths=["a.ts:90"]), "bug", None)[0]
        self.assertEqual(first["partialFingerprints"], moved["partialFingerprints"])

    def test_waived(self):
        result = sarif.results_for(finding(), "bug", ENTRY)[0]
        self.assertEqual(result["suppressions"][0]["kind"], "external")

    def test_no_paths(self):
        self.assertEqual(sarif.results_for(finding(paths=()), "bug", None), [])


class ToSarifTest(unittest.TestCase):
    def setUp(self):
        self.findings = [
            finding(),
            finding(key="cards/otp", decision="needs_confirmation", severity=None, severity_if_confirmed="bug"),
            finding(key="cards/rej", decision="rejected", severity=None, disproof="a.ts:1"),
        ]

    def test_skips_rejected(self):
        log = sarif.to_sarif(ledger(self.findings), severity_of)
        run = log["runs"][0]
        self.assertEqual([r["ruleId"] for r in run["results"]], ["cards/idor", "cards/otp"])
        self.assertEqual([r["id"] for r in run["tool"]["driver"]["rules"]], ["cards/idor", "cards/otp"])

    def test_envelope(self):
        log = sarif.to_sarif(ledger([]), severity_of)
        self.assertEqual(log["version"], "2.1.0")
        self.assertEqual(log["runs"][0]["tool"]["driver"]["name"], "appsec-review")
        self.assertEqual(log["runs"][0]["properties"]["sourceRef"], "abc123")
        self.assertEqual(log["runs"][0]["results"], [])

    def test_waiver_applied(self):
        log = sarif.to_sarif(ledger(self.findings), severity_of,
                             lambda item, severity: ENTRY if item["key"] == "cards/otp" else None)
        suppressed = [r["ruleId"] for r in log["runs"][0]["results"] if "suppressions" in r]
        self.assertEqual(suppressed, ["cards/otp"])

    def test_serializable(self):
        json.dumps(sarif.to_sarif(ledger(self.findings), severity_of))


if __name__ == "__main__":
    unittest.main()
