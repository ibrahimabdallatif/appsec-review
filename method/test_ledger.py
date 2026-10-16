"""Unit tests for ledger.py. Run: python -I test_ledger.py"""
import copy
import json
import os
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True  # keep the skill folder free of __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger  # noqa: E402

AREAS = {"access-control", "injection-input", "wildcard", "obvious-things"}


def unit(status="covered", area="access-control", surface="src/api/Cards.java#GET /cards/{id}", **fields):
    base = {
        "id": "%s::%s" % (surface, area), "surface": surface, "area": area, "status": status,
        "reviewed_paths": ["src/api/Cards.java"], "checks": ["owner check present"],
        "finding_keys": [], "unresolved": [],
    }
    base.update(fields)
    return base


def finding(key="cards-idor", decision="confirmed", severity="critical", **fields):
    base = {"key": key, "title": "Card id not bound to caller", "decision": decision,
            "severity": severity, "paths": ["src/api/Cards.java"]}
    base.update(fields)
    return base


def ledger_with(units, findings=(), profile="deep"):
    return {"repo": "cards", "source_ref": "abc123", "profile": profile, "scope": "repo",
            "units": list(units), "findings": list(findings)}


class AllowedAreasTest(unittest.TestCase):
    def test_reads_rule_stems_and_hunters(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("00-overview.md", "access-control.md", "notes.txt"):
                open(os.path.join(tmp, name), "w").close()
            self.assertEqual(ledger.allowed_areas(tmp), {"access-control", "wildcard", "obvious-things"})

    def test_missing_dir_gives_hunters_only(self):
        self.assertEqual(ledger.allowed_areas("/no/such/dir"), set(ledger.HUNTER_AREAS))

    def test_real_rules_dir_includes_new_category(self):
        self.assertIn("web-protocol-identity", ledger.allowed_areas())


class IsRelativePathTest(unittest.TestCase):
    def test_accepts_relative(self):
        self.assertTrue(ledger.is_relative_path("src/a/b.java"))

    def test_rejects_absolute_drive_traversal_and_empty(self):
        for path in ("/etc/passwd", "\\x", "C:/repo/a", "src/../../x", "", "  ", None):
            self.assertFalse(ledger.is_relative_path(path), path)


class MissingKeysTest(unittest.TestCase):
    def test_lists_missing(self):
        self.assertEqual(ledger.missing_keys({"a": 1}, ("a", "b"), "x"), ["x: missing 'b'"])


class CheckTopTest(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(ledger.check_top(ledger_with([])), [])

    def test_bad_scope(self):
        data = ledger_with([])
        data["scope"] = "everything"
        self.assertTrue(ledger.check_top(data))

    def test_bad_or_missing_profile(self):
        self.assertTrue(ledger.check_top(ledger_with([], profile="quick")))
        data = ledger_with([])
        del data["profile"]
        self.assertTrue(ledger.check_top(data))


class CheckGranularityTest(unittest.TestCase):
    def test_standard_rejects_route_surface(self):
        self.assertTrue(ledger.check_granularity(unit(), "standard"))

    def test_standard_accepts_module_surface(self):
        self.assertEqual(ledger.check_granularity(unit(surface="src/api/Cards.java"), "standard"), [])

    def test_deep_accepts_route_surface(self):
        self.assertEqual(ledger.check_granularity(unit(), "deep"), [])


class CheckUnitIdTest(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(ledger.check_unit_id(unit(), AREAS), [])

    def test_unknown_area(self):
        self.assertTrue(ledger.check_unit_id(unit(area="magic"), AREAS))

    def test_id_mismatch(self):
        self.assertTrue(ledger.check_unit_id(unit(id="other"), AREAS))

    def test_separator_in_surface(self):
        bad = unit(surface="a::b")
        self.assertTrue(ledger.check_unit_id(bad, AREAS))


class CheckUnitStateTest(unittest.TestCase):
    def test_covered_ok(self):
        self.assertEqual(ledger.check_unit_state(unit()), [])

    def test_covered_without_evidence(self):
        self.assertTrue(ledger.check_unit_state(unit(checks=[])))

    def test_planned_with_evidence(self):
        self.assertTrue(ledger.check_unit_state(unit(status="planned")))

    def test_planned_empty_ok(self):
        self.assertEqual(ledger.check_unit_state(unit(status="planned", reviewed_paths=[], checks=[])), [])

    def test_deferred_needs_reason(self):
        empty = dict(reviewed_paths=[], checks=[])
        self.assertTrue(ledger.check_unit_state(unit(status="deferred", **empty)))
        self.assertEqual(ledger.check_unit_state(unit(status="deferred", unresolved=["budget"], **empty)), [])

    def test_finding_needs_keys(self):
        self.assertTrue(ledger.check_unit_state(unit(status="finding")))
        self.assertEqual(ledger.check_unit_state(unit(status="finding", finding_keys=["k"])), [])

    def test_blocked_needs_unresolved(self):
        self.assertTrue(ledger.check_unit_state(unit(status="blocked")))
        self.assertEqual(ledger.check_unit_state(unit(status="blocked", unresolved=["proxy config"])), [])

    def test_unknown_status(self):
        self.assertTrue(ledger.check_unit_state(unit(status="done")))


class CheckPathsTest(unittest.TestCase):
    def test_flags_absolute(self):
        self.assertEqual(len(ledger.check_paths(["ok.py", "/abs.py"], "x")), 1)


class CheckUnitTest(unittest.TestCase):
    def test_missing_field_short_circuits(self):
        bad = unit()
        del bad["checks"]
        self.assertEqual(ledger.check_unit(bad, AREAS), ["unit %s: missing 'checks'" % bad["id"]])

    def test_absolute_reviewed_path(self):
        self.assertTrue(ledger.check_unit(unit(reviewed_paths=["/src/a"]), AREAS))

    def test_profile_passed_through(self):
        self.assertTrue(ledger.check_unit(unit(), AREAS, "standard"))
        self.assertEqual(ledger.check_unit(unit(), AREAS, "deep"), [])


class CheckFindingTest(unittest.TestCase):
    def test_confirmed_ok(self):
        self.assertEqual(ledger.check_finding(finding()), [])

    def test_confirmed_without_severity(self):
        self.assertTrue(ledger.check_finding(finding(severity=None)))

    def test_rejected_with_severity(self):
        self.assertTrue(ledger.check_finding(finding(decision="rejected")))

    def test_needs_confirmation_null_severity_ok(self):
        nc = finding(decision="needs_confirmation", severity=None, severity_if_confirmed="critical")
        self.assertEqual(ledger.check_finding(nc), [])

    def test_rejected_with_disproof_ok(self):
        rejected = finding(decision="rejected", severity=None, disproof="src/api/Guard.java:42 owner check")
        self.assertEqual(ledger.check_finding(rejected), [])

    def test_hardening_cannot_be_critical(self):
        self.assertTrue(ledger.check_finding(finding(decision="hardening")))
        self.assertEqual(ledger.check_finding(finding(decision="hardening", severity="warning")), [])

    def test_unknown_decision(self):
        self.assertTrue(ledger.check_finding(finding(decision="maybe")))


class CheckRejectionProofTest(unittest.TestCase):
    def test_rejected_without_disproof(self):
        self.assertTrue(ledger.check_rejection_proof(finding(decision="rejected", severity=None), "x"))

    def test_rejected_disproof_without_line(self):
        rejected = finding(decision="rejected", severity=None, disproof="a guard exists somewhere")
        self.assertTrue(ledger.check_rejection_proof(rejected, "x"))

    def test_rejected_with_path_line(self):
        rejected = finding(decision="rejected", severity=None, disproof="src/a.ts:10")
        self.assertEqual(ledger.check_rejection_proof(rejected, "x"), [])

    def test_disproof_only_on_rejected(self):
        self.assertTrue(ledger.check_rejection_proof(finding(disproof="src/a.ts:10"), "x"))
        self.assertEqual(ledger.check_rejection_proof(finding(), "x"), [])


class CheckSeverityIfConfirmedTest(unittest.TestCase):
    def test_needs_confirmation_requires_it(self):
        nc = finding(decision="needs_confirmation", severity=None)
        self.assertTrue(ledger.check_severity_if_confirmed(nc, "x"))

    def test_needs_confirmation_rejects_unknown_value(self):
        nc = finding(decision="needs_confirmation", severity=None, severity_if_confirmed="huge")
        self.assertTrue(ledger.check_severity_if_confirmed(nc, "x"))

    def test_needs_confirmation_with_value(self):
        nc = finding(decision="needs_confirmation", severity=None, severity_if_confirmed="bug")
        self.assertEqual(ledger.check_severity_if_confirmed(nc, "x"), [])

    def test_not_allowed_on_other_decisions(self):
        self.assertTrue(ledger.check_severity_if_confirmed(finding(severity_if_confirmed="bug"), "x"))
        self.assertEqual(ledger.check_severity_if_confirmed(finding(), "x"), [])


class CheckDeferralTest(unittest.TestCase):
    def deferred(self):
        return unit(status="deferred", reviewed_paths=[], checks=[], unresolved=["time"])

    def test_deferred_without_user_stop(self):
        self.assertTrue(ledger.check_deferral(self.deferred(), False))

    def test_deferred_after_user_stop(self):
        self.assertEqual(ledger.check_deferral(self.deferred(), True), [])

    def test_other_status_unaffected(self):
        self.assertEqual(ledger.check_deferral(unit(), False), [])


class DuplicatesTest(unittest.TestCase):
    def test_finds_repeats(self):
        self.assertEqual(ledger.duplicates(["a", "b", "a", "c", "b"]), ["a", "b"])


class CheckLinksTest(unittest.TestCase):
    def test_linked_ok(self):
        units = [unit(status="finding", finding_keys=["cards-idor"])]
        self.assertEqual(ledger.check_links(units, [finding()]), [])

    def test_unknown_key(self):
        self.assertTrue(ledger.check_links([unit(status="finding", finding_keys=["nope"])], []))

    def test_orphan_finding(self):
        self.assertTrue(ledger.check_links([unit()], [finding()]))

    def test_only_rejected_links(self):
        units = [unit(status="finding", finding_keys=["cards-idor"])]
        self.assertTrue(ledger.check_links(units, [finding(decision="rejected", severity=None)]))


class ValidateTest(unittest.TestCase):
    def valid(self):
        return ledger_with([unit(status="finding", finding_keys=["cards-idor"]),
                            unit(area="wildcard")], [finding()])

    def test_valid_ledger(self):
        self.assertEqual(ledger.validate(self.valid(), AREAS), [])

    def test_not_an_object(self):
        self.assertTrue(ledger.validate([], AREAS))

    def test_standard_ledger_with_route_surface_fails(self):
        data = self.valid()
        data["profile"] = "standard"
        self.assertIn("module paths", " ".join(ledger.validate(data, AREAS)))

    def test_standard_ledger_with_module_surfaces(self):
        data = ledger_with([unit(surface="src/api/Cards.java", status="finding", finding_keys=["cards-idor"]),
                            unit(surface="<repo>", area="wildcard")], [finding()], profile="standard")
        self.assertEqual(ledger.validate(data, AREAS), [])

    def test_deferred_unit_needs_stopped_early(self):
        data = self.valid()
        data["units"].append(unit(area="obvious-things", status="deferred", reviewed_paths=[], checks=[],
                                  unresolved=["user stopped the run"]))
        self.assertIn("stopped_early", " ".join(ledger.validate(data, AREAS)))
        data["stopped_early"] = True
        self.assertEqual(ledger.validate(data, AREAS), [])

    def test_duplicate_unit(self):
        data = self.valid()
        data["units"].append(copy.deepcopy(data["units"][1]))
        self.assertIn("duplicate unit id", " ".join(ledger.validate(data, AREAS)))


class SummaryTest(unittest.TestCase):
    def test_counts(self):
        data = ledger_with([unit(status="finding", finding_keys=["cards-idor"]), unit(area="wildcard")], [finding()])
        self.assertEqual(ledger.summary(data),
                         {"units": {"finding": 1, "covered": 1}, "findings": {"confirmed": 1},
                          "root_causes": 1, "locations": 1})

    def test_root_causes_and_locations_skip_rejected(self):
        findings = [finding(paths=["a.ts", "b.ts", "c.ts"]),
                    finding(key="other", decision="rejected", severity=None, disproof="a.ts:1")]
        result = ledger.summary(ledger_with([], findings))
        self.assertEqual((result["root_causes"], result["locations"]), (1, 3))


class MainTest(unittest.TestCase):
    def write(self, data):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(data, handle)
        handle.close()
        self.addCleanup(os.remove, handle.name)
        return handle.name

    def test_usage(self):
        self.assertEqual(ledger.main([]), 2)

    def test_invalid_returns_1(self):
        self.assertEqual(ledger.main([self.write({"repo": "x"})]), 1)

    def test_valid_returns_0(self):
        data = ledger_with([unit(area="wildcard")])
        self.assertEqual(ledger.main([self.write(data)]), 0)


if __name__ == "__main__":
    unittest.main()
