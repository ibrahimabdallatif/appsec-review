"""Unit tests for ledger.py. Run: python -I test_ledger.py"""
import contextlib
import copy
import datetime
import io
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.dont_write_bytecode = True  # keep the skill folder free of __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ledger  # noqa: E402

AREAS = {"access-control", "injection-input", "wildcard", "obvious-things", "abuse-path"}
THREAT_MODEL = {"assets": [{"id": "card-pan", "what": "card numbers returned by /cards/{id}"}],
                "actors": ["customer", "anonymous"], "boundaries": ["browser -> API"]}


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


def abuse_unit(slug="other-customer-reads-pan", status="covered", **fields):
    base = unit(status=status, area="abuse-path", surface="abuse/" + slug,
                checks=["blocked: findByIdAndCustomerId at src/api/Cards.java:88"],
                abuse={"actor": "customer", "asset": "card-pan", "goal": "read another customer's PAN"})
    base.update(fields)
    return base


def ledger_with(units, findings=(), profile="deep", abuse=True):
    """A ledger with the given units and findings; with abuse, also a threat model and three abuse paths."""
    data = {"repo": "cards", "source_ref": "abc123", "profile": profile, "scope": "repo",
            "units": list(units), "findings": list(findings)}
    if abuse:
        data["threat_model"] = copy.deepcopy(THREAT_MODEL)
        data["units"] += [abuse_unit("a"), abuse_unit("b"), abuse_unit("c")]
    return data


class AllowedAreasTest(unittest.TestCase):
    def test_reads_rule_stems_and_hunters(self):
        with tempfile.TemporaryDirectory() as tmp:
            for name in ("00-overview.md", "access-control.md", "notes.txt"):
                open(os.path.join(tmp, name), "w").close()
            self.assertEqual(ledger.allowed_areas(tmp),
                             {"access-control", "wildcard", "obvious-things", "sink-trace", "abuse-path"})

    def test_missing_dir_gives_method_areas_only(self):
        self.assertEqual(ledger.allowed_areas("/no/such/dir"), set(ledger.HUNTER_AREAS) | {"abuse-path"})

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

    def test_missing_threat_model(self):
        data = ledger_with([unit(area="wildcard")], abuse=False)
        self.assertIn("threat_model: missing", " ".join(ledger.validate(data, AREAS)))

    def test_too_few_abuse_paths(self):
        data = self.valid()
        data["units"] = [u for u in data["units"] if u["surface"] != "abuse/c"]
        self.assertIn("write at least 3", " ".join(ledger.validate(data, AREAS)))

    def test_valid_chain(self):
        data = self.valid()
        data["findings"] += [finding(key="leak", severity="warning"), finding(key="guess", severity="warning"),
                             finding(key="takeover", chain=["leak", "guess"])]
        data["units"][0]["finding_keys"] += ["leak", "guess", "takeover"]
        self.assertEqual(ledger.validate(data, AREAS), [])

    def test_chain_not_worse_than_links(self):
        data = self.valid()
        data["findings"] += [finding(key="leak", severity="warning"), finding(key="takeover", severity="critical",
                                                                             chain=["leak", "cards-idor"])]
        data["units"][0]["finding_keys"] += ["leak", "takeover"]
        self.assertIn("more severe than its worst link", " ".join(ledger.validate(data, AREAS)))

    def test_duplicate_unit(self):
        data = self.valid()
        data["units"].append(copy.deepcopy(data["units"][1]))
        self.assertIn("duplicate unit id", " ".join(ledger.validate(data, AREAS)))


class SummaryTest(unittest.TestCase):
    def test_counts(self):
        data = ledger_with([unit(status="finding", finding_keys=["cards-idor"]), unit(area="wildcard")], [finding()])
        self.assertEqual(ledger.summary(data),
                         {"units": {"finding": 1, "covered": 1}, "abuse_paths": {"covered": 3},
                          "findings": {"confirmed": 1}, "chains": 0, "root_causes": 1, "locations": 1})

    def test_counts_chains(self):
        findings = [finding(key="leak", severity="warning"), finding(key="guess", severity="warning"),
                    finding(key="takeover", chain=["leak", "guess"])]
        self.assertEqual(ledger.summary(ledger_with([], findings))["chains"], 1)

    def test_count_by(self):
        self.assertEqual(ledger.count_by([{"s": "a"}, {"s": "a"}, {"s": "b"}], "s"), {"a": 2, "b": 1})

    def test_root_causes_and_locations_skip_rejected(self):
        findings = [finding(paths=["a.ts", "b.ts", "c.ts"]),
                    finding(key="other", decision="rejected", severity=None, disproof="a.ts:1")]
        result = ledger.summary(ledger_with([], findings))
        self.assertEqual((result["root_causes"], result["locations"]), (1, 3))


def inventory_with(entries=(), sinks=(), source_ref="abc123"):
    return {"source_ref": source_ref, "entry_points": list(entries), "sinks": list(sinks)}


def entry(path="src/api/Cards.java", surface="src/api/Cards.java#GET /cards/{id}"):
    return {"path": path, "surface": surface, "line": 10, "kind": "route"}


def sink(path="src/api/Cards.java", area="access-control", kind="outbound-http"):
    return {"path": path, "area": area, "kind": kind, "line": 20}


class EntrySurfaceTest(unittest.TestCase):
    def test_standard_uses_module(self):
        self.assertEqual(ledger.entry_surface(entry(), "standard"), "src/api/Cards.java")

    def test_deep_uses_entry_surface(self):
        self.assertEqual(ledger.entry_surface(entry(), "deep"), "src/api/Cards.java#GET /cards/{id}")


class CheckInventoryRefTest(unittest.TestCase):
    def test_same_ref(self):
        self.assertEqual(ledger.check_inventory_ref(ledger_with([]), inventory_with()), [])

    def test_stale_inventory(self):
        self.assertTrue(ledger.check_inventory_ref(ledger_with([]), inventory_with(source_ref="old")))

    def test_inventory_without_ref(self):
        self.assertEqual(ledger.check_inventory_ref(ledger_with([]), inventory_with(source_ref=None)), [])


class CheckEntryCoverageTest(unittest.TestCase):
    def test_covered_deep_entry(self):
        self.assertEqual(ledger.check_entry_coverage(ledger_with([unit()]), inventory_with([entry()])), [])

    def test_missing_entry(self):
        errors = ledger.check_entry_coverage(ledger_with([]), inventory_with([entry()]))
        self.assertIn("src/api/Cards.java#GET /cards/{id}", errors[0])

    def test_planned_unit_does_not_count(self):
        planned = unit(status="planned", reviewed_paths=[], checks=[])
        self.assertTrue(ledger.check_entry_coverage(ledger_with([planned]), inventory_with([entry()])))

    def test_standard_module_unit(self):
        module_unit = unit(surface="src/api/Cards.java")
        data = ledger_with([module_unit], profile="standard")
        self.assertEqual(ledger.check_entry_coverage(data, inventory_with([entry()])), [])


class SinkReviewersTest(unittest.TestCase):
    def test_read_and_excused(self):
        units = [unit(), unit(status="not_applicable", area="injection-input", surface="src/x.py",
                              reviewed_paths=[], checks=[], unresolved=["no input"]),
                 unit(status="planned", area="client-side", reviewed_paths=[], checks=[])]
        read, excused = ledger.sink_reviewers(units)
        self.assertEqual(read, {"access-control": {"src/api/Cards.java"}})
        self.assertEqual(excused, {("src/x.py", "injection-input")})


class CheckSinkCoverageTest(unittest.TestCase):
    def test_read_under_matching_area(self):
        self.assertEqual(ledger.check_sink_coverage(ledger_with([unit()]), inventory_with(sinks=[sink()])), [])

    def test_read_under_other_area_fails(self):
        errors = ledger.check_sink_coverage(ledger_with([unit()]), inventory_with(sinks=[sink(area="injection-input")]))
        self.assertIn("src/api/Cards.java:20 (outbound-http) not read by any injection-input unit", errors[0])

    def test_excused_sink(self):
        excused = unit(status="out_of_scope", surface="src/api/Cards.java", reviewed_paths=[], checks=[],
                       unresolved=["user narrowed scope"])
        self.assertEqual(ledger.check_sink_coverage(ledger_with([excused]), inventory_with(sinks=[sink()])), [])


class CheckInventoryTest(unittest.TestCase):
    def test_combines_checks(self):
        errors = ledger.check_inventory(ledger_with([]), inventory_with([entry()], [sink()], source_ref="old"))
        self.assertEqual(len(errors), 3)


class ParseArgsTest(unittest.TestCase):
    def test_ledger_only(self):
        self.assertEqual(ledger.parse_args(["l.json"]),
                         {"ledger": "l.json", "inventory": None, "fail_on": None, "accepted": None, "sarif": None})

    def test_all_options_any_order(self):
        parsed = ledger.parse_args(["l.json", "--accepted", "a.json", "--fail-on", "bug", "--inventory", "i.json",
                                    "--sarif", "o.sarif"])
        self.assertEqual(parsed, {"ledger": "l.json", "inventory": "i.json", "fail_on": "bug", "accepted": "a.json",
                                  "sarif": "o.sarif"})

    def test_accepted_with_sarif_only(self):
        parsed = ledger.parse_args(["l.json", "--accepted", "a.json", "--sarif", "o.sarif"])
        self.assertEqual((parsed["accepted"], parsed["sarif"], parsed["fail_on"]), ("a.json", "o.sarif", None))

    def test_bad_usage(self):
        for args in ([], ["l.json", "--other", "x"], ["l.json", "--inventory"], ["l.json", "--fail-on", "high"],
                     ["l.json", "--inventory", "a", "--inventory", "b"], ["l.json", "--accepted", "a.json"]):
            self.assertIsNone(ledger.parse_args(args), args)


class GateSeverityTest(unittest.TestCase):
    def test_by_decision(self):
        self.assertEqual(ledger.gate_severity(finding()), "critical")
        nc = finding(decision="needs_confirmation", severity=None, severity_if_confirmed="bug")
        self.assertEqual(ledger.gate_severity(nc), "bug")
        rejected = finding(decision="rejected", severity=None, disproof="a.ts:1")
        self.assertIsNone(ledger.gate_severity(rejected))


class BlockingFindingsTest(unittest.TestCase):
    def setUp(self):
        self.data = ledger_with([], [
            finding(key="warn", decision="hardening", severity="warning"),
            finding(key="crit"),
            finding(key="nc", decision="needs_confirmation", severity=None, severity_if_confirmed="bug"),
            finding(key="rej", decision="rejected", severity=None, disproof="a.ts:1"),
        ])

    def test_threshold_critical(self):
        self.assertEqual([f["key"] for f in ledger.blocking_findings(self.data, "critical")], ["crit"])

    def test_threshold_bug_includes_needs_confirmation(self):
        self.assertEqual([f["key"] for f in ledger.blocking_findings(self.data, "bug")], ["crit", "nc"])

    def test_threshold_suggestion_skips_rejected(self):
        keys = [f["key"] for f in ledger.blocking_findings(self.data, "suggestion")]
        self.assertEqual(keys, ["crit", "nc", "warn"])


def acceptance(**fields):
    base = {"id": "accept-crit", "paths_any": ["src/api/Cards"], "text": "crit", "max_severity": "critical",
            "reason": "compensating control", "accepted_by": "security review", "expires": "2026-12-31"}
    base.update(fields)
    return base


class GateTest(unittest.TestCase):
    TODAY = datetime.date(2026, 10, 16)

    def setUp(self):
        self.data = ledger_with([], [finding(key="crit"),
                                     finding(key="nc", decision="needs_confirmation", severity=None,
                                             severity_if_confirmed="bug")])

    def test_finding_label(self):
        self.assertEqual(ledger.finding_label(finding()), "critical cards-idor (confirmed)")

    def test_format_gate(self):
        crit, nc = self.data["findings"]
        text = ledger.format_gate([(crit, None), (nc, "acceptance 'x' expired 2026-01-01")],
                                  [(crit, acceptance())], [acceptance(id="old")], "bug")
        self.assertEqual(text.splitlines(), [
            "FAIL critical crit (confirmed)",
            "FAIL bug nc (needs_confirmation): acceptance 'x' expired 2026-01-01",
            "ACCEPTED critical crit (confirmed): 'accept-crit' until 2026-12-31, compensating control",
            "UNUSED acceptance 'old': matches no reported finding",
            "Gate: 2 finding(s) at or above 'bug', 1 accepted",
        ])

    def test_run_gate_without_acceptances(self):
        code, text = ledger.run_gate(self.data, "bug", [], self.TODAY)
        self.assertEqual(code, 3)
        self.assertIn("Gate: 2 finding(s) at or above 'bug', 0 accepted", text)

    def test_run_gate_partly_accepted(self):
        code, text = ledger.run_gate(self.data, "bug", [acceptance()], self.TODAY)
        self.assertEqual(code, 3)
        self.assertIn("ACCEPTED critical crit", text)
        self.assertIn("FAIL bug nc", text)

    def test_run_gate_all_accepted_passes(self):
        code, text = ledger.run_gate(self.data, "critical", [acceptance()], self.TODAY)
        self.assertEqual(code, 0)
        self.assertIn("Gate: 0 finding(s) at or above 'critical', 1 accepted", text)

    def test_run_gate_expired_blocks(self):
        code, text = ledger.run_gate(self.data, "critical", [acceptance(expires="2026-10-01")], self.TODAY)
        self.assertEqual(code, 3)
        self.assertIn("expired 2026-10-01", text)

    def test_run_gate_lists_unused_and_ignores_rejected(self):
        data = ledger_with([], [finding(key="crit", decision="rejected", severity=None, disproof="a.ts:1")])
        code, text = ledger.run_gate(data, "critical", [acceptance()], self.TODAY)
        self.assertEqual(code, 0)
        self.assertIn("UNUSED acceptance 'accept-crit'", text)


class SarifLogTest(unittest.TestCase):
    TODAY = datetime.date(2026, 10, 16)

    def test_marks_waived_findings_suppressed(self):
        data = ledger_with([], [finding(key="crit"), finding(key="other", title="Other", severity="bug")])
        log = ledger.sarif_log(data, [acceptance()], self.TODAY)
        results = {r["ruleId"]: r for r in log["runs"][0]["results"]}
        self.assertEqual(results["crit"]["suppressions"][0]["status"], "accepted")
        self.assertNotIn("suppressions", results["other"])

    def test_expired_acceptance_not_suppressed(self):
        data = ledger_with([], [finding(key="crit")])
        log = ledger.sarif_log(data, [acceptance(expires="2026-01-01")], self.TODAY)
        self.assertNotIn("suppressions", log["runs"][0]["results"][0])


class LoadAcceptedTest(unittest.TestCase):
    def write(self, data):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(data, handle)
        handle.close()
        self.addCleanup(os.remove, handle.name)
        return handle.name

    def test_no_path(self):
        self.assertEqual(ledger.load_accepted(None), ([], []))

    def test_valid(self):
        self.assertEqual(ledger.load_accepted(self.write({"accepted": [acceptance()]})), ([acceptance()], []))

    def test_invalid(self):
        entries, errors = ledger.load_accepted(self.write({"accepted": [acceptance(expires="never")]}))
        self.assertEqual(entries, [])
        self.assertEqual(len(errors), 1)


class PrintErrorsTest(unittest.TestCase):
    def test_caps_output(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            ledger.print_errors(["e%d" % i for i in range(102)])
        self.assertIn("... and 2 more", out.getvalue())
        self.assertEqual(out.getvalue().count("ERROR "), 100)


class MainTest(unittest.TestCase):
    def write(self, data):
        handle = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
        json.dump(data, handle)
        handle.close()
        self.addCleanup(os.remove, handle.name)
        return handle.name

    def run_main(self, args):
        with contextlib.redirect_stdout(io.StringIO()):
            return ledger.main(args)

    def test_usage(self):
        self.assertEqual(self.run_main([]), 2)

    def test_inventory_gap_returns_1(self):
        data = ledger_with([unit(area="wildcard")])
        other = entry(surface="src/api/Cards.java#POST /cards")
        self.assertEqual(self.run_main([self.write(data), "--inventory", self.write(inventory_with([other]))]), 1)

    def gated(self):
        crit = unit(status="finding", finding_keys=["cards-idor"])
        return self.write(ledger_with([crit], [finding()]))

    def test_fail_on_blocking_returns_3(self):
        self.assertEqual(self.run_main([self.gated(), "--fail-on", "bug"]), 3)

    def test_fail_on_without_blocking_returns_0(self):
        data = ledger_with([unit(area="wildcard")])
        self.assertEqual(self.run_main([self.write(data), "--fail-on", "critical"]), 0)

    def test_accepted_finding_passes(self):
        accepted = {"accepted": [acceptance(text="cards-idor", expires="2999-12-31")]}
        self.assertEqual(self.run_main([self.gated(), "--fail-on", "bug", "--accepted", self.write(accepted)]), 0)

    def test_invalid_accepted_file_returns_1(self):
        accepted = {"accepted": [acceptance(max_severity="high")]}
        self.assertEqual(self.run_main([self.gated(), "--fail-on", "bug", "--accepted", self.write(accepted)]), 1)

    def test_sarif_written_without_changing_exit_code(self):
        out = os.path.join(tempfile.mkdtemp(), "nested", "out.sarif")
        self.addCleanup(shutil.rmtree, os.path.dirname(os.path.dirname(out)), ignore_errors=True)
        self.assertEqual(self.run_main([self.gated(), "--sarif", out]), 0)
        with open(out, encoding="utf-8") as handle:
            log = json.load(handle)
        self.assertEqual([r["ruleId"] for r in log["runs"][0]["results"]], ["cards-idor"])

    def test_sarif_not_written_for_invalid_ledger(self):
        out = os.path.join(tempfile.mkdtemp(), "out.sarif")
        self.addCleanup(shutil.rmtree, os.path.dirname(out), ignore_errors=True)
        self.assertEqual(self.run_main([self.write({"repo": "x"}), "--sarif", out]), 1)
        self.assertFalse(os.path.exists(out))

    def test_no_gate_ignores_findings(self):
        self.assertEqual(self.run_main([self.gated()]), 0)

    def test_inventory_covered_returns_0(self):
        data = ledger_with([unit()])
        inv = inventory_with([entry()], [sink()])
        self.assertEqual(self.run_main([self.write(data), "--inventory", self.write(inv)]), 0)

    def test_invalid_returns_1(self):
        self.assertEqual(self.run_main([self.write({"repo": "x"})]), 1)

    def test_valid_returns_0(self):
        data = ledger_with([unit(area="wildcard")])
        self.assertEqual(self.run_main([self.write(data)]), 0)


if __name__ == "__main__":
    unittest.main()
