"""Unit tests for threat_model.py. Run: python -I test_threat_model.py"""
import copy
import os
import sys
import unittest

sys.dont_write_bytecode = True  # keep the skill folder free of __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import threat_model as tm  # noqa: E402

MODEL = {"assets": [{"id": "card-pan", "what": "card numbers"}, {"id": "wallet", "what": "wallet balances"}],
         "actors": ["customer", "anonymous"], "boundaries": ["browser -> API", "API -> card vault"]}


def abuse_unit(slug="a", asset="card-pan", actor="customer", status="covered", checks=None, **fields):
    base = {"id": "abuse/%s::abuse-path" % slug, "surface": "abuse/" + slug, "area": "abuse-path",
            "status": status, "checks": ["blocked at src/Cards.java:88"] if checks is None else checks,
            "abuse": {"actor": actor, "asset": asset, "goal": "steal it"}}
    base.update(fields)
    return base


def ledger(units=None, model=MODEL):
    units = [abuse_unit("a"), abuse_unit("b"), abuse_unit("c", asset="wallet")] if units is None else units
    return {"threat_model": copy.deepcopy(model), "units": units}


def finding(key, decision="confirmed", severity="warning", **fields):
    base = {"key": key, "decision": decision, "severity": severity}
    base.update(fields)
    return base


def severity_of(item):
    if item["decision"] == "needs_confirmation":
        return item["severity_if_confirmed"]
    return None if item["decision"] == "rejected" else item["severity"]


class HelpersTest(unittest.TestCase):
    def test_is_text(self):
        self.assertTrue(tm.is_text("a"))
        for value in ("", "  ", None, 1):
            self.assertFalse(tm.is_text(value), value)

    def test_is_text_list(self):
        self.assertTrue(tm.is_text_list(["a"]))
        for value in ([], ["a", ""], "a", None):
            self.assertFalse(tm.is_text_list(value), value)

    def test_duplicates(self):
        self.assertEqual(tm.duplicates(["a", "b", "a"]), ["a"])

    def test_rank(self):
        self.assertLess(tm.rank("critical"), tm.rank("bug"))
        self.assertEqual(tm.rank(None), len(tm.SEVERITIES))

    def test_asset_ids_and_abuse_units(self):
        self.assertEqual(tm.asset_ids(MODEL), ["card-pan", "wallet"])
        units = [abuse_unit(), {"area": "access-control"}]
        self.assertEqual(tm.abuse_units(units), [units[0]])


class CheckModelTest(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(tm.check_model(MODEL), [])

    def test_missing(self):
        self.assertIn("missing", tm.check_model(None)[0])

    def test_no_assets(self):
        self.assertEqual(tm.check_model(dict(MODEL, assets=[])), ["threat_model: assets must be a non-empty list"])

    def test_bad_asset_and_lists(self):
        errors = tm.check_model({"assets": [{"id": "x"}], "actors": [], "boundaries": "browser"})
        self.assertEqual(errors, ["threat_model: every asset needs 'id' and 'what'",
                                  "threat_model: actors must be a non-empty list of strings",
                                  "threat_model: boundaries must be a non-empty list of strings"])

    def test_duplicate_asset(self):
        model = dict(MODEL, assets=[{"id": "a", "what": "x"}, {"id": "a", "what": "y"}])
        self.assertEqual(tm.check_model(model), ["threat_model: duplicate asset id 'a'"])


class CheckAbuseUnitTest(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(tm.check_abuse_unit(abuse_unit(), MODEL), [])

    def test_surface_prefix(self):
        errors = tm.check_abuse_unit(abuse_unit(surface="steal-pan"), MODEL)
        self.assertIn("start with 'abuse/'", errors[0])

    def test_missing_abuse_object(self):
        errors = tm.check_abuse_unit(abuse_unit(abuse={"actor": "customer"}), MODEL)
        self.assertEqual(errors, ["unit abuse/a::abuse-path: abuse paths need 'abuse' with actor, asset and goal"])

    def test_unknown_actor_and_asset(self):
        errors = tm.check_abuse_fields(abuse_unit(actor="martian", asset="gold"), MODEL)
        self.assertEqual(len(errors), 2)
        self.assertIn("actor 'martian'", errors[0])
        self.assertIn("asset 'gold'", errors[1])

    def test_blocked_needs_control_line(self):
        errors = tm.check_abuse_unit(abuse_unit(checks=["looked fine"]), MODEL)
        self.assertIn("path:line of the control", errors[0])

    def test_realised_needs_no_control_line(self):
        self.assertEqual(tm.check_abuse_unit(abuse_unit(status="finding", checks=["reached"]), MODEL), [])


class CheckAbuseCoverageTest(unittest.TestCase):
    def test_enough_and_every_asset(self):
        self.assertEqual(tm.check_abuse_coverage(ledger()["units"], MODEL), [])

    def test_too_few(self):
        errors = tm.check_abuse_coverage([abuse_unit("a"), abuse_unit("b", asset="wallet")], MODEL)
        self.assertEqual(errors, ["threat_model: 2 abuse path unit(s); write at least 3"])

    def test_asset_without_path(self):
        errors = tm.check_abuse_coverage([abuse_unit("a"), abuse_unit("b"), abuse_unit("c")], MODEL)
        self.assertEqual(errors, ["threat_model: asset 'wallet' has no abuse path"])


class CheckAbuseTest(unittest.TestCase):
    def test_valid(self):
        self.assertEqual(tm.check_abuse(ledger()), [])

    def test_model_errors_stop_unit_checks(self):
        data = ledger(model={"assets": []})
        self.assertEqual(tm.check_abuse(data), ["threat_model: assets must be a non-empty list"])

    def test_unit_and_coverage_errors(self):
        data = ledger([abuse_unit("a", checks=["fine"]), abuse_unit("b")])
        errors = tm.check_abuse(data)
        self.assertEqual(len(errors), 3)


class CheckChainsTest(unittest.TestCase):
    def findings(self, *extra):
        return [finding("leak"), finding("guess"), finding("unsure", decision="needs_confirmation", severity=None,
                                                           severity_if_confirmed="warning"),
                finding("gone", decision="rejected", severity=None)] + list(extra)

    def errors(self, chain):
        return tm.check_chains(self.findings(chain), severity_of)

    def test_valid(self):
        self.assertEqual(self.errors(finding("takeover", severity="critical", chain=["leak", "guess"])), [])

    def test_findings_without_chain_ignored(self):
        self.assertEqual(tm.check_chains(self.findings(), severity_of), [])

    def test_too_short(self):
        self.assertIn("at least two", self.errors(finding("c", severity="bug", chain=["leak"]))[0])
        self.assertIn("at least two", self.errors(finding("c", severity="bug", chain="leak,guess"))[0])

    def test_bad_links(self):
        chain = finding("c", severity="bug", chain=["leak", "leak", "c", "nope", "gone"])
        self.assertEqual(self.errors(chain), [
            "finding c: chain lists 'leak' twice",
            "finding c: chain must not include itself",
            "finding c: chain link 'nope' is not a finding",
            "finding c: chain link 'gone' was rejected",
        ])

    def test_nested_chain(self):
        inner = finding("inner", severity="bug", chain=["leak", "guess"])
        outer = finding("outer", severity="critical", chain=["inner", "leak"])
        errors = tm.check_chains(self.findings(inner, outer), severity_of)
        self.assertEqual(errors, ["finding outer: chain link 'inner' is itself a chain; list its links instead"])

    def test_unconfirmed_link(self):
        chain = finding("c", severity="critical", chain=["leak", "unsure"])
        self.assertEqual(self.errors(chain), ["finding c: a chain with an unconfirmed link is needs_confirmation"])
        unsure = finding("c", decision="needs_confirmation", severity=None, severity_if_confirmed="critical",
                         chain=["leak", "unsure"])
        self.assertEqual(self.errors(unsure), [])

    def test_must_be_worse_than_worst_link(self):
        chain = finding("c", severity="warning", chain=["leak", "guess"])
        self.assertIn("more severe than its worst link (warning)", self.errors(chain)[0])

    def test_rejected_chain_skips_verdict(self):
        chain = finding("c", decision="rejected", severity=None, chain=["leak", "guess"])
        self.assertEqual(self.errors(chain), [])


if __name__ == "__main__":
    unittest.main()
