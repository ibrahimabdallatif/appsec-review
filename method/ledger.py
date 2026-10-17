"""Coverage ledger validator for appsec-review.

Usage:
    python -I ledger.py <coverage-ledger.json> [--inventory <inventory.json>] [--sarif <out.sarif>]
                        [--fail-on <severity>] [--accepted <accepted-risks.json>]
                                                   validate and print a coverage summary
    python -I test_ledger.py                       run the unit tests

Exit codes: 0 valid (and, with --fail-on, no blocking finding), 1 invalid ledger, invalid accepted-risk file or
coverage gap, 2 bad usage, 3 valid but a reported finding is at or above the --fail-on severity (critical, bug,
warning or suggestion) and not waived by an accepted risk.

Every ledger also carries a threat model, abuse path units and, where findings combine, chained findings; their
rules are in threat_model.py.

With --inventory (written by inventory.py), every listed entry point must have a unit and every listed sink file
must have been read under the sink's category, so coverage no longer depends on what a run happened to notice.

--fail-on is a CI gate on the finished ledger: it never shortens a review. Confirmed and hardening findings count
by their severity, needs_confirmation findings by severity_if_confirmed, and rejected findings never count.
--accepted waives findings a team has accepted until an expiry date (see accepted_risks.py); waived findings
are still printed. It needs --fail-on or --sarif.

--sarif writes the reported findings of a valid ledger as SARIF 2.1.0 (see sarif.py), with accepted risks marked
as suppressed, for GitHub code scanning or Jenkins Warnings. It does not change the exit code.
"""
import datetime
import json
import os
import re
import sys

sys.dont_write_bytecode = True  # keep the skill folder free of __pycache__
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import accepted_risks  # noqa: E402
import sarif  # noqa: E402
import threat_model  # noqa: E402

SCOPES = ("diff", "repo", "endpoint", "files")
PROFILES = ("standard", "deep")
HUNTER_AREAS = ("wildcard", "obvious-things", "sink-trace")
DECISIONS = ("confirmed", "needs_confirmation", "rejected", "hardening")
SEVERITIES = ("critical", "bug", "warning", "suggestion")
HARDENING_SEVERITIES = ("warning", "suggestion")
NO_SEVERITY = ("needs_confirmation", "rejected")
REQUIRED_TOP = ("repo", "source_ref", "profile", "scope", "units", "findings")
REQUIRED_UNIT = ("id", "surface", "area", "status", "reviewed_paths", "checks", "finding_keys", "unresolved")
REQUIRED_FINDING = ("key", "title", "decision", "severity", "paths")

EVIDENCE_STATES = ("covered", "finding", "blocked")
EXCUSED_STATES = ("not_applicable", "out_of_scope")

# status -> (evidence required, finding keys required, unresolved required); None means "may be either"
STATES = {
    "planned": (False, False, False),
    "not_applicable": (False, False, True),
    "out_of_scope": (False, False, True),
    "deferred": (False, False, True),
    "covered": (True, False, False),
    "finding": (True, True, None),
    "blocked": (True, False, True),
}

DRIVE = re.compile(r"^[A-Za-z]:")
PATH_LINE = re.compile(r"[^\s:]+:\d+")
ID_LIKE = re.compile(r"^\s*[A-Za-z]{0,3}[-_ ]?\d+\s*$")
MIN_TITLE_WORDS = 3
RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules")


def allowed_areas(rules_dir=RULES_DIR):
    """Category file stems in rules/ (except the overview), the hunter areas and the abuse path area."""
    names = os.listdir(rules_dir) if os.path.isdir(rules_dir) else []
    stems = [n[:-3] for n in names if n.endswith(".md") and n != "00-overview.md"]
    return set(stems) | set(HUNTER_AREAS) | {threat_model.ABUSE_AREA}


def is_relative_path(path):
    """True for a repository-relative path with no traversal."""
    if not isinstance(path, str) or not path.strip():
        return False
    if path.startswith(("/", "\\")) or DRIVE.match(path):
        return False
    return ".." not in re.split(r"[\\/]", path)


def missing_keys(obj, required, label):
    return ["%s: missing '%s'" % (label, key) for key in required if key not in obj]


def check_top(ledger):
    errors = missing_keys(ledger, REQUIRED_TOP, "ledger")
    if ledger.get("scope") not in SCOPES:
        errors.append("ledger: scope must be one of %s" % ", ".join(SCOPES))
    if ledger.get("profile") not in PROFILES:
        errors.append("ledger: profile must be one of %s" % ", ".join(PROFILES))
    return errors


def check_granularity(unit, profile):
    """Standard ledgers use module-level surfaces: a path with no '#route' part."""
    if profile == "standard" and "#" in unit.get("surface", ""):
        return ["unit %s: standard profile surfaces are module paths without '#'" % unit.get("id")]
    return []


def check_unit_id(unit, areas):
    label = "unit %s" % unit.get("id")
    errors = []
    if unit.get("area") not in areas:
        errors.append("%s: unknown area '%s'" % (label, unit.get("area")))
    surface = unit.get("surface", "")
    if not surface.strip() or "::" in surface:
        errors.append("%s: surface must be non-empty and must not contain '::'" % label)
    if unit.get("id") != "%s::%s" % (surface, unit.get("area")):
        errors.append("%s: id must be '<surface>::<area>'" % label)
    return errors


def check_unit_state(unit):
    label = "unit %s" % unit.get("id")
    status = unit.get("status")
    if status not in STATES:
        return ["%s: unknown status '%s'" % (label, status)]
    needs_evidence, needs_keys, needs_unresolved = STATES[status]
    has_evidence = bool(unit["reviewed_paths"]) and bool(unit["checks"])
    has_any_evidence = bool(unit["reviewed_paths"]) or bool(unit["checks"])
    errors = []
    if needs_evidence and not has_evidence:
        errors.append("%s: '%s' needs reviewed_paths and checks" % (label, status))
    if not needs_evidence and has_any_evidence:
        errors.append("%s: '%s' must not carry reviewed_paths or checks" % (label, status))
    if bool(unit["finding_keys"]) != needs_keys:
        errors.append("%s: finding_keys %s for '%s'" % (label, "required" if needs_keys else "not allowed", status))
    if needs_unresolved is not None and bool(unit["unresolved"]) != needs_unresolved:
        errors.append("%s: unresolved %s for '%s'" % (label, "required" if needs_unresolved else "not allowed", status))
    return errors


def check_paths(paths, label):
    return ["%s: path '%s' must be repository-relative" % (label, p) for p in paths if not is_relative_path(p)]


def check_deferral(unit, stopped_early):
    """In-scope units may be deferred only when the user stopped the run, never to save time."""
    if unit.get("status") == "deferred" and not stopped_early:
        return ["unit %s: 'deferred' needs a run the user stopped (stopped_early: true); "
                "review it instead" % unit.get("id")]
    return []


def check_unit(unit, areas, profile="deep"):
    errors = missing_keys(unit, REQUIRED_UNIT, "unit %s" % unit.get("id"))
    if errors:
        return errors
    errors += check_unit_id(unit, areas)
    errors += check_granularity(unit, profile)
    errors += check_unit_state(unit)
    errors += check_paths(unit["reviewed_paths"], "unit %s" % unit["id"])
    return errors


def check_finding(finding):
    label = "finding %s" % finding.get("key")
    errors = missing_keys(finding, REQUIRED_FINDING, label)
    if errors:
        return errors
    decision, severity = finding["decision"], finding["severity"]
    if decision not in DECISIONS:
        errors.append("%s: unknown decision '%s'" % (label, decision))
    elif decision in NO_SEVERITY and severity is not None:
        errors.append("%s: '%s' must have severity null" % (label, decision))
    elif decision == "hardening" and severity not in HARDENING_SEVERITIES:
        errors.append("%s: hardening severity must be warning or suggestion" % label)
    elif decision == "confirmed" and severity not in SEVERITIES:
        errors.append("%s: confirmed needs a severity" % label)
    errors += check_title(finding, label)
    errors += check_rejection_proof(finding, label)
    errors += check_severity_if_confirmed(finding, label)
    errors += check_paths(finding["paths"], label)
    return errors


def check_title(finding, label):
    """Titles name the weakness for people reading results, SARIF and reports: never a candidate id like 'C9'."""
    title = finding.get("title")
    if not isinstance(title, str) or ID_LIKE.match(title) or len(title.split()) < MIN_TITLE_WORDS:
        return ["%s: title must name the weakness in at least %d words, not an id" % (label, MIN_TITLE_WORDS)]
    return []


def check_rejection_proof(finding, label):
    """A rejection must cite the path:line of the control that disproves the candidate."""
    disproof = finding.get("disproof")
    if finding.get("decision") == "rejected":
        if not isinstance(disproof, str) or not PATH_LINE.search(disproof):
            return ["%s: rejected needs a 'disproof' citing path:line" % label]
    elif disproof:
        return ["%s: only rejected findings carry 'disproof'" % label]
    return []


def check_severity_if_confirmed(finding, label):
    """needs_confirmation findings carry the severity they have if the missing fact is unsafe."""
    value = finding.get("severity_if_confirmed")
    if finding.get("decision") == "needs_confirmation":
        if value not in SEVERITIES:
            return ["%s: needs_confirmation needs severity_if_confirmed" % label]
    elif value is not None:
        return ["%s: only needs_confirmation findings carry severity_if_confirmed" % label]
    return []


def duplicates(values):
    seen, dups = set(), set()
    for value in values:
        (dups if value in seen else seen).add(value)
    return sorted(dups, key=str)


def check_links(units, findings):
    by_key = {f.get("key"): f for f in findings}
    linked = set()
    errors = []
    for unit in units:
        keys = unit.get("finding_keys") or []
        linked.update(keys)
        errors += ["unit %s: unknown finding key '%s'" % (unit.get("id"), k) for k in keys if k not in by_key]
        live = [k for k in keys if k in by_key and by_key[k].get("decision") != "rejected"]
        if unit.get("status") == "finding" and keys and not live:
            errors.append("unit %s: every linked finding is rejected; mark the unit covered" % unit.get("id"))
    errors += ["finding %s: not linked from any unit" % k for k in by_key if k not in linked]
    return errors


def validate(ledger, areas=None):
    """Return a list of error strings; empty means the ledger is valid."""
    if not isinstance(ledger, dict):
        return ["ledger: top level must be an object"]
    errors = check_top(ledger)
    if errors:
        return errors
    areas = areas if areas is not None else allowed_areas()
    units, findings = ledger["units"], ledger["findings"]
    errors += ["duplicate unit id '%s'" % d for d in duplicates(u.get("id") for u in units)]
    errors += ["duplicate finding key '%s'" % d for d in duplicates(f.get("key") for f in findings)]
    for unit in units:
        errors += check_unit(unit, areas, ledger["profile"])
        errors += check_deferral(unit, ledger.get("stopped_early") is True)
    for finding in findings:
        errors += check_finding(finding)
    errors += threat_model.check_abuse(ledger)
    errors += threat_model.check_chains(findings, gate_severity)
    return errors + check_links(units, findings)


def count_by(items, field):
    counts = {}
    for item in items:
        counts[item[field]] = counts.get(item[field], 0) + 1
    return counts


def summary(ledger):
    """Counts of coverage units and abuse paths per status, findings per decision, reported chains, root causes
    and locations."""
    abuse = threat_model.abuse_units(ledger["units"])
    units = [u for u in ledger["units"] if u.get("area") != threat_model.ABUSE_AREA]
    reported = [f for f in ledger["findings"] if f["decision"] != "rejected"]
    return {"units": count_by(units, "status"), "abuse_paths": count_by(abuse, "status"),
            "findings": count_by(ledger["findings"], "decision"),
            "chains": sum(1 for f in reported if "chain" in f),
            "root_causes": len(reported), "locations": sum(len(f["paths"]) for f in reported)}


def entry_surface(entry, profile):
    """The ledger surface an inventory entry point needs: its module in standard, its own surface in deep."""
    return entry["path"] if profile == "standard" else entry["surface"]


def check_inventory_ref(ledger, inventory):
    ref = inventory.get("source_ref")
    if ref and ref != ledger.get("source_ref"):
        return ["inventory: built at %s but the ledger is at %s; re-run inventory.py"
                % (ref, ledger.get("source_ref"))]
    return []


def check_entry_coverage(ledger, inventory):
    """Every inventory entry point has a unit that is no longer planned."""
    done = {u.get("surface") for u in ledger["units"] if u.get("status") != "planned"}
    needed = sorted({entry_surface(e, ledger["profile"]) for e in inventory.get("entry_points", [])})
    return ["inventory: entry point '%s' has no unit beyond planned" % s for s in needed if s not in done]


def sink_reviewers(units):
    """(area -> paths read under that area, (surface, area) pairs excused as not applicable or out of scope)."""
    read, excused = {}, set()
    for unit in units:
        if unit.get("status") in EVIDENCE_STATES:
            read.setdefault(unit.get("area"), set()).update(unit.get("reviewed_paths") or [])
        elif unit.get("status") in EXCUSED_STATES:
            excused.add((unit.get("surface"), unit.get("area")))
    return read, excused


def check_sink_coverage(ledger, inventory):
    """Every inventory sink file was read by a unit of the sink's category, or excused for that category."""
    read, excused = sink_reviewers(ledger["units"])
    errors = []
    for sink in inventory.get("sinks", []):
        path, area = sink["path"], sink["area"]
        if path not in read.get(area, set()) and (path, area) not in excused:
            errors.append("inventory: sink %s:%s (%s) not read by any %s unit"
                          % (path, sink["line"], sink["kind"], area))
    return errors


def check_inventory(ledger, inventory):
    """Errors for inventory entry points and sinks the ledger does not cover."""
    return (check_inventory_ref(ledger, inventory) + check_entry_coverage(ledger, inventory)
            + check_sink_coverage(ledger, inventory))


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def gate_severity(finding):
    """Severity a finding has for the --fail-on gate; None for rejected findings."""
    if finding.get("decision") == "needs_confirmation":
        return finding.get("severity_if_confirmed")
    return None if finding.get("decision") == "rejected" else finding.get("severity")


def blocking_findings(ledger, threshold):
    """Reported findings at or above the threshold severity, most severe first."""
    rank = {s: i for i, s in enumerate(SEVERITIES)}
    hits = [f for f in ledger["findings"] if rank.get(gate_severity(f), len(SEVERITIES)) <= rank[threshold]]
    return sorted(hits, key=lambda f: rank[gate_severity(f)])


def finding_label(finding):
    return "%s %s (%s)" % (gate_severity(finding), finding["key"], finding["decision"])


def format_gate(still, waived, unused, threshold):
    """Gate output: blocking findings with the reason an acceptance did not apply, waived ones, unused entries."""
    lines = ["FAIL " + finding_label(f) + (": " + note if note else "") for f, note in still]
    lines += ["ACCEPTED %s: '%s' until %s, %s" % (finding_label(f), e["id"], e["expires"], e["reason"])
              for f, e in waived]
    lines += ["UNUSED acceptance '%s': matches no reported finding" % e["id"] for e in unused]
    lines.append("Gate: %d finding(s) at or above '%s', %d accepted" % (len(still), threshold, len(waived)))
    return "\n".join(lines)


def run_gate(ledger, threshold, entries, today):
    """(exit code, gate output) for the reported findings against the threshold and accepted risks."""
    blocking = blocking_findings(ledger, threshold)
    still, waived = accepted_risks.apply(blocking, entries, gate_severity, today)
    reported = [f for f in ledger["findings"] if f["decision"] != "rejected"]
    text = format_gate(still, waived, accepted_risks.unused(entries, reported), threshold)
    return (3 if still else 0), text


def load_accepted(path):
    """(entries, errors) from an accepted-risk file; no path means no entries."""
    if path is None:
        return [], []
    doc = load_json(path)
    errors = accepted_risks.check_accepted(doc)
    return ([] if errors else doc["accepted"]), errors


def sarif_log(ledger, entries, today):
    """SARIF for the ledger's reported findings, with currently waived ones marked as suppressed."""
    def waiver_for(finding, severity):
        return accepted_risks.waiver_for(finding, severity, entries, today)
    return sarif.to_sarif(ledger, gate_severity, waiver_for)


def write_sarif(path, ledger, entries, today):
    folder = os.path.dirname(os.path.abspath(path))
    os.makedirs(folder, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(sarif_log(ledger, entries, today), handle, indent=1)
    print("SARIF written to %s" % path)


def parse_args(args):
    """{'ledger', 'inventory', 'fail_on', 'accepted', 'sarif'} from the command line, or None for bad usage."""
    if not args:
        return None
    parsed = {"ledger": args[0], "inventory": None, "fail_on": None, "accepted": None, "sarif": None}
    options = {"--inventory": "inventory", "--fail-on": "fail_on", "--accepted": "accepted", "--sarif": "sarif"}
    rest = args[1:]
    if len(rest) % 2:
        return None
    for flag, value in zip(rest[::2], rest[1::2]):
        if flag not in options or parsed[options[flag]] is not None:
            return None
        parsed[options[flag]] = value
    if parsed["fail_on"] is not None and parsed["fail_on"] not in SEVERITIES:
        return None
    if parsed["accepted"] is not None and parsed["fail_on"] is None and parsed["sarif"] is None:
        return None
    return parsed


def print_errors(errors):
    for error in errors[:100]:
        print("ERROR " + error)
    if len(errors) > 100:
        print("... and %d more" % (len(errors) - 100))


def main(args):
    parsed = parse_args(args)
    if parsed is None:
        print(__doc__)
        return 2
    ledger = load_json(parsed["ledger"])
    errors = validate(ledger)
    if not errors and parsed["inventory"]:
        errors = check_inventory(ledger, load_json(parsed["inventory"]))
    entries, accepted_errors = load_accepted(parsed["accepted"])
    errors += accepted_errors
    print_errors(errors)
    if errors:
        return 1
    print(json.dumps(summary(ledger), indent=2, sort_keys=True))
    today = datetime.date.today()
    if parsed["sarif"]:
        write_sarif(parsed["sarif"], ledger, entries, today)
    if parsed["fail_on"] is None:
        return 0
    code, text = run_gate(ledger, parsed["fail_on"], entries, today)
    print(text)
    return code


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
