"""Coverage ledger validator for appsec-review.

Usage:
    python -I ledger.py <coverage-ledger.json>     validate and print a coverage summary
    python -I test_ledger.py                       run the unit tests
"""
import json
import os
import re
import sys

SCOPES = ("diff", "repo", "endpoint", "files")
PROFILES = ("standard", "deep")
HUNTER_AREAS = ("wildcard", "obvious-things")
DECISIONS = ("confirmed", "needs_confirmation", "rejected", "hardening")
SEVERITIES = ("critical", "bug", "warning", "suggestion")
HARDENING_SEVERITIES = ("warning", "suggestion")
NO_SEVERITY = ("needs_confirmation", "rejected")
REQUIRED_TOP = ("repo", "source_ref", "profile", "scope", "units", "findings")
REQUIRED_UNIT = ("id", "surface", "area", "status", "reviewed_paths", "checks", "finding_keys", "unresolved")
REQUIRED_FINDING = ("key", "title", "decision", "severity", "paths")

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
RULES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "rules")


def allowed_areas(rules_dir=RULES_DIR):
    """Category file stems in rules/ (except the overview) plus the two hunters."""
    names = os.listdir(rules_dir) if os.path.isdir(rules_dir) else []
    stems = [n[:-3] for n in names if n.endswith(".md") and n != "00-overview.md"]
    return set(stems) | set(HUNTER_AREAS)


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
    errors += check_rejection_proof(finding, label)
    errors += check_severity_if_confirmed(finding, label)
    errors += check_paths(finding["paths"], label)
    return errors


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
    return errors + check_links(units, findings)


def summary(ledger):
    """Counts of units per status, findings per decision, and reported root causes and locations."""
    units = {}
    for unit in ledger["units"]:
        units[unit["status"]] = units.get(unit["status"], 0) + 1
    findings = {}
    for finding in ledger["findings"]:
        findings[finding["decision"]] = findings.get(finding["decision"], 0) + 1
    reported = [f for f in ledger["findings"] if f["decision"] != "rejected"]
    locations = sum(len(f["paths"]) for f in reported)
    return {"units": units, "findings": findings, "root_causes": len(reported), "locations": locations}


def main(args):
    if len(args) != 1:
        print(__doc__)
        return 2
    with open(args[0], encoding="utf-8") as handle:
        ledger = json.load(handle)
    errors = validate(ledger)
    for error in errors[:100]:
        print("ERROR " + error)
    if errors:
        return 1
    print(json.dumps(summary(ledger), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
