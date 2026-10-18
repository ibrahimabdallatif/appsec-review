"""Benchmark scorer for appsec-review: compares a run's coverage ledger with known findings.

Usage:
    python -I benchmark.py <benchmark.json> <coverage-ledger.json>
    python -I benchmark.py <benchmark.json> <run-1.json> <run-2.json> ...    stability across fresh runs
    python -I test_benchmark.py                     run the unit tests

A benchmark lists the findings a review of one repository at one commit must find. Each expected finding has
an id, a minimum severity, and a matcher: substrings for its file paths and a regex for its key and title.
The scorer reports which expected findings the run found, missed or downgraded, and its extra findings.

A benchmark can also list decoys under "absent": code that looks vulnerable but is safe, with the same matcher
(id, paths_any, text). A reported finding that matches a decoy is a false positive; a rejected one is correct.
The scorer prints the false positives and the precision over the labelled findings (expected and decoys).

Given several ledgers from fresh runs of the same commit, it reports how often each expected finding was found
(STABLE in every run, FLAKY in some, LOST in none) and which extra findings only some runs produced. A flaky
finding points at the rule, prompt or inventory pattern that needs work. Each decoy that any run reported is
listed with the number of runs that reported it.
"""
import json
import re
import sys

SEVERITY_ORDER = ("suggestion", "warning", "bug", "critical")
REQUIRED_EXPECTED = ("id", "min_severity", "paths_any", "text")
REQUIRED_ABSENT = ("id", "paths_any", "text")


def load_json(path):
    with open(path, encoding="utf-8") as handle:
        return json.load(handle)


def severity_rank(severity):
    """0 (suggestion) to 3 (critical); -1 for none or unknown."""
    return SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else -1


def check_matcher(item, label, required):
    """Missing keys and a bad text regex for one expected finding or decoy."""
    errors = ["%s: missing '%s'" % (label, key) for key in required if key not in item]
    try:
        re.compile(item.get("text", ""))
    except re.error as exc:
        errors.append("%s: bad regex (%s)" % (label, exc))
    return errors


def check_expected(item):
    label = "expected %s" % item.get("id")
    errors = check_matcher(item, label, REQUIRED_EXPECTED)
    if item.get("min_severity") not in SEVERITY_ORDER:
        errors.append("%s: min_severity must be one of %s" % (label, ", ".join(SEVERITY_ORDER)))
    return errors


def check_benchmark(benchmark):
    """Error strings for a malformed benchmark; empty when valid."""
    errors = []
    for item in benchmark.get("expected", []):
        errors += check_expected(item)
    for item in benchmark.get("absent", []):
        errors += check_matcher(item, "absent %s" % item.get("id"), REQUIRED_ABSENT)
    if not benchmark.get("expected"):
        errors.append("benchmark: 'expected' is empty")
    return errors


def finding_text(finding):
    return "%s %s" % (finding.get("key", ""), finding.get("title", ""))


def matches(expected, finding):
    """True when one of the finding's paths contains a listed substring and its key or title matches."""
    paths = finding.get("paths") or []
    path_hit = any(part in path for part in expected["paths_any"] for path in paths)
    return path_hit and re.search(expected["text"], finding_text(finding), re.IGNORECASE) is not None


def effective(finding):
    """(severity, decision) as the run reported it; needs_confirmation uses severity_if_confirmed."""
    decision = finding.get("decision")
    if decision == "needs_confirmation":
        return finding.get("severity_if_confirmed"), decision
    return finding.get("severity"), decision


def candidate_rank(finding):
    """Order matches: reported beats rejected, confirmed beats needs_confirmation, then severity."""
    severity, decision = effective(finding)
    reported = decision != "rejected"
    return (reported, decision == "confirmed", severity_rank(severity))


def classify(expected, best):
    """found, downgraded, needs_confirmation, rejected or missed."""
    if best is None:
        return "missed"
    severity, decision = effective(best)
    if decision == "rejected":
        return "rejected"
    if severity_rank(severity) < severity_rank(expected["min_severity"]):
        return "downgraded"
    if decision == "needs_confirmation" and expected.get("expect_confirmed", False):
        return "needs_confirmation"
    return "found"


def is_reported(finding):
    return finding.get("decision") != "rejected"


def classify_decoy(hits):
    """reported (a false positive), rejected (verification caught it) or clean (never raised)."""
    if any(is_reported(f) for f in hits):
        return "reported"
    return "rejected" if hits else "clean"


def score_decoys(benchmark, findings, used):
    """Per-decoy results; marks every matching finding as used so it is not listed as an extra."""
    decoys = []
    for absent in benchmark.get("absent", []):
        hits = [f for f in findings if matches(absent, f)]
        used.update(id(f) for f in hits)
        reported = [f.get("key") for f in hits if is_reported(f)]
        decoys.append({"id": absent["id"], "status": classify_decoy(hits), "matched": reported})
    return decoys


def score(benchmark, ledger):
    """Per-expected results, per-decoy results, and extra findings that match nothing."""
    findings = ledger.get("findings", [])
    results, used = [], set()
    for expected in benchmark["expected"]:
        hits = [f for f in findings if matches(expected, f)]
        best = max(hits, key=candidate_rank) if hits else None
        used.update(id(f) for f in hits)
        results.append({"id": expected["id"], "status": classify(expected, best),
                        "min_severity": expected["min_severity"],
                        "human_confirmed": expected.get("human_confirmed", False),
                        "matched": best.get("key") if best else None,
                        "severity": effective(best)[0] if best else None,
                        "decision": effective(best)[1] if best else None})
    decoys = score_decoys(benchmark, findings, used)
    extras = [f.get("key") for f in findings if id(f) not in used and is_reported(f)]
    return {"results": results, "decoys": decoys, "extras": extras}


def recall(results, only_confirmed=False):
    """(found, total) where 'found' counts found and needs_confirmation at or above the floor."""
    pool = [r for r in results if r["human_confirmed"]] if only_confirmed else results
    found = sum(1 for r in pool if r["status"] in ("found", "needs_confirmation"))
    return found, len(pool)


def false_positives(scored):
    return [d for d in scored.get("decoys", []) if d["status"] == "reported"]


def precision(scored):
    """(true, reported) over labelled findings: expected ones reported at any severity, plus reported decoys."""
    true = sum(1 for r in scored["results"] if r["status"] in ("found", "needs_confirmation", "downgraded"))
    return true, true + len(false_positives(scored))


def format_decoys(scored):
    decoys = scored.get("decoys", [])
    if not decoys:
        return []
    lines = []
    for d in decoys:
        detail = " <- %s" % ", ".join(d["matched"]) if d["matched"] else ""
        status = "FALSE-POSITIVE" if d["status"] == "reported" else d["status"].upper()
        lines.append("%-18s %-26s decoy%s" % (status, d["id"], detail))
    true, reported = precision(scored)
    lines.append("False positives: %d/%d decoys reported" % (len(false_positives(scored)), len(decoys)))
    lines.append("Precision on labelled findings: %d/%d" % (true, reported))
    return lines


def format_report(scored):
    lines = []
    for r in scored["results"]:
        detail = "" if r["matched"] is None else " <- %s (%s, %s)" % (r["matched"], r["decision"], r["severity"])
        lines.append("%-18s %-26s min %-10s%s" % (r["status"].upper(), r["id"], r["min_severity"], detail))
    found, total = recall(scored["results"])
    lines.append("Recall: %d/%d expected findings" % (found, total))
    h_found, h_total = recall(scored["results"], only_confirmed=True)
    if h_total:
        lines.append("Recall on human-confirmed findings: %d/%d" % (h_found, h_total))
    lines += format_decoys(scored)
    lines.append("Extra findings not in the benchmark (%d): %s" % (len(scored["extras"]), ", ".join(scored["extras"])))
    return "\n".join(lines)


def is_hit(result):
    return result["status"] in ("found", "needs_confirmation")


def hit_counts(scored_runs):
    """Per expected id: runs that found it, and how often each status occurred."""
    counts = {}
    for scored in scored_runs:
        for r in scored["results"]:
            entry = counts.setdefault(r["id"], {"hits": 0, "statuses": {}, "min_severity": r["min_severity"]})
            entry["hits"] += 1 if is_hit(r) else 0
            entry["statuses"][r["status"]] = entry["statuses"].get(r["status"], 0) + 1
    return counts


def extra_counts(scored_runs):
    """Per extra finding key: the number of runs that reported it."""
    counts = {}
    for scored in scored_runs:
        for key in set(scored["extras"]):
            counts[key] = counts.get(key, 0) + 1
    return counts


def decoy_counts(scored_runs):
    """Per decoy id: the number of runs that reported it as a finding."""
    counts = {}
    for scored in scored_runs:
        for d in scored.get("decoys", []):
            counts[d["id"]] = counts.get(d["id"], 0) + (1 if d["status"] == "reported" else 0)
    return counts


def format_decoy_stability(scored_runs):
    counts = decoy_counts(scored_runs)
    if not counts:
        return []
    runs = len(scored_runs)
    lines = ["FALSE-POSITIVE %-26s %d/%d runs" % (id_, n, runs) for id_, n in counts.items() if n]
    lines.append("Decoys never reported: %d/%d" % (sum(1 for n in counts.values() if not n), len(counts)))
    return lines


def stability_label(hits, runs):
    if hits == runs:
        return "STABLE"
    return "LOST" if hits == 0 else "FLAKY"


def misses_text(statuses):
    misses = ["%s %d" % (status, n) for status, n in sorted(statuses.items()) if status not in ("found",
              "needs_confirmation")]
    return " (%s)" % ", ".join(misses) if misses else ""


def format_stability(scored_runs):
    runs = len(scored_runs)
    counts = hit_counts(scored_runs)
    lines = ["%-7s %-26s %d/%d runs%s" % (stability_label(c["hits"], runs), id_, c["hits"], runs,
                                           misses_text(c["statuses"])) for id_, c in counts.items()]
    stable = sum(1 for c in counts.values() if c["hits"] == runs)
    mean = sum(recall(s["results"])[0] for s in scored_runs) / float(runs)
    lines.append("Found in every run: %d/%d expected findings" % (stable, len(counts)))
    lines.append("Mean recall per run: %.1f/%d" % (mean, len(counts)))
    lines += format_decoy_stability(scored_runs)
    partial = sorted((k, n) for k, n in extra_counts(scored_runs).items() if n < runs)
    lines.append("Extras reported by some runs only (%d): %s"
                 % (len(partial), ", ".join("%s %d/%d" % (k, n, runs) for k, n in partial)))
    return "\n".join(lines)


def run_single(benchmark, ledger):
    scored = score(benchmark, ledger)
    print(format_report(scored))
    missed = [r for r in scored["results"] if r["status"] in ("missed", "rejected", "downgraded")]
    return 1 if missed or false_positives(scored) else 0


def run_many(benchmark, ledgers):
    scored_runs = [score(benchmark, ledger) for ledger in ledgers]
    print(format_stability(scored_runs))
    unstable = [c for c in hit_counts(scored_runs).values() if c["hits"] < len(ledgers)]
    noisy = [n for n in decoy_counts(scored_runs).values() if n]
    return 1 if unstable or noisy else 0


def main(args):
    if len(args) < 2:
        print(__doc__)
        return 2
    benchmark = load_json(args[0])
    errors = check_benchmark(benchmark)
    for error in errors:
        print("ERROR " + error)
    if errors:
        return 2
    ledgers = [load_json(path) for path in args[1:]]
    return run_single(benchmark, ledgers[0]) if len(ledgers) == 1 else run_many(benchmark, ledgers)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
