"""SARIF 2.1.0 export of a coverage ledger, for GitHub code scanning, Jenkins Warnings and other SARIF viewers.

Each reported finding becomes one result per path, so every affected location is annotated. Rejected findings are
left out. Results carry the finding key as their rule id and as a partial fingerprint, so a viewer tracks the same
alert across runs even when line numbers move. Messages hold only the title and decision, never attack steps:
SARIF often ends up in places with wider access than the ledger.
"""
import re

TOOL_URI = "https://github.com/ibrahimabdallatif/appsec-review"
SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVELS = {"critical": "error", "bug": "error", "warning": "warning", "suggestion": "note"}
# GitHub code scanning reads 'security-severity' (0-10) to label alerts critical, high, medium or low.
SECURITY_SEVERITY = {"critical": "9.5", "bug": "7.5", "warning": "5.0", "suggestion": "2.0"}
LOCATION = re.compile(r"^(?P<path>.+?):(?P<start>\d+)(?:-(?P<end>\d+))?$")


def split_location(text):
    """(path, start line or None, end line or None) from 'path', 'path:12' or 'path:12-20'."""
    match = LOCATION.match(text)
    if not match:
        return text, None, None
    end = match.group("end")
    return match.group("path"), int(match.group("start")), int(end) if end else None


def region(start, end):
    """SARIF region for the lines; line 1 when the ledger names only the file."""
    found = {"startLine": start or 1}
    if end and start and end >= start:
        found["endLine"] = end
    return found


def location(text):
    path, start, end = split_location(text)
    return {"physicalLocation": {"artifactLocation": {"uri": path.replace("\\", "/"), "uriBaseId": "SRCROOT"},
                                 "region": region(start, end)}}


def message(finding, severity):
    if finding["decision"] == "needs_confirmation":
        return "%s (needs confirmation; %s if confirmed)" % (finding["title"], severity)
    return "%s (%s)" % (finding["title"], finding["decision"])


def rule(finding, severity):
    return {"id": finding["key"], "name": finding["key"],
            "shortDescription": {"text": finding["title"]},
            "defaultConfiguration": {"level": LEVELS[severity]},
            "properties": {"security-severity": SECURITY_SEVERITY[severity], "tags": ["security"]}}


def suppression(entry):
    """External suppression for a finding waived by an accepted risk."""
    return {"kind": "external", "status": "accepted",
            "justification": "%s (accepted by %s until %s)" % (entry["reason"], entry["accepted_by"],
                                                               entry["expires"])}


def results_for(finding, severity, waiver):
    """One SARIF result per path of the finding."""
    results = []
    for path in finding.get("paths") or []:
        result = {"ruleId": finding["key"], "level": LEVELS[severity],
                  "message": {"text": message(finding, severity)},
                  "locations": [location(path)],
                  "partialFingerprints": {"appsecReviewKey/v1": "%s|%s" % (finding["key"], split_location(path)[0])}}
        if waiver:
            result["suppressions"] = [suppression(waiver)]
        results.append(result)
    return results


def to_sarif(ledger, severity_of, waiver_for=lambda finding, severity: None):
    """SARIF log for the ledger's reported findings. severity_of gives a finding's severity (None skips it);
    waiver_for gives the accepted-risk entry that waives it, or None."""
    rules, results = [], []
    for finding in ledger["findings"]:
        severity = severity_of(finding)
        if severity not in LEVELS:
            continue
        rules.append(rule(finding, severity))
        results += results_for(finding, severity, waiver_for(finding, severity))
    driver = {"name": "appsec-review", "informationUri": TOOL_URI, "rules": rules}
    run = {"tool": {"driver": driver}, "results": results,
           "properties": {"repo": ledger.get("repo"), "sourceRef": ledger.get("source_ref"),
                          "profile": ledger.get("profile")}}
    return {"$schema": SCHEMA, "version": "2.1.0", "runs": [run]}
