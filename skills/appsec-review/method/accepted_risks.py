"""Accepted risks for the ledger.py --fail-on gate.

An accepted-risk file lists findings a team has decided to live with for now, so the gate stops failing on them
without hiding them:

    {"accepted": [
      {"id": "legacy-orders-idor", "paths_any": ["src/legacy/OrderController"], "text": "order.*(owner|idor)",
       "max_severity": "bug", "reason": "Endpoint removed in the Q1 release; gateway blocks cross-tenant ids",
       "accepted_by": "payments security review", "expires": "2027-01-31"}
    ]}

An entry matches a finding the way a benchmark does: one of the finding's paths contains a 'paths_any' substring
and its key or title matches the 'text' regex (case-insensitive), so a fresh run that names the issue differently
still matches. A matched finding stops blocking only while the entry has not expired and the finding is no more
severe than 'max_severity'; otherwise it blocks again and the gate says why. Entries that match no reported
finding are listed as unused, so fixed issues can be removed.
"""
import datetime
import re

SEVERITIES = ("critical", "bug", "warning", "suggestion")
REQUIRED = ("id", "paths_any", "text", "max_severity", "reason", "accepted_by", "expires")


def parse_date(text):
    """datetime.date for a YYYY-MM-DD string, None otherwise."""
    try:
        return datetime.date.fromisoformat(text) if isinstance(text, str) and len(text) == 10 else None
    except ValueError:
        return None


def is_valid_regex(text):
    try:
        re.compile(text)
    except (re.error, TypeError):
        return False
    return True


def is_text_list(value):
    return isinstance(value, list) and bool(value) and all(isinstance(v, str) and v for v in value)


def check_entry(entry):
    """Error strings for one accepted-risk entry; empty when valid."""
    if not isinstance(entry, dict):
        return ["accepted: every entry must be an object"]
    label = "accepted %s" % entry.get("id")
    errors = ["%s: missing '%s'" % (label, key) for key in REQUIRED if not entry.get(key)]
    if errors:
        return errors
    if not is_text_list(entry["paths_any"]):
        errors.append("%s: paths_any must be a list of path substrings" % label)
    if not is_valid_regex(entry["text"]):
        errors.append("%s: text is not a valid regex" % label)
    if entry["max_severity"] not in SEVERITIES:
        errors.append("%s: max_severity must be one of %s" % (label, ", ".join(SEVERITIES)))
    if parse_date(entry["expires"]) is None:
        errors.append("%s: expires must be a YYYY-MM-DD date" % label)
    return errors


def duplicate_ids(entries):
    seen, dups = set(), set()
    for entry in entries:
        (dups if entry.get("id") in seen else seen).add(entry.get("id"))
    return sorted(dups, key=str)


def check_accepted(doc):
    """Error strings for an accepted-risk file; empty when valid."""
    if not isinstance(doc, dict) or not isinstance(doc.get("accepted"), list):
        return ["accepted: top level must be an object with an 'accepted' list"]
    errors = []
    for entry in doc["accepted"]:
        errors += check_entry(entry)
    if all(isinstance(e, dict) for e in doc["accepted"]):
        errors += ["accepted: duplicate id '%s'" % d for d in duplicate_ids(doc["accepted"])]
    return errors


def matches(entry, finding):
    """True when a finding path contains one of the entry's substrings and its key or title matches its text."""
    paths = finding.get("paths") or []
    if not any(part in path for part in entry["paths_any"] for path in paths):
        return False
    text = "%s %s" % (finding.get("key", ""), finding.get("title", ""))
    return re.search(entry["text"], text, re.IGNORECASE) is not None


def entry_for(finding, entries):
    """The first entry that matches the finding, or None."""
    return next((e for e in entries if matches(e, finding)), None)


def more_severe(severity, limit):
    return SEVERITIES.index(severity) < SEVERITIES.index(limit)


def why_still_blocking(entry, severity, today):
    """Why a matched entry does not waive the finding, or None when it does."""
    if parse_date(entry["expires"]) < today:
        return "acceptance '%s' expired %s" % (entry["id"], entry["expires"])
    if more_severe(severity, entry["max_severity"]):
        return "above acceptance '%s' (accepted up to %s)" % (entry["id"], entry["max_severity"])
    return None


def waiver_for(finding, severity, entries, today):
    """The entry that currently waives the finding, or None."""
    entry = entry_for(finding, entries)
    return entry if entry and why_still_blocking(entry, severity, today) is None else None


def apply(blocking, entries, severity_of, today):
    """Split blocking findings into (still blocking as (finding, note or None), waived as (finding, entry))."""
    still, waived = [], []
    for finding in blocking:
        entry = entry_for(finding, entries)
        note = why_still_blocking(entry, severity_of(finding), today) if entry else None
        if entry and note is None:
            waived.append((finding, entry))
        else:
            still.append((finding, note))
    return still, waived


def unused(entries, reported):
    """Entries that match none of the reported (non-rejected) findings."""
    return [e for e in entries if not any(matches(e, f) for f in reported)]
