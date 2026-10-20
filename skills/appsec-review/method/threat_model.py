"""Threat model, abuse paths and chained findings in a coverage ledger. Called by ledger.py's validate().

- threat_model (top level): assets ranked most valuable first ({"id", "what"}), actors and trust boundaries.
- Abuse paths are ledger units with area 'abuse-path', surface 'abuse/<slug>' and an 'abuse' object naming the
  actor, the asset and the goal. A ledger needs at least MIN_ABUSE_PATHS of them, and every asset must be the
  target of one. A 'covered' abuse path was blocked: one of its checks must cite the path:line of the control
  that stops it. A 'finding' abuse path links the findings that realise it.
- A chained finding has 'chain': the keys of two or more reported findings that together give a worse outcome
  than any of them alone. It is needs_confirmation (or rejected) while a link is unconfirmed, and must be more
  severe than its most severe link; otherwise the links are reported on their own.
"""
import re

ABUSE_AREA = "abuse-path"
ABUSE_PREFIX = "abuse/"
MIN_ABUSE_PATHS = 3
SEVERITIES = ("critical", "bug", "warning", "suggestion")
PATH_LINE = re.compile(r"[^\s:]+:\d+")


def is_text(value):
    return isinstance(value, str) and bool(value.strip())


def is_text_list(value):
    return isinstance(value, list) and bool(value) and all(is_text(v) for v in value)


def check_asset(asset):
    if not isinstance(asset, dict) or not is_text(asset.get("id")) or not is_text(asset.get("what")):
        return ["threat_model: every asset needs 'id' and 'what'"]
    return []


def duplicates(values):
    seen, dups = set(), set()
    for value in values:
        (dups if value in seen else seen).add(value)
    return sorted(dups, key=str)


def check_model(model):
    """Errors for the top-level threat_model block."""
    if not isinstance(model, dict):
        return ["threat_model: missing; list assets, actors and boundaries (method/threat-model.md)"]
    assets = model.get("assets")
    if not isinstance(assets, list) or not assets:
        return ["threat_model: assets must be a non-empty list"]
    errors = []
    for asset in assets:
        errors += check_asset(asset)
    for field in ("actors", "boundaries"):
        if not is_text_list(model.get(field)):
            errors.append("threat_model: %s must be a non-empty list of strings" % field)
    if not errors:
        errors += ["threat_model: duplicate asset id '%s'" % d for d in duplicates(a["id"] for a in assets)]
    return errors


def asset_ids(model):
    return [a["id"] for a in model["assets"]]


def abuse_units(units):
    return [u for u in units if u.get("area") == ABUSE_AREA]


def check_abuse_fields(unit, model):
    """The unit's 'abuse' object names a known actor, a known asset and a goal."""
    label = "unit %s" % unit.get("id")
    abuse = unit.get("abuse")
    if not isinstance(abuse, dict) or not all(is_text(abuse.get(k)) for k in ("actor", "asset", "goal")):
        return ["%s: abuse paths need 'abuse' with actor, asset and goal" % label]
    errors = []
    if abuse["actor"] not in model["actors"]:
        errors.append("%s: actor '%s' is not in threat_model actors" % (label, abuse["actor"]))
    if abuse["asset"] not in asset_ids(model):
        errors.append("%s: asset '%s' is not in threat_model assets" % (label, abuse["asset"]))
    return errors


def check_abuse_unit(unit, model):
    label = "unit %s" % unit.get("id")
    errors = []
    if not str(unit.get("surface", "")).startswith(ABUSE_PREFIX):
        errors.append("%s: abuse path surfaces start with '%s'" % (label, ABUSE_PREFIX))
    errors += check_abuse_fields(unit, model)
    checks = unit.get("checks") or []
    if unit.get("status") == "covered" and not any(PATH_LINE.search(str(c)) for c in checks):
        errors.append("%s: a blocked abuse path needs a check citing the path:line of the control that stops it"
                      % label)
    return errors


def check_abuse_coverage(units, model):
    """Enough abuse paths, and one aimed at every asset."""
    errors = []
    if len(units) < MIN_ABUSE_PATHS:
        errors.append("threat_model: %d abuse path unit(s); write at least %d" % (len(units), MIN_ABUSE_PATHS))
    targeted = {(u.get("abuse") or {}).get("asset") for u in units if isinstance(u.get("abuse"), dict)}
    errors += ["threat_model: asset '%s' has no abuse path" % a for a in asset_ids(model) if a not in targeted]
    return errors


def check_abuse(ledger):
    """Errors for the threat model and the abuse path units."""
    model = ledger.get("threat_model")
    errors = check_model(model)
    if errors:
        return errors
    units = abuse_units(ledger.get("units", []))
    for unit in units:
        errors += check_abuse_unit(unit, model)
    return errors + check_abuse_coverage(units, model)


def rank(severity):
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def check_chain_links(finding, by_key):
    """Errors in the list of linked keys."""
    label = "finding %s" % finding.get("key")
    chain = finding["chain"]
    if not isinstance(chain, list) or len(chain) < 2 or not all(is_text(k) for k in chain):
        return ["%s: chain must list at least two finding keys" % label]
    errors = ["%s: chain lists '%s' twice" % (label, k) for k in duplicates(chain)]
    for key in chain:
        link = by_key.get(key)
        if key == finding.get("key"):
            errors.append("%s: chain must not include itself" % label)
        elif link is None:
            errors.append("%s: chain link '%s' is not a finding" % (label, key))
        elif link.get("decision") == "rejected":
            errors.append("%s: chain link '%s' was rejected" % (label, key))
        elif "chain" in link:
            errors.append("%s: chain link '%s' is itself a chain; list its links instead" % (label, key))
    return errors


def check_chain_verdict(finding, links, severity_of):
    """A chain is no more certain than its links and must be worse than the worst of them."""
    label = "finding %s" % finding.get("key")
    decision = finding.get("decision")
    if decision == "rejected":
        return []
    errors = []
    if decision == "confirmed" and any(l.get("decision") == "needs_confirmation" for l in links):
        errors.append("%s: a chain with an unconfirmed link is needs_confirmation" % label)
    worst = min((severity_of(l) for l in links), key=rank)
    if rank(severity_of(finding)) >= rank(worst):
        errors.append("%s: a chain must be more severe than its worst link (%s); otherwise report the links alone"
                      % (label, worst))
    return errors


def check_chains(findings, severity_of):
    """Errors for chained findings. severity_of gives a finding's reported or if-confirmed severity."""
    by_key = {f.get("key"): f for f in findings}
    errors = []
    for finding in findings:
        if "chain" not in finding:
            continue
        link_errors = check_chain_links(finding, by_key)
        errors += link_errors
        if not link_errors:
            errors += check_chain_verdict(finding, [by_key[k] for k in finding["chain"]], severity_of)
    return errors
