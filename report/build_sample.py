"""Build the public sample report from report-template.html and a fictional fixture.

The sample in docs/ is linked from the README, so it must stay in step with the template: the CI tests fail when
the committed files differ from a fresh build.

Usage:
    python -I build_sample.py            write docs/sample-report.html and docs/sample-report.md
    python -I build_sample.py --check    exit 1 when the committed files are out of date
    python -I test_build_sample.py       run the unit tests
"""
import html
import json
import os
import re
import sys

sys.dont_write_bytecode = True  # keep the skill folder free of __pycache__
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import cvss40  # noqa: E402

TEMPLATE = os.path.join(HERE, "report-template.html")
FIXTURE = os.path.join(HERE, "sample", "acme-shop.json")
DOCS = os.path.join(os.path.dirname(HERE), "docs")
OUTPUTS = {"html": os.path.join(DOCS, "sample-report.html"), "md": os.path.join(DOCS, "sample-report.md")}

RATINGS = ("Critical", "High", "Medium", "Low", "Informational")
SEV_CLASS = {"Critical": "s-critical", "High": "s-high", "Medium": "s-medium", "Low": "s-low",
             "Informational": "s-info"}
IMPACT_RANK = {"H": 2, "L": 1, "N": 0}
REF = re.compile(r"\{ref:([\w-]+)\}")
REPO_URL = "https://github.com/ibrahimabdallatif/appsec-review"
LINKEDIN_URL = "https://www.linkedin.com/in/ibrahimabdallatif/"


# Finding data

def score(finding):
    """Copy of the finding with its normalised vector, CVSS 4.0 base score and rating, computed by cvss40.py."""
    if not finding.get("vector"):
        return dict(finding, vector="", cvss=0.0, rating="Informational")
    value = cvss40.base_score(finding["vector"])
    return dict(finding, vector=cvss40.normalize(finding["vector"]), cvss=value, rating=cvss40.rating(value))


def impact(finding, metrics):
    """Sum of the H/L/N impact levels of the given metrics; 0 for a finding without a vector."""
    if not finding["vector"]:
        return 0
    parsed = cvss40.parse_vector(finding["vector"])
    return sum(IMPACT_RANK[parsed[m]] for m in metrics)


def sort_key(finding):
    """REPORT.md section 3: highest score first, then higher VC/VI, then higher SC/SI/SA."""
    return (-finding["cvss"], -impact(finding, ("VC", "VI")), -impact(finding, ("SC", "SI", "SA")))


def build_sections(data):
    """One 4.x section per layer, in layer order, with numbered, sorted findings."""
    sections = []
    for x, layer in enumerate(data["layers"], 1):
        found = sorted((score(f) for f in data["findings"] if f["layer"] == layer["name"]), key=sort_key)
        for n, finding in enumerate(found, 1):
            finding.update(id="4.%d.%d" % (x, n), anchor="f%d-%d" % (x, n))
        sections.append(dict(layer, layer_name=layer["name"], num="4.%d" % x, anchor="s%d" % x, findings=found))
    return sections


def all_findings(sections):
    return [f for s in sections for f in s["findings"]]


def finding_ids(sections):
    """Finding key -> (finding id, anchor), for resolving {ref:key}."""
    return {f["key"]: (f["id"], f["anchor"]) for f in all_findings(sections)}


def count_ratings(findings):
    counts = dict.fromkeys(RATINGS, 0)
    for finding in findings:
        counts[finding["rating"]] += 1
    return counts


def count_locations(findings):
    return sum(len(f["assets"]) for f in findings)


def format_score(finding):
    return "%.1f" % finding["cvss"]


# Text

def html_text(text, ids):
    """Escape text, turn `code` into <code> and {ref:key} into a link to that finding."""
    escaped = re.sub(r"`([^`]+)`", r"<code>\1</code>", html.escape(text))
    return REF.sub(lambda m: '<a href="#%s">%s</a>' % (ids[m.group(1)][1], ids[m.group(1)][0]), escaped)


def md_text(text, ids):
    """Resolve {ref:key} to the finding id; Markdown keeps the backticks."""
    return REF.sub(lambda m: ids[m.group(1)][0], text)


# Template editing

def fill(text, values):
    for key, value in values.items():
        text = text.replace("{{%s}}" % key, str(value))
    return text


def line_index(lines, marker, start=0):
    hits = [i for i in range(start, len(lines)) if marker in lines[i]]
    if len(hits) != 1:
        raise ValueError("expected one template line with %r, found %d" % (marker, len(hits)))
    return hits[0]


def find_line(text, marker):
    lines = text.split("\n")
    return lines[line_index(lines, marker)]


def replace_line(text, marker, new_lines):
    lines = text.split("\n")
    i = line_index(lines, marker)
    return "\n".join(lines[:i] + list(new_lines) + lines[i + 1:])


def repeat_line(text, marker, rows):
    """Replace the one line holding marker with one filled copy per row."""
    line = find_line(text, marker)
    return replace_line(text, marker, [fill(line, row) for row in rows])


def uncomment(line):
    """'  <!-- LAYERS ONLY, note: <markup> -->' -> '  <markup>'."""
    match = re.match(r"(\s*)<!--[^:]*: (.*) -->\s*$", line)
    if not match:
        raise ValueError("not a commented template line: %r" % line)
    return match.group(1) + match.group(2)


def indent_of(line):
    return line[:len(line) - len(line.lstrip())]


def block_range(lines, marker, closing):
    """(start, end) line indexes of the block opened on the marker line and closed by `closing` at its indent."""
    start = line_index(lines, marker)
    close = indent_of(lines[start]) + closing
    for end in range(start + 1, len(lines)):
        if lines[end] == close:
            return start, end + 1
    raise ValueError("no %r closes the block at %r" % (closing, marker))


def replace_block(text, marker, closing, render):
    """Replace a template block with render(block_text)."""
    lines = text.split("\n")
    start, end = block_range(lines, marker, closing)
    return "\n".join(lines[:start] + [render("\n".join(lines[start:end]))] + lines[end:])


def strip_comments(text):
    """Remove template comments: whole comment lines first, then inline ones."""
    text = re.sub(r"^[ \t]*<!--(?:(?!-->).)*-->[ \t]*\n", "", text, flags=re.S | re.M)
    return re.sub(r"<!--(?:(?!-->).)*-->", "", text, flags=re.S)


def drop_empty_bars(text):
    """REPORT template: drop a stacked-bar span whose count is 0."""
    return re.sub(r'^[ \t]*<span class="s-\w+" style="flex:0"></span>\n', "", text, flags=re.M)


def drop_empty_legend(text):
    """Layer cards drop a legend entry whose count is 0."""
    return re.sub(r'^[ \t]*<div class="s-\w+"><b>0</b><span>\w+</span></div>\n', "", text, flags=re.M)


def wrap_document(body):
    """The template is a fragment; GitHub Pages needs a full document with its charset."""
    head = ('<!doctype html>\n<html lang="en">\n<meta charset="utf-8">\n'
            '<meta name="viewport" content="width=device-width, initial-scale=1">\n')
    return head + body.rstrip("\n") + "\n</html>\n"


# HTML sections

def rating_values(prefix, counts):
    names = {"Critical": "CRITICAL", "High": "HIGH", "Medium": "MEDIUM", "Low": "LOW", "Informational": "INFO"}
    return {prefix + names[r]: counts[r] for r in RATINGS}


def render_rail(text, ctx):
    line = uncomment(find_line(text, "LAYERS ONLY, REPEAT per 4.x section"))
    rows = [{"SECTION_ANCHOR": s["anchor"], "SECTION_NUM": s["num"], "LAYER": s["layer_name"]}
            for s in ctx["sections"]]
    return replace_line(text, "LAYERS ONLY, REPEAT per 4.x section", [fill(line, r) for r in rows])


def layer_card(block, section):
    found = section["findings"]
    values = dict(rating_values("L_", count_ratings(found)), LAYER=section["layer_name"],
                  LAYER_TOTAL=len(found), LAYER_LOCATIONS=count_locations(found))
    return drop_empty_legend(fill(block, values) + "\n").rstrip("\n")


def render_layer_cards(text, ctx):
    return replace_block(text, 'class="card total layer"', "</div>",
                         lambda block: "\n".join(layer_card(block, s) for s in ctx["sections"]))


def glance_row(line, finding):
    return fill(line, {"SEQ": finding["id"], "ANCHOR": finding["anchor"], "FINDING_TITLE": html.escape(finding["title"]),
                       "SEV_CLASS": SEV_CLASS[finding["rating"]], "RATING": finding["rating"],
                       "CVSS": format_score(finding), "FILE:LINES": html.escape(finding["assets"][0]),
                       "STATUS": finding["status"]})


def render_glance(text, ctx):
    group = uncomment(find_line(text, "LAYERS ONLY, before each layer's rows"))
    row = find_line(text, "{{FINDING_TITLE}}</a>")
    rows = []
    for section in ctx["sections"]:
        rows.append(fill(group, {"SECTION_NUM": section["num"], "LAYER": section["layer_name"]}))
        rows.extend(glance_row(row, f) for f in section["findings"])
    return replace_line(text, "{{FINDING_TITLE}}</a>", rows)


def render_scope(text, ctx):
    line = find_line(text, "{{STACK}} · {{LAYER}}")
    stack = fill(line, {"STACK": html_text(ctx["data"]["meta"]["stack"], ctx["ids"]),
                        "LAYER": " and ".join(s["layer_name"] for s in ctx["sections"])})
    layers = ["%s<tr><td>Layer</td><td>%s</td></tr>" % (indent_of(line), html_text(layer_detail(s), ctx["ids"]))
              for s in ctx["sections"]]
    return replace_line(text, "{{STACK}} · {{LAYER}}", [stack] + layers)


def layer_detail(section):
    return "%s: %s in %s; %s" % (section["layer_name"], section["stack"], section["folders"], section["entry_points"])


def render_threat_model(text, ctx):
    data, ids = ctx["data"], ctx["ids"]
    text = repeat_line(text, "{{ABUSE_PATH}}", [
        {"ABUSE_PATH": html_text(t["path"], ids), "ABUSE_RESULT": t["result"],
         "FINDING_ID_OR_CONTROL_OR_FACT": html_text(t["evidence"], ids)} for t in data["threats"]])
    return repeat_line(text, "{{NOT_VERIFIED_ITEM}}",
                       [{"NOT_VERIFIED_ITEM": html_text(item, ids)} for item in data["limitations"]])


def checklist_rows(ctx):
    findings = all_findings(ctx["sections"])
    rows = []
    for item in ctx["data"]["checklist"]:
        vulnerable = sum(1 for f in findings if f["category"] == item["category"])
        rows.append({"CATEGORY": item["category"], "VULN": vulnerable, "SECURE": item["checks"] - vulnerable,
                     "TOTAL_CHECKS": item["checks"]})
    return rows


def render_checklist(text, ctx):
    text = repeat_line(text, "{{CATEGORY}}", checklist_rows(ctx))
    return repeat_line(text, "{{SECURE_CONTROL}}",
                       [{"SECURE_CONTROL": html_text(c, ctx["ids"])} for c in ctx["data"]["secure_controls"]])


def poc_block(finding):
    marked = set(finding["highlight"])
    lines = [('<span class="hl">%s</span>' if n in marked else "%s") % html.escape(code)
             for n, code in enumerate(finding["poc"], 1)]
    return "<pre>" + "\n".join(lines) + "</pre>"


def finding_values(finding, ids):
    return {"SEV_CLASS": SEV_CLASS[finding["rating"]], "ANCHOR": finding["anchor"], "FINDING_ID": finding["id"],
            "LEDGER_KEY": html.escape(finding["ledger_key"]), "FINDING_TITLE": html.escape(finding["title"]),
            "RATING": finding["rating"], "CVSS": format_score(finding),
            "VECTOR": finding["vector"] or "No vector (informational)",
            "CHECKLIST_CATEGORY": finding["category"], "VERIFICATION": finding["verification"],
            "STATUS": finding["status"], "REFERENCES": html.escape(finding["references"]),
            "DESCRIPTION": html_text(finding["description"], ids), "IMPACT": html_text(finding["impact"], ids),
            "RECOMMENDATION": html_text(finding["recommendation"], ids),
            "FULL_REPO_PATH": html.escape(finding["poc_path"])}


def finding_card(article, finding, ids):
    card = repeat_line(article, "{{PATH:LINES}}", [{"PATH:LINES": html.escape(a)} for a in finding["assets"]])
    steps = "".join("<li>%s</li>" % html_text(step, ids) for step in finding["attack"])
    card = card.replace("<li>{{ATTACK_STEP}}</li>", steps)
    if finding.get("needs_confirmation"):
        card = card.replace('<!-- optional: <span class="confirm">Needs confirmation</span> -->',
                            '<span class="confirm">Needs confirmation</span>')
    card = replace_line(card, "{{CODE_LINE}}", [poc_block(finding)])
    card = replace_line(card, "{{VULNERABLE_LINE}}", [])
    return fill(card, finding_values(finding, ids))


def findings_section(block, section, ids):
    lines = block.split("\n")
    start, end = block_range(lines, "<article", "</article>")
    head = fill("\n".join(lines[:start]), {"SECTION_ANCHOR": section["anchor"], "SECTION_NUM": section["num"],
                                           "LAYER": section["layer_name"],
                                           "LAYER_FOLDERS": html_text(section["folders"], ids)})
    head = replace_line(head, "LAYERS ONLY: <p", [uncomment(find_line(head, "LAYERS ONLY: <p"))])
    article = "\n".join(lines[start:end])
    cards = "\n\n".join(finding_card(article, f, ids) for f in section["findings"])
    return head + "\n" + cards


def render_findings(text, ctx):
    return replace_block(text, 'id="{{SECTION_ANCHOR}}"', "</article>", lambda block: "\n\n".join(
        findings_section(block, s, ctx["ids"]) for s in ctx["sections"]))


def closes(keys, ids):
    return ", ".join(ids[k][0] for k in keys)


def fact_rows(ctx):
    return [{"ANCHOR": f["anchor"], "FINDING_ID": f["id"], "FACT": html_text(f["fact"], ctx["ids"]),
             "SAFE_CHECK": html_text(f["safe_check"], ctx["ids"]), "SEV_CLASS": SEV_CLASS[f["unsafe_rating"]],
             "RATING": f["unsafe_rating"]}
            for f in all_findings(ctx["sections"]) if f.get("needs_confirmation")]


def render_remediation(text, ctx):
    ids = ctx["ids"]
    text = repeat_line(text, "{{RECOMMENDED_ACTION}}", [
        {"RECOMMENDED_ACTION": html_text(r["action"], ids), "FINDING_IDS": closes(r["closes"], ids),
         "EFFORT": r["effort"]} for r in ctx["data"]["remediation"]])
    rows = fact_rows(ctx)
    if rows:
        return repeat_line(text, "{{FACT}}", rows)
    line = find_line(text, "{{FACT}}")
    return replace_line(text, "{{FACT}}", [indent_of(line) + '<tr><td colspan="4">None</td></tr>'])


def render_appendix(text, ctx):
    data, ids = ctx["data"], ctx["ids"]
    text = repeat_line(text, "{{STANDARD_USE}}", [
        {"STANDARD": s["name"], "STANDARD_VERSION": s["version"], "STANDARD_USE": s["use"]}
        for s in data["standards"]])
    return repeat_line(text, "{{CANDIDATE_TITLE}}", [
        {"CANDIDATE_TITLE": html.escape(r["title"]), "FILE:LINES": html.escape(r["location"]),
         "REASON": html_text(r["reason"], ids), "DISPROOF_PATH:LINE": html.escape(r["disproof"])}
        for r in data["rejected"]])


def global_values(ctx):
    meta, summary, method, ids = ctx["data"]["meta"], ctx["data"]["summary"], ctx["data"]["methodology"], ctx["ids"]
    findings = all_findings(ctx["sections"])
    values = rating_values("N_", count_ratings(findings))
    values.update({
        "SERVICE_TITLE": meta["service_title"], "ORGANISATION": meta["organisation"], "PLATFORM": meta["platform"],
        "SERVICE": meta["service"], "ONE_SENTENCE_SCOPE": html_text(meta["scope_sentence"], ids),
        "VERSION": meta["version"], "DATE_LONG": meta["date_long"], "BRANCH": meta["branch"], "MODE": meta["mode"],
        "TOTAL": len(findings), "N_LOCATIONS": count_locations(findings), "STATUS": meta["status"],
        "WHAT_WAS_REVIEWED_AND_WHY": html_text(summary["reviewed"], ids),
        "MOST_URGENT_PROBLEMS": html_text(summary["urgent"], ids),
        "WHAT_IS_WELL_BUILT": html_text(summary["well_built"], ids), "APP_VERSION": meta["app_version"],
        "CODE_SCOPE": html_text(meta["code_scope"], ids), "ENDPOINTS": html_text(meta["endpoints"], ids),
        "INTEGRATIONS": html_text(meta["integrations"], ids),
        "ASSETS_AND_ACTORS": html_text(ctx["data"]["assets_and_actors"], ids),
        "NOT_APPLICABLE_CATEGORIES": html_text(ctx["data"]["not_applicable"], ids), "SKILL_REF": meta["skill_ref"],
        "STACK_AND_ENTRY_POINTS": html_text(method["enumeration"], ids),
        "DEPENDENCY_AND_SECRET_CHECKS_AND_TOOLS_RUN": html_text(method["dependencies"], ids),
        "STACK": html_text(meta["stack"], ids), "VERIFICATION_METHOD": html_text(method["verification"], ids),
        "DURATION": meta["duration"], "TOKENS": meta["tokens"]})
    return values


HTML_STEPS = (render_rail, render_layer_cards, render_glance, render_scope, render_threat_model, render_checklist,
              render_findings, render_remediation, render_appendix)


def context(data):
    sections = build_sections(data)
    return {"data": data, "sections": sections, "ids": finding_ids(sections)}


def build_html(template, data):
    ctx = context(data)
    text = template
    for step in HTML_STEPS:
        text = step(text, ctx)
    text = fill(text, global_values(ctx))
    return wrap_document(drop_empty_bars(strip_comments(text)))


# Markdown

def md_table(header, rows):
    lines = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    lines.extend("| " + " | ".join(str(cell) for cell in row) + " |" for row in rows)
    return "\n".join(lines)


def md_front_matter(meta):
    keys = (("service", meta["service"]), ("repository", meta["repository"]), ("branch", meta["branch"]),
            ("commit", meta["commit"]), ("mode", meta["mode"]), ("version", meta["version"]),
            ("date", meta["date"]), ("status", meta["status"]))
    return "---\n" + "\n".join('%s: "%s"' % pair for pair in keys) + "\n---"


def md_cover(ctx):
    meta, findings = ctx["data"]["meta"], all_findings(ctx["sections"])
    counts = count_ratings(findings)
    summary = "%d in %d locations (%d critical, %d high)" % (
        len(findings), count_locations(findings), counts["Critical"], counts["High"])
    rows = [("Version", meta["version"]), ("Date of issue", meta["date_long"]), ("Branch", "`%s`" % meta["branch"]),
            ("Review mode", meta["mode"]), ("Findings", summary), ("Status", meta["status"])]
    return "\n\n".join([
        "# %s Source Code Review Report" % meta["service"],
        "Confidential · %s · %s" % (meta["organisation"], meta["platform"]),
        md_text(meta["scope_sentence"], ctx["ids"]), md_table(("Item", "Detail"), rows)])


def md_rating_row(label, findings):
    counts = count_ratings(findings)
    return [label] + [counts[r] for r in RATINGS] + [len(findings), count_locations(findings)]


def md_glance(ctx):
    rows = []
    for section in ctx["sections"]:
        rows.append(["**%s %s**" % (section["num"], section["layer_name"]), "", "", "", "", ""])
        rows.extend([f["id"], f["title"], f["rating"], format_score(f), "`%s`" % f["assets"][0], f["status"]]
                    for f in section["findings"])
    return md_table(("#", "Vulnerability", "Risk", "CVSS 4.0", "Affected file", "Status"), rows)


def md_exec(ctx):
    summary, ids = ctx["data"]["summary"], ctx["ids"]
    rows = [md_rating_row(s["layer_name"], s["findings"]) for s in ctx["sections"]]
    rows.append(md_rating_row("**Total**", all_findings(ctx["sections"])))
    return "\n\n".join([
        "## 1.0 Executive Summary", "### 1.1 Key Takeaways",
        md_text(summary["reviewed"], ids), md_text(summary["urgent"], ids), md_text(summary["well_built"], ids),
        "### 1.2 Risk Profile",
        md_table(("Layer",) + RATINGS + ("Root causes", "Locations"), rows),
        "### 1.3 Findings at a Glance", "Findings are grouped by layer, in section order.", md_glance(ctx)])


def md_bullets(items, ids):
    return "\n".join("- " + md_text(item, ids) for item in items)


def md_scope(ctx):
    data, ids = ctx["data"], ctx["ids"]
    meta = data["meta"]
    rows = [("Repository", "`%s`, branch `%s`, version %s" % (meta["service"], meta["branch"], meta["app_version"])),
            ("Stack", meta["stack"])]
    rows += [("Layer", layer_detail(s)) for s in ctx["sections"]]
    rows += [("Code", meta["code_scope"]), ("Entry points", meta["endpoints"]), ("Integrations", meta["integrations"])]
    threats = [(t["path"], t["result"], md_text(t["evidence"], ids)) for t in data["threats"]]
    return "\n\n".join([
        "## 2.0 Scope and Threat Model", "### 2.1 Scope of Work", md_table(("Item", "Detail"), rows),
        "### 2.2 Threat Model", md_text(data["assets_and_actors"], ids),
        md_table(("Abuse path", "Result", "Evidence"), threats),
        "### 2.3 Limitations", md_bullets(data["limitations"], ids)])


def md_checklist(ctx):
    rows = [(r["CATEGORY"], r["VULN"], r["SECURE"], r["TOTAL_CHECKS"]) for r in checklist_rows(ctx)]
    return "\n\n".join([
        "## 3.0 Security Controls Checklist", "### 3.1 Checklist Results",
        md_table(("Category", "Vulnerable", "Secure", "Checks"), rows),
        "Not applicable: %s (see 2.3)." % ctx["data"]["not_applicable"],
        "### 3.2 Controls Verified as Secure", md_bullets(ctx["data"]["secure_controls"], ctx["ids"])])


def fence_for(lines):
    longest = max([len(run) for line in lines for run in re.findall(r"`+", line)] + [0])
    return "`" * max(3, longest + 1)


def md_poc(finding):
    fence = fence_for(finding["poc"])
    marked = ", ".join(str(n) for n in finding["highlight"])
    return "\n\n".join([
        "**Proof of concept**", "`%s`" % finding["poc_path"],
        "%s%s\n%s\n%s" % (fence, finding["poc_language"], "\n".join(finding["poc"]), fence),
        "Vulnerable lines: %s" % marked])


def md_finding(finding, ids):
    vector = " (`%s`)" % finding["vector"] if finding["vector"] else ""
    confirm = "Needs confirmation. " if finding.get("needs_confirmation") else ""
    metrics = ["- **Severity:** %s, CVSS 4.0 %s%s" % (finding["rating"], format_score(finding), vector),
               "- **Checklist:** " + finding["category"], "- **Verification:** " + finding["verification"],
               "- **Status:** " + finding["status"]]
    steps = "\n".join("%d. %s" % (n, md_text(s, ids)) for n, s in enumerate(finding["attack"], 1))
    return "\n\n".join([
        "#### %s %s" % (finding["id"], finding["title"]), "`%s`" % finding["ledger_key"], "\n".join(metrics),
        "**Affected assets**", "\n".join("- `%s`" % a for a in finding["assets"]),
        "**References:** " + finding["references"],
        "**Description:** " + confirm + md_text(finding["description"], ids),
        "**Attack scenario**", steps, "**Impact:** " + md_text(finding["impact"], ids),
        "**Recommendation:** " + md_text(finding["recommendation"], ids), md_poc(finding)])


def md_findings(ctx):
    parts = ["## 4.0 Vulnerability Findings"]
    for section in ctx["sections"]:
        parts.append("### %s %s · %s" % (section["num"], ctx["data"]["meta"]["service"], section["layer_name"]))
        parts.append("Covers %s." % section["folders"])
        parts.extend(md_finding(f, ctx["ids"]) for f in section["findings"])
    return "\n\n".join(parts)


def md_remediation(ctx):
    ids = ctx["ids"]
    actions = "\n".join("%d. %s Closes %s · Effort %s" % (n, md_text(r["action"], ids), closes(r["closes"], ids),
                                                        r["effort"])
                        for n, r in enumerate(ctx["data"]["remediation"], 1))
    facts = [(f["id"], md_text(f["fact"], ids), md_text(f["safe_check"], ids), f["unsafe_rating"])
             for f in all_findings(ctx["sections"]) if f.get("needs_confirmation")] or [("None", "", "", "")]
    return "\n\n".join([
        "## 5.0 Remediation Plan", "### 5.1 Prioritised Actions", actions, "### 5.2 Facts to Confirm",
        md_table(("Finding", "Fact to confirm", "How to check", "Rating if unsafe"), facts)])


def md_methodology(ctx):
    meta, method, ids = ctx["data"]["meta"], ctx["data"]["methodology"], ctx["ids"]
    items = ["**Code enumeration.** " + md_text(method["enumeration"], ids),
             "**Dependency and secret checks.** " + md_text(method["dependencies"], ids),
             "**Manual source analysis.** Followed each entry point (routes and handlers, screens and client flows) "
             "through its middleware, filters and guards to its sinks, with a STRIDE pass on every trust boundary, "
             "against the checklist in section 3.0 and the stack checks for %s." % meta["stack"],
             "**Verification.** " + md_text(method["verification"], ids),
             "**Run.** %s mode, %s, %s." % (meta["mode"], meta["duration"], meta["tokens"])]
    return "\n\n".join([
        "### 6.1 Assessment Methodology",
        "This review was performed with the **appsec-review** skill, commit `%s`." % meta["skill_ref"],
        "\n".join("- " + item for item in items)])


def md_appendix(ctx):
    data, ids = ctx["data"], ctx["ids"]
    standards = [(s["name"], s["version"], s["use"]) for s in data["standards"]]
    bands = [("Critical", "9.0 – 10.0"), ("High", "7.0 – 8.9"), ("Medium", "4.0 – 6.9"), ("Low", "0.1 – 3.9"),
             ("Informational", "0.0")]
    rejected = [(r["title"], "`%s`" % r["location"], md_text(r["reason"], ids), "`%s`" % r["disproof"])
                for r in data["rejected"]] or [("None", "", "", "")]
    return "\n\n".join([
        "## 6.0 Appendix", md_methodology(ctx), "### 6.2 Security Standards",
        md_table(("Standard", "Version", "Used for"), standards), "### 6.3 Risk Rating Criteria",
        "Each finding is rated by its CVSS 4.0 base score (CVSS-B: base metrics only, no threat or environmental "
        "metrics). Where log or repository access is a precondition, the score assumes low-privileged readers (PR:L).",
        md_table(("Risk", "CVSS 4.0"), bands), "### 6.4 Candidates Rejected by Verification",
        md_table(("Candidate", "Location", "Reason", "Disproof"), rejected), "### 6.5 Disclaimer",
        "This report is confidential and intended only for %s. Its findings reflect the code on the reviewed branch "
        "on the date of issue; later changes to code, configuration or architecture may change the results. "
        "Findings marked \"needs confirmation\" depend on behaviour outside the review scope."
        % data["meta"]["organisation"]])


def md_footer():
    return "\n\n".join([
        "---",
        "Confidential. Secret values, card data, OTPs and tokens are referenced by location only and never "
        "reproduced in this report.",
        "Generated with appsec-review (%s) · Skill author: Ibrahim Abdallatif · LinkedIn (%s)"
        % (REPO_URL, LINKEDIN_URL)])


MD_PARTS = (md_cover, md_exec, md_scope, md_checklist, md_findings, md_remediation, md_appendix)


def build_markdown(data):
    ctx = context(data)
    parts = [md_front_matter(data["meta"])] + [part(ctx) for part in MD_PARTS] + [md_footer()]
    return "\n\n".join(parts) + "\n"


# Files

def read_text(path):
    with open(path, encoding="utf-8") as handle:
        return handle.read()


def write_text(path, text):
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)


def build_all():
    data = json.loads(read_text(FIXTURE))
    return {"html": build_html(read_text(TEMPLATE), data), "md": build_markdown(data)}


def stale_outputs(built):
    """Output paths whose committed content differs from the fresh build."""
    return [OUTPUTS[k] for k, text in built.items()
            if not os.path.exists(OUTPUTS[k]) or read_text(OUTPUTS[k]) != text]


def main(args):
    built = build_all()
    if args == ["--check"]:
        stale = stale_outputs(built)
        for path in stale:
            print("out of date: %s (run: python -I report/build_sample.py)" % path)
        return 1 if stale else 0
    if args:
        print(__doc__)
        return 2
    for key, text in built.items():
        write_text(OUTPUTS[key], text)
        print("wrote %s" % OUTPUTS[key])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
