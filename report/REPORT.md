# Security report: structure and CVSS 3.1 scoring

Use this file whenever someone asks for a **report** of an appsec-review (a page, an artifact, an export, a
document to share). Terminal-only reviews keep the format in `SKILL.md`. A report always uses the structure,
fields and scoring below, so every report looks and rates the same way.

Build the page from `report-template.html`: keep its CSS and layout and replace only the content. Never put
another company's name, logo or branding on the report (it is an internal review), and never quote secret values,
card numbers, CVVs, OTPs or tokens. Refer to them by file, line or commit.

- **Escape everything you insert.** HTML-escape every replaced value (`&`, `<`, `>` always; `"` and `'` inside
  attributes). Code excerpts go into `<pre>` as escaped text only; the only markup allowed inside `<pre>` is the
  template's `<span class="hl">` wrapper around already-escaped lines. A proof of concept must never run or break
  the page when it is opened.
- **No third-party requests.** The template uses system font stacks and no external fonts, scripts or images, so
  opening a confidential report contacts no outside host. Keep it that way.
- **Light and dark mode.** Keep the cover's `#theme-toggle` button and its inline script at the end of the
  template; it is the only script a report may contain. It switches `data-theme` on the root element, keeps
  a fixed "Dark mode" label with `aria-pressed` carrying the state, follows the system theme until the reader
  picks one, and remembers the choice in that browser. Define every new color as a token in all three theme
  blocks so both modes stay readable.

## 1. Structure

Keep these sections, numbers and titles in this order. Leave a section in place with "None" rather than
dropping it.

| # | Section | Content |
|---|---|---|
| Cover | Title block | "Confidential" badge with the light/dark mode toggle beside it, organisation · platform, `<service>` + "Source Code Review Report", one-sentence scope, and a meta grid: Version, Date of issue, Branch (or PR/commit), Review type, Findings (total, with critical and high counts), Status |
| 1.0 | Document Control | 1.1 Document Details (title, classification "Confidential", description, date of issue). 1.2 Diffusion List (contact **titles** and purpose only; no personal names or emails unless the user supplies them). 1.3 Document History (version, report type, date, role, description; reviewer and approver rows "Pending" until the user fills them) |
| 2.0 | Executive Summary | 2.1 Project Objective (what was reviewed, the 1–2 most urgent problems, what is well built). 2.2 Disclaimer (confidential, point-in-time, what "needs confirmation" means). 2.3 Assessment Methodology (code enumeration and coverage ledger, dependency and secret checks, manual source analysis, wildcard and obvious-things hunters, and in `deep` the sink-trace hunter, verification of every candidate, reporting; name the review mode (`diff`, `standard` or `deep`), the review duration and token use from the run summary, the stack files applied, any scanners actually run, and which findings had an independent verifier and which were self-verified). 2.4 Security Standards (the standards table from "Security standards" below). 2.5 Findings Distribution (total, stacked bar, counts per rating). 2.6 Findings Distribution Chart (horizontal bars per rating). 2.7 Risk Criteria (CVSS band table, section 3 below). 2.7.1 Exploitation Complexity. 2.7.2 Risk Level Calculation (impact × complexity matrix). 2.8 Summary of Findings (table: #, Vulnerability linked to its finding, Risk, CVSS 3.1, Affected file:line, Status) |
| 3.0 | Project Description | 3.1 Scope of Work (repository, branch, version, stack and layer, code size, endpoints or screens, integrations). 3.2 Reviewing Constraints and Limitations (everything not verified, tools not run, dependency sources read or downloaded to check library behaviour and any that couldn't be obtained, ledger units left `blocked`, `deferred` or `out_of_scope` with their reasons, and the ledger summary counts). 3.3 Report Organization |
| 4.0 | Check List | 4.1 Secure Code Review Checklist: vulnerable / secure counts for each category in section 4 below. 4.2 Controls Verified as Secure (the "checked and found clean" list, taken from `covered` ledger units) |
| 5.0 | Vulnerability Findings | Single repository: 5.1 `<service>` · `<layer>`, where the layer is Backend, Web frontend or Mobile app (a repository with several layers, such as a full-stack app, gets 5.1 and 5.2). Several repositories: 5.1 Platform-wide findings, then 5.2 onwards with one section per repository (rules in section 6 of this file; 6.0 stays Recommendation). One finding card per issue, numbered 5.1.1, 5.1.2, … (5.2.1, … in later sections) ordered by CVSS score within its section, highest first; ties keep the order of the summary table |
| 6.0 | Recommendation | 8–12 numbered, prioritised actions that generalise the findings |
| Footer | | Confidentiality line and the note that secrets are referenced by location only |

### Security standards

Every report is assessed against the same baseline, which `rules/00-overview.md` maps to the checks. Section 2.4
lists it as a table (standard, version, what it covers in this review), and each finding cites it in References.

| Standard | Version | Used for |
|---|---|---|
| OWASP Top 10 | 2025 | Web application risk categories |
| OWASP API Security Top 10 | 2023 | API risks (object and function level authorization, resource limits, business flows) |
| OWASP ASVS | 5.0 | Verification requirements, chapters V1–V16. V3 Web Frontend Security when a browser UI is in scope |
| OWASP MASVS | 2.1 | Mobile controls: storage, crypto, auth, network, platform, code, resilience, privacy |
| OWASP MASTG | 2.0 | Mobile tests behind a mobile proof of concept |
| OWASP MASWE | 1.0 | Mobile weakness ids, used with CWE |
| OWASP Mobile Top 10 | 2024 | Mobile risks M1–M10 |
| MITRE/CISA CWE Top 25 | 2025 | Weakness ids for every finding |
| OWASP WSTG | current | Penetration-testing categories, including WSTG-CLNT for the browser |
| PCI DSS | v4.0 (req. 6.2.4, 3, 4) | Cardholder data, card data in logs, transport |
| NIST SP 800-63B | 4 | Passwords, authenticators, OTP and step-up |
| IETF RFC 9700 | 2025 | OAuth 2.0 Security Best Current Practice |
| IETF RFC 8252 | BCP 212 | OAuth 2.0 for native apps |
| IETF RFC 10017 | 2026 | OAuth 2.0 for browser-based applications |
| IETF RFC 9110 / 9111 / 9112 | 2022 | HTTP semantics, caching and message framing (request smuggling, cache poisoning) |
| OASIS SAML | 2.0 | SAML assertion signing, audience and replay checks |
| W3C WebAuthn | Level 3 | Passkey registration and authentication ceremonies |
| OWASP Top 10 for LLM Applications | 2025 | Prompt injection, output handling, excessive agency, RAG and memory, unbounded consumption |
| OWASP Top 10 for Agentic Applications | 2026 | Tool misuse, identity and privilege abuse, MCP and agent supply chain |
| SLSA / NIST SSDF | current / SP 800-218 | Build provenance, release integrity and secure development process |
| FIRST CVSS | 3.1 | Base score and rating (section 2 of this file) |
| Mozilla Web Security Guidelines, CIS/Checkov baselines, CISA KEV | current | Browser headers and cookies, containers and IaC, prioritising dependency CVEs |

Keep the table to standards the review actually applied: drop a row that has no matching code in scope and
say so in 3.2. Examples: SAML or WebAuthn when the code has neither; PCI DSS when no card data is handled; MASVS, MASTG, MASWE, Mobile Top 10 and RFC 8252
when no mobile app is in scope; RFC 10017 when no browser OAuth client is in scope.

### Finding card fields

Every finding has all of these, in this order:

1. **Number and title**: `5.1.n`, a short noun phrase naming the weakness (title case, no "[Security]" prefix,
   which belongs to the terminal format only).
2. **Metric strip**: Severity (rating from the CVSS band), CVSS 3.1 (score and full vector), Checklist
   (category from section 4), Status (`Initial Review`, later `Fixed`, `Partially Fixed`, `Not Fixed`,
   `Risk Accepted`).
3. **Affected assets**: one `path:lines` per line, repository-relative.
4. **References**: the identifiers the finding maps to, most specific first: OWASP Top 10:2025 (`A01`), OWASP
   API Top 10:2023 (`API1`) when an API is involved, one or two CWE ids, the ASVS 5.0 chapter or requirement
   (`V3`, `V8`). For a browser finding add WSTG-CLNT, and RFC 10017 when OAuth in the page is involved. For a
   mobile finding add the MASVS control, a MASWE id when one fits, the Mobile Top 10 id (`M9`), and RFC 8252
   when native OAuth is involved. Add PCI DSS v4.0, NIST SP 800-63B-4 or RFC 9700 when they apply. Use the
   same ids as the terminal title.
5. **Description**: what the code does and why it is weak. Add a "Needs confirmation" tag when exploitability
   depends on something outside the review, and say what must be confirmed.
6. **Impact**: what an attacker gains, under which preconditions.
7. **Recommendation**: a concrete fix that uses the codebase's existing helpers, plus the negative test to add.
8. **Proof of concept**: the file path, then a short code excerpt (5–10 lines) with the vulnerable lines
   highlighted. Omit only when no code excerpt can show the issue (e.g. git history, contract-driven crypto).

## 2. Scoring: CVSS 3.1 base score

Every finding gets a CVSS 3.1 base vector and score. The score sets the rating; nothing else does.

### Compute, never estimate

Run the calculator in this folder for every vector and copy its output:

```bash
python -I <skill folder>/report/cvss31.py "AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"
python -I <skill folder>/report/cvss31.py --selftest   # verifies the formula
```

If Python is unavailable, use the FIRST CVSS 3.1 calculator formula exactly (Roundup to one decimal) and say in
2.3 that scores were computed by hand.

### Rating bands

| Rating | CVSS 3.1 | Meaning |
|---|---|---|
| Critical | 9.0 – 10.0 | Exposed and exploitable with severe impact; no control in place or planned |
| High | 7.0 – 8.9 | High concern given exposure, ease of exploitation or severity of impact |
| Medium | 4.0 – 6.9 | Moderate concern; a control exists but is partial or only somewhat effective |
| Low | 0.1 – 3.9 | Minor concern; the control is in place but could be improved |
| Informational | 0.0 | Hardening advice with no direct exploit path today (no vector; score 0.0) |

### How to choose each metric

Score the realistic attacker for the deployed service, not the worst case you can imagine.

- **AV (Attack Vector)**: `N` for anything reachable through the public API or by reading central logs or the
  repository remotely; `A` when the attacker must sit on the internal network path (MITM on service-to-service
  calls, TLS issues); `L` for local access to the host.
- **AC (Attack Complexity)**: `H` when success depends on a condition the attacker cannot reliably control: a
  network position, a race, a specific DB or deployment configuration, a secret from another tenant, a mitigation
  to bypass, or an unconfirmed downstream behaviour. Otherwise `L`. Holding a credential or token is never a
  reason for `H`: model it with PR, and report how the credential leaks as its own finding.
- **PR (Privileges Required)**: `N` for anonymous endpoints; `L` for any authenticated customer (including an
  attacker using a customer's stolen token) **and** for readers of the central log store or the repository
  (treated as low-privileged insiders); `H` only for admin or operator roles. State the log-access assumption in
  2.7.
- **UI (User Interaction)**: `R` only when a victim must click or act; otherwise `N`.
- **S (Scope)**: `C` when the impact crosses the reviewed component's authorization boundary: another tenant's
  data, or credentials and tokens that unlock other services (identity provider, core banking, internal
  providers). Otherwise `U`.
- **C / I / A**: `H` for card data (PAN, CVV), credentials, tokens, every customer's data, or full control;
  `L` for limited or partial data (masked names, error text, one user's non-sensitive data); `N` when untouched.

### Exploitation complexity and the risk matrix

Report 2.7.1 and 2.7.2 for context; the rating itself always comes from the CVSS band.

| Complexity | Meaning |
|---|---|
| Trivial | No special knowledge; a single crafted request |
| Easy | A valid low-privilege account or read access to logs |
| Moderate | A network position, a misconfiguration, or a second weakness |
| Complex | Advanced knowledge, insider secrets, or several conditions at once |

| Impact \ Complexity | Trivial | Easy | Moderate | Complex |
|---|---|---|---|---|
| Critical | Critical | Critical | High | High |
| High | Critical | High | High | Medium |
| Medium | High | Medium | Medium | Low |
| Low | Medium | Low | Low | Low |

### Compliance overrides

CVSS does not capture compliance. When a finding breaks PCI DSS (CVV/PIN/track data stored or exposed, PAN in
clear) or a documented platform rule (e.g. never log OTPs, anti-enumeration), keep its CVSS rating and say in
its Impact that it must be prioritised with the highest-rated finding of the same kind.

### Mapping from the terminal format

| Terminal (`00-overview.md`) | Usual CVSS range |
|---|---|
| critical | High – Critical |
| bug | Medium – High |
| warning | Low – Medium |
| suggestion | Informational – Low |

This is a sanity check only. The vector decides; when it disagrees with the terminal label, use the vector.

## 3. Ordering and numbering

- Sort findings by CVSS score, highest first, within each section 5.x. For equal scores, put the higher C/I impact
  first, then `S:C` before `S:U`.
- The numbering depends on how many 5.x sections the report has, not on how many repositories it covers.
- **Only 5.1 (every finding is 5.1.n):** number the finding cards 5.1.1 onwards in that order (`{{FINDING_ID}}`).
  The 2.8 summary table lists them in the same order with a plain sequence number 1, 2, 3 (`{{SEQ}}`), where row n
  is finding 5.1.n. Give each card the element id `f<n>` (`{{ANCHOR}}`) and link the summary row to `#f<n>`.
- **Several 5.x sections (e.g. 5.2 Frontend in one repository, or a multi-repository report per section 6 of this
  file):** `{{FINDING_ID}}` and `{{SEQ}}` are both the full finding id `5.<x>.<n>`, and `{{ANCHOR}}` is
  `f<x>-<n>` (finding 5.2.1 has the id `f2-1`). The summary table lists findings grouped by section in section
  order.

## 4. Checklist categories

Use these categories in 4.1 and in each finding's Checklist field. Count a check as vulnerable when at
least one finding falls in it; count what you verified as secure in 4.2. List a category as "Not applicable" in
4.1, and say why in 3.2, when nothing in scope touches it (card data in a repository with no cardholder data,
web frontend and mobile security in a back end with no UI, OTP step-up where no flow uses one).

| # | Category | Main references |
|---|---|---|
| 1 | Access control and IDOR | A01, API1, API3, API5, ASVS V8, CWE-639/862/863 |
| 2 | Authentication and tokens | A07, API2, ASVS V6/V7/V9/V10, RFC 9700, CWE-287/345 |
| 3 | OTP step-up and one-time proofs | A07, API2, NIST SP 800-63B-4, ASVS V6, CWE-308/294 |
| 4 | Injection and input validation | A05, ASVS V1/V2, CWE-89/78/79/611/502 |
| 5 | Cryptography and secrets | A04, ASVS V11/V13, CWE-798/327/321 |
| 6 | Card data protection (PCI DSS) | PCI DSS v4.0 req. 3 and 6.2.4, A04, ASVS V14, CWE-312/359 |
| 7 | Transport security | A04, ASVS V12, PCI DSS req. 4, CWE-295/319 |
| 8 | Security misconfiguration and supply chain | A02, A03, API8, API9, ASVS V13/V15, CISA KEV, CWE-16/1104 |
| 9 | Logging and error handling | A09, A10, ASVS V16, PCI DSS req. 10, CWE-532/209/778 |
| 10 | Business logic and abuse | A06, API4, API6, ASVS V2, CWE-840/362/799 |
| 11 | Web frontend and mobile security | A05, ASVS V3, WSTG-CLNT, RFC 10017, MASVS, MASTG, MASWE, Mobile Top 10 M1–M10, RFC 8252, CWE-79/601/922/312/295 |

Findings from `web-protocol-identity.md` use the existing categories: SAML, WebAuthn, MFA enrollment, recovery,
account linking, API keys, mTLS identity and session rotation go in 2 (Authentication and tokens; cite SAML 2.0,
WebAuthn Level 3 or NIST SP 800-63B-4 in References); request smuggling, cache poisoning or deception and
forwarded-header trust go in 8 (Security misconfiguration; cite RFC 9112 or RFC 9111); response-header injection
goes in 4 (Injection). Wildcard and obvious-things findings go in the category that fits the weakness.

Findings from `ai-llm-agents.md` also use the existing categories: tool authorization, MCP identity and retrieval
without a tenant filter go in 1 (Access control); prompt injection that reaches a tool or sink, and unsafe model
output handling, go in 4 (Injection); secrets or personal data in prompts and traces go in 5 (Cryptography and
secrets) or 9 (Logging); unsafe model loading and unpinned MCP servers go in 8 (Supply chain); unbounded model
spend and agent loops go in 10 (Business logic and abuse). Cite the LLM or ASI id in References.

Check that every standard in 2.4 is the current edition (rules/00-overview.md, after the standards list); if
that wasn't possible, say so in 3.2.

## 5. Publishing

- Publish the report as a private artifact. Before telling the user to share it more widely, warn them that it
  contains working attack details for open issues.
- On a retest, keep the finding numbers, update Status per finding, bump the version in 1.1 and 1.3, and add a
  history row.

## 6. Multi-repository reports

Use these rules whenever more than one repository is in scope (SKILL.md "Multi-repository reviews"). Everything
in sections 1 to 5 still applies.

### Order of work

- Build the report only from deep reviews. Review one repository in depth, merge it into the report, publish (or
  update) the same artifact, then move to the next repository. Do not publish a combined report built from a quick
  sweep across repositories.
- Review in risk order: authentication and identity, money movement, card data, shared providers and gateways,
  then the rest.
- If the user stops early or a repository cannot be reviewed in depth, keep its section with the label
  "Breadth review (deep review pending)" and list it in 3.2.

### Structure changes

- **Cover:** the organisation or workspace name instead of one service; "current branch per repository (3.1)" as
  the branch; Status "In progress: N of M repositories deep-reviewed" until all are done, then "Initial Review".
- **2.1:** say which repositories were deep-reviewed so far, then the most urgent problems across all of them.
- **2.8:** one row per finding, grouped by section in section order, with the finding id (5.2.1) in the # column
  and the repository name at the start of the affected-file column. Add one sentence above the table saying how it
  is grouped.
- **3.1:** a table with one row per repository: name, branch reviewed, stack and layer, review depth (Deep or
  Breadth). Then the usual code, entry points and integrations rows for the whole set.
- **3.2:** add every repository still at breadth depth and anything shared that could not be verified (databases,
  downstream systems, identity-provider settings).
- **4.1 and 4.2:** count findings and verified controls across all repositories; name the repository in each
  verified control.
- **5.1 Platform-wide findings:** issues that come from code, configuration or libraries shared by several
  repositories. Report each once, list every affected repository and location in its assets, and use the most
  representative excerpt as the proof of concept.
- **5.2 onwards, one section per repository** (`<repository> · <layer>`): open each with a one-paragraph note
  stating the review depth, the branch, what was covered and which controls held. Keep the section even when it
  has no findings of its own, and say that its issues are listed in 5.1.
- **Contents rail:** add one sub-entry per section 5.x.
- **6.0:** generalise across repositories; reference findings by id.
- **1.3 Document History:** one row per merged repository (version 1.1, 1.2, …), saying what was added, moved
  or corrected.

### Merging rules

- When a repository repeats a pattern already in 5.1, add its locations to that finding. When a repository finding
  reappears in another repository, move it to 5.1. Never report the same root cause twice.
- Give the same issue the same CVSS vector everywhere; if merging changes an earlier score, say so in that
  finding's description and in the history row.
- Before merging a standalone single-repository report, re-check each of its findings against the current code,
  drop or correct what no longer holds, and correct any statement in 4.2 or 2.1 that the deeper review disproves.
- Cross-references between findings must survive renumbering: keep symbolic ids in the working data and resolve
  them to finding numbers and links when building the page.
- Prefix every asset path with its repository name (an ellipsis may shorten the package path).
