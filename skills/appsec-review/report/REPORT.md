# Security report: structure and CVSS 4.0 scoring

Use this file for the **report** every appsec-review run produces after its terminal result (SKILL.md "Report").
The terminal result keeps the format in `SKILL.md`. A report always uses the structure, fields and scoring below,
so every report looks and rates the same way.

Every report is written twice from the same finding data: an HTML page for people and a Markdown copy for
feeding to another session (section 5). Build the page from `report-template.html`: keep its CSS and layout and
replace only the content. Never put
another company's name, logo or branding on the report (it is an internal review), and never quote secret values,
card numbers, CVVs, OTPs or tokens. Refer to them by file, line or commit.

- **Organisation name.** Take `{{ORGANISATION}}` (the cover line and the 6.5 Disclaimer, in both the HTML and
  the Markdown copy) from the repository under review, freshly for every report: the owner in its
  `git remote get-url origin` (the GitHub or Bitbucket owner, the GitLab group, the Azure DevOps organisation);
  with no remote, the name in its project manifest or README; failing both, the repository folder name. For
  several repositories, use their shared owner, or the workspace folder name when they differ. Never reuse a
  name from an earlier report, another repository, memory or this skill's examples.

- **Escape everything you insert.** HTML-escape every replaced value (`&`, `<`, `>` always; `"` and `'` inside
  attributes). Code excerpts go into `<pre>` as escaped text only; the only markup allowed inside `<pre>` is the
  template's `<span class="hl">` wrapper around already-escaped lines. A proof of concept must never run or break
  the page when it is opened.
- **No third-party requests.** The template uses system font stacks and no external fonts, scripts or images, so
  opening a confidential report contacts no outside host. Keep it that way.
- **Logo.** The cover and the footer credit line show the skill's logo: the dark logo on the cover band, and in the
  footer the logo matching the theme (the light one in print). Leave the template's `{{LOGO_LIGHT}}` and
  `{{LOGO_DARK}}` placeholders in place when writing the page, then run
  `python -I <skill folder>/report/embed_logos.py <report.html>`, which embeds both images from `report/assets/`
  as data URIs. Never type or copy the image data yourself. The Markdown copy has no logo.
- **Light and dark mode.** Keep the cover's `#theme-toggle` button and its inline script at the end of the
  template; it is the only script a report may contain. It switches `data-theme` on the root element, keeps
  a label naming the mode it switches to ("Dark mode" or "Light mode"), follows the system theme until the reader
  picks one, and remembers the choice in that browser. Define every new color as a token in all three theme
  blocks so both modes stay readable.
- **Print and PDF.** The template's `@media print` block makes Print → Save as PDF a light, single-column A4
  document in either theme: no toggle or contents rail, each numbered section on a new page, table headers
  repeated across pages, and a "Confidential" and page-number footer. Keep table header rows in `<thead>`, and
  add every new color token to the print block too.

## 1. Structure

Keep these sections, numbers and titles in this order. Leave a section in place with "None" rather than
dropping it.

| # | Section | Content |
|---|---|---|
| Cover | Title block | "Confidential" badge with the light/dark mode toggle beside it, organisation · platform, `<service>` + "Source Code Review Report", one-sentence scope, and a meta grid: Version, Date of issue, Branch (or PR/commit), Review mode (`diff`, `standard` or `deep`), Findings (root causes and affected locations, with critical and high counts), Status |
| 1.0 | Executive Summary | 1.1 Key Takeaways (what was reviewed, the 1–2 most urgent problems, what is well built; on a retest, also what changed since the previous version: fixed, new and re-rated findings). 1.2 Risk Profile (one card: root causes, affected locations, stacked bar and counts per rating; with several layers, one more card per layer, section 7). 1.3 Findings at a Glance (table: #, Vulnerability linked to its finding, Risk, CVSS 4.0, Affected file:line, Status; with several layers, grouped by layer) |
| 2.0 | Scope and Threat Model | 2.1 Scope of Work (repository, branch, version, stack and layer, code size, endpoints or screens, integrations; with several layers, one Layer row per layer naming its folders). 2.2 Threat Model (from the ledger: assets, actors and each abuse path with its result: realised by a finding, blocked by a named control, or blocked on an outside fact). 2.3 Limitations (everything not verified, tools not run, dependency sources read or downloaded to check library behaviour and any that couldn't be obtained, ledger units left `blocked`, `deferred` or `out_of_scope` with their reasons, and the ledger summary counts) |
| 3.0 | Security Controls Checklist | 3.1 Checklist Results: vulnerable / secure counts for each applicable category in section 4 below, then one line naming the categories that don't apply. 3.2 Controls Verified as Secure (the "checked and found clean" list, taken from `covered` ledger units) |
| 4.0 | Vulnerability Findings | Single repository: 4.1 `<service>` · `<layer>`, where the layer is Backend, Web frontend or Mobile app. A repository with several layers, such as a full-stack app, gets one section per layer, never one mixed section (section 7 of this file). Several repositories: 4.1 Platform-wide findings, then 4.2 onwards with one section per repository (rules in section 6 of this file; 5.0 stays Remediation Plan). One finding card per issue, numbered 4.1.1, 4.1.2, … (4.2.1, … in later sections) ordered by CVSS score within its section, highest first; ties keep the order of the summary table |
| 5.0 | Remediation Plan | 5.1 Prioritised Actions: 8–12 numbered actions that generalise the findings, each naming the finding ids it closes and an effort (S, M or L). 5.2 Facts to Confirm: one row per `needs confirmation` finding with its id, the exact fact, a safe way for the owner to check it, and the rating if it turns out unsafe ("None" when there are none) |
| 6.0 | Appendix | 6.1 Assessment Methodology (one opening line naming the appsec-review skill and its commit, `git -C <skill folder> rev-parse --short HEAD`, dropping the commit when the skill folder is not a git repository; then code enumeration and coverage ledger, dependency and secret checks, manual source analysis, wildcard and obvious-things hunters, and in `deep` the sink-trace hunter, verification of every candidate, reporting; name the review mode, the review duration and token use from the run summary, the stack files applied and any scanners actually run). 6.2 Security Standards (the standards table from "Security standards" below). 6.3 Risk Rating Criteria (CVSS band table, section 2 below). 6.4 Candidates Rejected by Verification (title, `file:line`, the verifier's reason and the disproof line, so the reader can overrule a wrong rejection; "None" when there are none). 6.5 Disclaimer (confidential, point-in-time, what "needs confirmation" means) |
| Footer | | Confidentiality line and the note that secrets are referenced by location only, then the credit line: "Generated with appsec-review · Skill author: Ibrahim Abdallatif · LinkedIn", linking the skill name to its repository and "LinkedIn" to the author's profile. Keep it as the template has it; the Markdown copy ends with the same line, with the repository and LinkedIn URLs written out |

### Security standards

Every report is assessed against the same baseline, which `rules/00-overview.md` maps to the checks. Section 6.2
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
| FIRST CVSS | 4.0 | Base score (CVSS-B) and rating (section 2 of this file) |
| Mozilla Web Security Guidelines, CIS/Checkov baselines, CISA KEV | current | Browser headers and cookies, containers and IaC, prioritising dependency CVEs |

Keep the table to standards the review actually applied: drop a row that has no matching code in scope and
say so in 2.3. Examples: SAML or WebAuthn when the code has neither; PCI DSS when no card data is handled; MASVS, MASTG, MASWE, Mobile Top 10 and RFC 8252
when no mobile app is in scope; RFC 10017 when no browser OAuth client is in scope.

### Finding card fields

Every finding has all of these, in this order:

1. **Number, title and key**: `4.1.n`, a short noun phrase naming the weakness (title case, no "[Security]"
   prefix, which belongs to the terminal format only), and the finding's ledger key in small type so a later run
   can be traced back to it.
2. **Metric strip**: Severity (rating from the CVSS band), CVSS 4.0 (score and full `CVSS:4.0/` vector), Checklist
   (category from section 4), Verification (`Independent verifier`, `Rejection reviewed` or `Self-verified`),
   Status (`Initial Review`, later `Fixed`, `Partially Fixed`, `Not Fixed`, `Risk Accepted`).
3. **Affected assets**: one `path:lines` per line, repository-relative.
4. **References**: the identifiers the finding maps to, most specific first: OWASP Top 10:2025 (`A01`), OWASP
   API Top 10:2023 (`API1`) when an API is involved, one or two CWE ids, the ASVS 5.0 chapter or requirement
   (`V3`, `V8`). For a browser finding add WSTG-CLNT, and RFC 10017 when OAuth in the page is involved. For a
   mobile finding add the MASVS control, a MASWE id when one fits, the Mobile Top 10 id (`M9`), and RFC 8252
   when native OAuth is involved. Add PCI DSS v4.0, NIST SP 800-63B-4 or RFC 9700 when they apply. Use the
   same ids as the terminal title.
5. **Description**: what the code does and why it is weak. Add a "Needs confirmation" tag when exploitability
   depends on something outside the review, and say what must be confirmed (it is also listed in 5.2).
6. **Attack scenario**: numbered steps: the attacker and what they hold, the request or action they send, and
   the result. For a chain, a `Chain:` line first naming its links by finding id in order and where each hands
   off to the next.
7. **Impact**: what an attacker gains, under which preconditions.
8. **Recommendation**: a concrete fix that uses the codebase's existing helpers, plus the negative test to add.
9. **Proof of concept**: the file path, then a short code excerpt (5–10 lines) with the vulnerable lines
   highlighted. Omit only when no code excerpt can show the issue (e.g. git history, contract-driven crypto).

## 2. Scoring: CVSS 4.0 base score

Every finding gets a CVSS 4.0 base vector and score. The score sets the rating; nothing else does. Only base
metrics are scored (CVSS-B): leave threat (`E`) and environmental metrics out of the vector, and say once in 6.3
that scores are CVSS-B.

### Compute, never estimate

Run the calculator in this folder for every vector and copy its output, including the normalised `CVSS:4.0/`
vector:

```bash
python -I <skill folder>/report/cvss40.py "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"
python -I <skill folder>/report/cvss40.py --selftest   # verifies against FIRST reference scores
```

CVSS 4.0 has no closed formula (scores come from FIRST's MacroVector lookup table), so never score by hand. If
the calculator exits non-zero, stop and report that error; do not invent a score. If Python is unavailable, use
the FIRST calculator at https://www.first.org/cvss/calculator/4.0 and say so in 6.1.

### Rating bands

| Rating | CVSS 4.0 | Meaning |
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
  calls, TLS issues); `L` for local access to the host or device (including a malicious app on the same phone);
  `P` when the attacker must physically handle the device.
- **AC (Attack Complexity)**: `H` only when the attacker must defeat a security mechanism the code or platform
  puts in place: guess or leak a secret specific to the target (another tenant's key, a CSRF token, an
  unpredictable id), or bypass a mitigation such as ASLR or certificate pinning. Otherwise `L`.
- **AT (Attack Requirements)**: `P` when success depends on a deployment or execution condition the attacker
  cannot control: winning a race, a network position for MITM, a specific DB or deployment configuration, a
  feature flag being on, or an unconfirmed downstream behaviour. Otherwise `N`. Holding a credential or token is
  never a reason for `AC:H` or `AT:P`: model it with PR, and report how the credential leaks as its own finding.
- **PR (Privileges Required)**: `N` for anonymous endpoints; `L` for any authenticated customer (including an
  attacker using a customer's stolen token) **and** for readers of the central log store or the repository
  (treated as low-privileged insiders); `H` only for admin or operator roles. State the log-access assumption in
  6.3.
- **UI (User Interaction)**: `P` (passive) when a victim only has to do something ordinary, such as open a page,
  a message or a shared link; `A` (active) when they must take a deliberate step, such as click a specific
  control, accept a prompt or install something; otherwise `N`.
- **VC / VI / VA (Vulnerable system)**: confidentiality, integrity and availability of the reviewed service
  itself. `H` for card data (PAN, CVV), credentials, tokens, every customer's data, or full control; `L` for
  limited or partial data (masked names, error text, one user's non-sensitive data); `N` when untouched.
- **SC / SI / SA (Subsequent systems)**: the same scale for systems beyond the reviewed component's authorization
  boundary: another tenant's environment, the victim's browser session (stored or reflected XSS), and services
  unlocked by leaked credentials or tokens (identity provider, core banking, internal providers). `N` when
  nothing outside the reviewed service is affected. This replaces CVSS 3.1's Scope: never add `S:`.

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

- Sort findings by CVSS score, highest first, within each section 4.x. For equal scores, put the higher VC/VI impact
  first, then the higher SC/SI/SA impact.
- The numbering depends on how many 4.x sections the report has, not on how many repositories it covers.
- **Only 4.1 (every finding is 4.1.n):** number the finding cards 4.1.1 onwards in that order (`{{FINDING_ID}}`).
  The 1.3 table lists them in the same order with a plain sequence number 1, 2, 3 (`{{SEQ}}`), where row n is
  finding 4.1.n. Give each card the element id `f<n>` (`{{ANCHOR}}`) and link the table row to `#f<n>`.
- **Several 4.x sections (e.g. 4.2 Frontend in one repository, or a multi-repository report per section 6 of this
  file):** `{{FINDING_ID}}` and `{{SEQ}}` are both the full finding id `4.<x>.<n>`, and `{{ANCHOR}}` is
  `f<x>-<n>` (finding 4.2.1 has the id `f2-1`). The 1.3 table lists findings grouped by section in section order.
- Reports built before this layout numbered findings 5.x.n. On a retest of one, renumber to 4.x.n and give the
  old id in brackets after the title, in that version only.

## 4. Checklist categories

Use these categories in 3.1 and in each finding's Checklist field. Count a check as vulnerable when at
least one finding falls in it; count what you verified as secure in 3.2. Leave a category out of the 3.1 bars and
name it on the "Not applicable" line instead, saying why in 2.3, when nothing in scope touches it (card data in a
repository with no cardholder data, web frontend and mobile security in a back end with no UI, OTP step-up where no flow uses one).

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

Check that every standard in 6.2 is the current edition (rules/00-overview.md, after the standards list); if
that wasn't possible, say so in 2.3.

## 5. Saving and publishing

### Local files

Every run that builds a report (every `standard` and `deep` run; a `diff` run only when asked or non-interactive)
writes both files to `~/.appsec-review/<repo>/`, outside the reviewed repository, next to the ledger. A
multi-repository report uses the name of the directory holding the repositories in place of `<repo>`. Each run
overwrites the previous files; the version and date on the cover tell them apart.

| File | Content |
|---|---|
| `report.html` | The page built from `report-template.html` |
| `report.md` | The same report as Markdown, built from the same finding data at the same time |

The Markdown copy must say everything the page says, in the same order, so another session can work from it alone:

- **Front matter** with `service`, `repository`, `branch`, `commit`, `mode`, `version`, `date` and `status`, so a
  script can read them.
- **Same structure:** every section and sub-section from section 1 as a heading with its number and title
  (`## 4.0 Vulnerability Findings`, `### 4.1.2 <title>`), and "None" where the page says None.
- **Same finding fields** in the same order (section 1, "Finding card fields"), each as a bold label. Put the
  ledger key on the line under the title, the full `CVSS:4.0/` vector and score next to the rating, and each
  affected asset as a list item.
- **Tables** as Markdown tables; the risk profile as a table of counts per rating instead of a bar.
- **Code excerpts** in fenced code blocks with the language named, the file path above the block, and a
  `Vulnerable lines:` line listing the highlighted line numbers instead of the highlight. Never change the code to
  mark lines, and use a fence longer than any run of backticks inside the excerpt.
- **No HTML**, no styling and no theme script. The secrets rule above applies unchanged.

### Publishing

Publishing is off unless the user explicitly asks to publish. Writing the local files is not publishing.

- On Claude Code, an explicit request publishes the HTML file as a private artifact and nothing wider. Before
  telling the user to share it further, warn them that it contains working attack details for open issues.
  When the session cannot publish (CI, scheduled, headless, or a host with no artifact tool), skip this step
  and say so; the local files are still written.
- Cursor and Codex have no publish step. If the user asked, tell them the report is only the local files.
- Never upload the report, the ledger, the inventory or source code on your own.
- Finish by printing the absolute path of both local files, with the home directory expanded, and the artifact
  link only when one was published (SKILL.md "Report").
- When a published report is updated, rewrite both local files too, so they always match the artifact.
- On a retest, keep the finding numbers, update Status per finding, bump the cover version and date of issue,
  and say in 1.1 what changed since the previous version. If the previous version was scored with CVSS 3.1,
  re-score every finding with CVSS 4.0 and say in 1.1 that ratings may have moved because of the new version.

## 6. Multi-repository reports

Use these rules whenever more than one repository is in scope (SKILL.md "Multi-repository reviews"). Everything
in sections 1 to 5 still applies.

### Order of work

- Build the report only from deep reviews. Review one repository in depth, merge it into the report, and rewrite
  both local files before moving to the next repository. Publish or update an artifact only when the user
  explicitly asked to publish. Do not publish a combined report built from a quick
  sweep across repositories.
- Review in risk order: authentication and identity, money movement, card data, shared providers and gateways,
  then the rest.
- If the user stops early or a repository cannot be reviewed in depth, keep its section with the label
  "Breadth review (deep review pending)" and list it in 2.3.

### Structure changes

- **Cover:** the organisation or workspace name instead of one service; "current branch per repository (2.1)" as
  the branch; Status "In progress: N of M repositories deep-reviewed" until all are done, then "Initial Review".
  Bump the version for each merged repository (1.1, 1.2, …).
- **1.1:** say which repositories were deep-reviewed so far, then the most urgent problems across all of them.
- **1.3:** one row per finding, grouped by section in section order, with the finding id (4.2.1) in the # column
  and the repository name at the start of the affected-file column. Add one sentence above the table saying how it
  is grouped.
- **2.1:** a table with one row per repository: name, branch reviewed, stack and layer, review depth (Deep or
  Breadth). Then the usual code, entry points and integrations rows for the whole set.
- **2.3:** add every repository still at breadth depth and anything shared that could not be verified (databases,
  downstream systems, identity-provider settings).
- **3.1 and 3.2:** count findings and verified controls across all repositories; name the repository in each
  verified control.
- **4.1 Platform-wide findings:** issues that come from code, configuration or libraries shared by several
  repositories. Report each once, list every affected repository and location in its assets, and use the most
  representative excerpt as the proof of concept.
- **4.2 onwards, one section per repository** (`<repository> · <layer>`): open each with a one-paragraph note
  stating the review depth, the branch, what was covered and which controls held. Keep the section even when it
  has no findings of its own, and say that its issues are listed in 4.1.
- **Contents rail:** add one sub-entry per section 4.x.
- **5.1:** generalise across repositories; reference findings by id.

### Merging rules

- When a repository repeats a pattern already in 4.1, add its locations to that finding. When a repository finding
  reappears in another repository, move it to 4.1. Never report the same root cause twice.
- Give the same issue the same CVSS vector everywhere; if merging changes an earlier score, say so in that
  finding's description.
- Before merging a standalone single-repository report, re-check each of its findings against the current code,
  drop or correct what no longer holds, and correct any statement in 3.2 or 1.1 that the deeper review disproves.
- Cross-references between findings must survive renumbering: keep symbolic ids in the working data and resolve
  them to finding numbers and links when building the page.
- Prefix every asset path with its repository name (an ellipsis may shorten the package path).

## 7. Repositories with several layers

Use these rules whenever a reviewed repository has more than one layer (a back end with a web front end, a back end
with a mobile app, or all three), so a reader can see each layer's findings on their own. They apply to a
single-repository report and to each such repository in a multi-repository report. The layer of each finding is the
`layer` field in the ledger, chosen by the rules in `rules/00-overview.md` ("Findings in a repository with several
layers").

- **4.0:** one section per layer, in the order Backend, Web frontend, Mobile app, titled `<service>` · `<layer>`
  (4.1 `shop` · Backend, 4.2 `shop` · Web frontend). Never put two layers' findings in one section. Open each
  section with one sentence naming the folders it covers. Keep a layer's section with "None" when it has no
  findings, and say which controls held there. In a multi-repository report the repository gets one section per
  layer in the same way (4.3 `shop` · Backend, 4.4 `shop` · Web frontend), after 4.1 Platform-wide findings.
- **Numbering:** several 4.x sections, so ids and anchors follow section 3 ("Several 4.x sections"): 4.1.1,
  4.2.1, with anchors `f1-1`, `f2-1`.
- **Cross-references:** when one weakness has a matching finding in another layer (the page renders unescaped
  HTML that the API stored without validation), each card's Description links the other by id. A back-end
  finding that the front end only hides gets one line in the front-end section pointing to it.
- **1.2 Risk Profile:** keep the total card, then add one card per layer below it with that layer's root causes,
  locations, bar and counts, so the counts per layer add up to the total.
- **1.3 Findings at a Glance:** one group per layer, in section order, each opened by a group row naming the
  section (`4.1 Backend`). The # column holds the full finding id.
- **2.1 Scope of Work:** one Layer row per layer: its stack, folders, and entry points or screens.
- **3.1 and 3.2:** count across layers, and name the layer in each verified control (`Backend: …`).
- **5.1 Prioritised Actions:** say which layer each action changes; an action that changes both names both.
- **Markdown copy:** the same sections and groups, with the per-layer counts as one table (rows per layer, columns
  per rating, plus a Total row).
- **Contents rail:** one sub-entry per layer section, linking its heading id (`s1`, `s2` for 4.1, 4.2).
