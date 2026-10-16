---
name: appsec-review
description: Manual security review and pentest-style assessment of back-end, web front-end and mobile code in any language or framework against OWASP Top 10:2025, OWASP API Top 10:2023, ASVS 5.0 including V3 Web Frontend Security, MASVS, MASTG, Mobile Top 10:2024, CWE Top 25, PCI DSS, NIST SP 800-63B-4, RFC 9700, RFC 8252 and RFC 10017. Run only when the user explicitly invokes /appsec-review or $appsec-review, for a diff, branch, PR, file, endpoint, the whole repository, or every repository under a directory.
disable-model-invocation: true
---

# Security assessment

This skill runs only when someone invokes it explicitly. It is not part of CodeCanary or any automatic PR check.

This skill lives in `~/.claude/skills/appsec-review/` and is available in every Claude Code session. It
reviews any repository, or every repository under a directory; Claude Code states the skill folder as the
skill's base directory when it loads. Paths to the skill's own files below (`rules/`, `method/`, `report/`) are relative to
that skill folder, not to the reviewed repository. The checklist is in `rules/`. Read those files; don't rely on memory.

| File | Area |
|---|---|
| `00-overview.md` | Method, STRIDE pass, severity scale, reporting format. Always read first. |
| `access-control.md` | IDOR/BOLA, function-level authorization, mass assignment, multi-tenancy, SSRF |
| `authentication-session.md` | Authentication, auth logic flaws, JWT/OAuth (RFC 9700, RFC 8252, RFC 10017), step-up/OTP, passwords (NIST 800-63B-4), sessions |
| `injection-input.md` | Validation, SQL/LIKE/command/EL injection, CRLF, XXE, deserialization, files |
| `cryptography-data-protection.md` | Secrets, crypto, TLS, card and personal data (PCI DSS) |
| `business-logic-resources.md` | Workflow integrity, money, races, replay, abuse, enumeration, resource limits |
| `configuration-supply-chain.md` | Exposed tooling, config, headers and cookies, dependencies, CI, containers and IaC |
| `logging-error-handling.md` | Security events, log leaks, error responses, fail-closed handling |
| `client-side.md` | Web front ends (ASVS V3, WSTG-CLNT, RFC 10017) and mobile apps (MASVS, MASTG, MASWE, Mobile Top 10, RFC 8252): DOM XSS, token storage, CSP, deep links, WebViews |
| `ai-llm-agents.md` | LLM, agent and MCP features: dangerous capability combinations, tool authorization and argument validation, MCP identity, RAG and memory tenant isolation, model output handling, prompts and traces, model supply chain, spend limits. Loaded only when its `detect` front matter matches |
| `web-protocol-identity.md` | Request smuggling, cache poisoning and deception, host and forwarded-header trust, header injection, session and cookie edges, SAML, WebAuthn/passkeys, MFA enrollment and downgrade, recovery and account linking, API keys, mTLS |
| `deep/*.md` | `deep` mode only: in-depth playbooks for object-level authorization, payment callback integrity, payment state and idempotency, race conditions and business-logic flaws. Each extends one category file (`parent` front matter) and loads when its `when` front matter matches code in scope |
| `stacks/*.md` | Framework add-ons, chosen by their `detect` front matter: `java-spring`, `node-backend`, `web-frontend`, `mobile`, `python`, `dotnet`, `go`, `baas` (Supabase, Firebase) |

The category files are framework-neutral; the stack files name each framework's entry points, constructs and
unsafe APIs.

The method files in `method/` are not checklists; they define how the review runs:

| File | Purpose |
|---|---|
| `method/coverage-ledger.md` | The coverage ledger: units (entry point × category), statuses, later runs |
| `method/ledger.py` | Ledger validator, coverage summary and the `--fail-on` CI gate (`test_ledger.py` holds its tests) |
| `method/accepted_risks.py` | Accepted-risk file for the gate's `--accepted` option (`test_accepted_risks.py` holds its tests) |
| `method/sarif.py` | SARIF 2.1.0 export for `ledger.py --sarif` (`test_sarif.py` holds its tests) |
| `method/hunters.md` | Wildcard, obvious-things and sink-trace hunter prompts, and when to run them as subagents |
| `method/verifier.md` | Verification per mode: an inline disproof pass, plus fresh verifier subagents that try to disprove candidates |
| `method/run_stats.py` | Run timer and token totals for the run summary (`test_run_stats.py` holds its tests) |
| `method/inventory.py` | Lists entry points and sinks by script, so every run seeds the same ledger units (`inventory_patterns.py` holds the per-stack patterns, `test_inventory.py` the tests) |
| `evals/benchmark.py` | Not used during a review. Scores one run's ledger, or several runs' for stability, against a benchmark of known findings, to check the skill after changes (`CONTRIBUTING.md`) |

## Review modes

Pick the mode once, before step 4, and state it at the top of the result. **Never choose `deep` yourself.**

| Mode | When | Subagents | Ledger |
|---|---|---|---|
| `diff` | Default when the user names nothing, or names a diff, branch, PR or files | None, except one verifier if a `critical` candidate survives the disproof pass | None |
| `standard` | The user asks for a whole repository, an endpoint, or several repositories | At most two: one combined hunter (`model: sonnet`), and one verifier for all `critical`, `bug` and `warning` candidates in one batch (session's model) | Module × category |
| `deep` | **Only** when the user explicitly says "deep" (`/appsec-review deep`, "deep review", "deep mode") | Two hunters (wildcard and obvious-things, and a backward sink tracer) and one verifier per `critical`/`bug` candidate, on the session's model; adds the `rules/deep/` playbooks | Entry point × category |

Modes change how many subagents run and how detailed the ledger is, **never how much code is read**. Every mode
reads every in-scope module and follows its inputs to their sinks. Never skip or defer in-scope code to save time
or tokens; a unit may be `deferred` only when the user stops the run.

`deep` takes several times longer and consumes much more tokens than `standard`. If the user asks for "thorough" or "full" without
saying "deep", use `standard`, and mention in one line at the end that `deep` exists. In the multi-repository
sections below and in `report/REPORT.md`, "deep review" means an in-depth review as opposed to a breadth sweep; it
never selects `deep` mode.

## Steps

0. **Start the clock.** Run `python -I <skill folder>/method/run_stats.py --start` and keep the printed value.
   If the session shows a remaining token budget (a "tokens left" figure), note it too. Do this before anything
   else, including in `diff` mode.
1. **Pick the repositories.** Use the repositories or directory the user named; otherwise the current directory.
   - If it is a git repository (or inside one), review that repository.
   - If it is not a git repository but contains several (direct subdirectories with their own `.git`, such as a
     workspace of service clones), or the user named several, this is a **multi-repository review**: list each
     repository with its current branch and follow "Multi-repository reviews" below. Skip directories that are not
     code repositories (docs, credentials, prebuilt jars) unless asked.
   - If it is neither, ask which repository to review.

   Run every git command and tool inside the repository it concerns (`git -C <repo> ...`), check its current
   branch first, and report paths relative to its root (prefixed with the repository name in a multi-repository
   review).
2. **Identify the stack.** For each repository, read its manifests and record languages, frameworks, versions and
   layer (back end, web front end, mobile app, or several), as `00-overview.md` describes. Pick the stack files
   whose `detect` front matter matches; a repository can match several. In `standard` and `deep`, then build the
   inventory: `python -I <skill folder>/method/inventory.py <repo> --out ~/.appsec-review/<repo>/inventory.json`
   (add `--only <path>` for an endpoint or files review). Compare the stacks it detected with yours and re-run it
   with `--stack <name>` for any it missed. Its entry points and sinks are the fixed starting list for steps 5
   and 6; the stack files' entry point lists still apply to what the patterns can't see.
3. **Scope.** Use what the user named. If they named nothing, review the current branch's changes against its base
   branch (`git merge-base HEAD <base>`; use `develop` when it exists, else `main`) plus uncommitted changes. A
   multi-repository review covers each whole repository unless the user narrowed it. For a whole-repo or
   single-endpoint review, start from the entry points the stack file lists (routes, handlers and controllers;
   for front ends and apps, routes, screens, API clients, deep links and message listeners) and follow each input
   to its sinks. Read the workspace and
   repository `CLAUDE.md`/`AGENTS.md` and the repository's own docs for its conventions before judging them.
4. **Load rules.** Read `00-overview.md`, then each category file whose `paths` front matter matches a file in
   scope (match against paths inside the reviewed repository), then the stack files picked in step 2. Skip
   categories with no matching files. A category file that also has `detect` front matter (`ai-llm-agents.md`)
   loads only when a manifest matches it. In `deep` mode only, also read each `rules/deep/` playbook whose
   `parent` category is loaded and whose `when` front matter matches code in scope, and follow its method for
   that category. If no stack file fits, use the framework's own documentation and say so.
   Read a method file only when its step runs: `method/coverage-ledger.md` at step 5 (not in `diff` mode),
   `method/hunters.md` at step 6, `method/verifier.md` at step 8. Read `report/` only when a report is asked for.
5. **Seed the coverage ledger** (`standard` and `deep` only). Seed the units from the inventory, map the trust
   boundaries and any entry points the inventory missed, then write the ledger units at the mode's granularity,
   plus the hunter units, as `method/coverage-ledger.md` describes. If a ledger from an earlier run exists, start from it and follow its "Later runs" rules.
6. **Assess, with the hunters in parallel.** Start the hunters as `method/hunters.md` says for the mode (wildcard
   and obvious-things inline in `diff` and as one subagent in `standard`; in `deep`, one subagent for those two
   and one sink-trace subagent working back from the inventory's sinks). Meanwhile follow `00-overview.md`: identify
   trust boundaries and data classes, run the STRIDE pass, then check each matching rule against the code. Read
   the helpers, middleware, filters, guards, interceptors and config the code depends on before deciding. Don't
   judge a diff hunk in isolation. For changed code, also run the history, callers and tests checks in
   `00-overview.md` ("Reviewing a change"). Close each ledger unit with the paths you read and one line per check.
   Everything you find at this stage is a **candidate**, not yet a finding.
7. **Optional tools.** If they're installed, run them from each repository's directory to back up the review and
   add their real hits as candidates. Never install them without asking:
   - `gitleaks detect --no-banner` for secrets, including history
   - `trivy fs --scanners vuln,secret,misconfig .` or `osv-scanner -r .` for dependencies and IaC, in any language
   - the ecosystem's own audit: `npm audit --omit=dev` / `pnpm audit` / `yarn npm audit`, `pip-audit`,
     `govulncheck ./...`, `dotnet list package --vulnerable`, `mvn org.owasp:dependency-check-maven:check`
   - `semgrep --config p/secrets` plus the packs for the stack: `p/java`, `p/typescript`, `p/javascript`,
     `p/react`, `p/nextjs`, `p/nodejsscan`, `p/python`, `p/django`, `p/flask`, `p/golang`, `p/csharp`, `p/kotlin`,
     `p/swift`
8. **Verify.** Merge your candidates, the hunters' and the tools' by root cause, then verify them as
   `method/verifier.md` says for the mode: a disproof pass for all, plus fresh verifier subagents where the mode
   calls for them. The verifier's decision stands: `confirmed` and `hardening`
   become findings, `needs_confirmation` is reported with the exact missing fact, `rejected` is dropped. Never
   verify your own candidates in the same pass that found them.
9. **Close the ledger** (`standard` and `deep` only). Link the verified findings, run the gap pass, and validate with
   `python -I <skill folder>/method/ledger.py <ledger> --inventory <inventory>`. Fix every error before writing
   the result. A candidate
   the gap pass turns up goes through step 8 before it is reported.

## Multi-repository reviews

Review each repository in depth first; build the combined result only from those deep reviews.

1. **Inventory.** List every repository with its branch, size and entry points, and order them by risk:
   authentication and identity, money movement, card data, shared providers and gateways, then the rest
   (front ends and apps after the back ends they call, so their findings can point at the server checks). A quick
   sweep across all repositories is allowed only to spot shared code (copied configuration, common libraries,
   identical helpers) to watch for. It never replaces a deep review and never feeds a published report on its own.
2. **In-depth review, one repository at a time.** Run steps 2 to 9 on the whole repository, in `standard` mode
   unless the user asked for `deep`. Run the hunter and verifier subagents per repository, not per finding: every entry point the
   stack file lists, middleware, filters, guards and interceptors, services, outbound clients, models and DTOs, UI
   code and app configuration for front ends and apps, configuration for every profile or environment, build and
   package files, CI workflows and container files, and the git history of configuration files. Record the controls
   you verified as secure as well as the findings.
3. **Classify each finding.** If the same weakness comes from code or configuration shared by more than one
   repository, report it once as a platform-wide finding that lists every affected repository and location. When
   a later repository shows a pattern already reported, add its locations to that finding instead of creating a
   new one, and move an earlier repository finding to platform-wide when it reappears. Everything else stays with
   its repository.
4. **Merge after each repository.** Update the combined result as soon as a repository's deep review is done:
   terminal output grouped as platform-wide first, then one group per repository; for a report, follow the
   multi-repository rules in `report/REPORT.md`, publish after the first repository, and update the same artifact
   after each later one (unless the user asked for one report at the end). Re-check scores so the same issue has
   the same vector in every repository.
5. **Reusing earlier reports.** When a standalone report for one of the repositories already exists, verify each of
   its findings against the current code before merging it, and rescore it under the shared rules.
6. **Unfinished work.** If a repository could not be deep-reviewed, say so in the result ("breadth only, deep
   review pending") instead of presenting its section as complete.

Keep the working finding data outside the reviewed repositories (a scratch or temporary folder), with symbolic ids
for cross-references, because finding numbers change as sections grow. Each repository keeps its own coverage
ledger; a platform-wide finding uses one finding key, linked from units in every affected repository's ledger.

## Output

- Order findings by severity (`critical`, `bug`, `warning`, `suggestion`), using the title format from
  `00-overview.md`: `[Security] <issue> (<OWASP/API/CWE ref>)`. In a multi-repository review, group them as
  platform-wide first, then by repository, and order by severity within each group.
- For each finding give `file:line`, the attack (preconditions, request, result), the impact, and a concrete fix
  that uses the codebase's existing helpers and conventions.
- "Needs confirmation" findings stay in the main list, placed by the severity they have if confirmed, with a label
  such as `critical if confirmed` and the exact fact to confirm.
- Give two counts: root causes (findings) and affected locations (one root cause can appear in several files),
  so runs can be compared with reports that counted each location separately.
- End with a short list of what was checked and found clean, and anything out of scope or not verifiable. Add a
  one-line coverage summary from `method/ledger.py` in `standard` and `deep` (units covered, finding, blocked,
  deferred), and how each finding was verified (independent verifier or self-verified disproof pass).
- List the candidates **rejected by verification** after that: title, `file:line`, the verifier's reason and the
  disproof line. The user can overrule a wrong rejection.
- Finish every run, including one stopped early or failed, with the run summary below.

### Run summary

The last block of every result:

```
Run summary
- Mode: <diff|standard|deep>
- Time: <python -I <skill folder>/method/run_stats.py <start value>>
- Tokens: <python -I <skill folder>/method/run_stats.py --tokens <budget at start> <budget at end> <tokens per subagent ...>>
- Subagents: <number started, by role and model>
- Findings: <root causes> root causes across <locations> locations; <n> rejected by verification
- <mode note>
```

- **Tokens.** The main-session figure is the drop in the session's remaining token budget; pass `-` for both
  budgets when the session shows none. Subagent figures are the token counts the Agent tool reports for each
  subagent. Never estimate a figure; leave out what isn't reported, and add "exact usage: `/cost` or `/usage`".
- **Mode note** for the mode that ran:
  - `diff`: "For a whole repository use `standard` (`/appsec-review whole repo`). `deep` (`/appsec-review deep`)
    covers more but takes several times longer and consumes much more tokens."
  - `standard`: "For high-stakes code use `deep` (`/appsec-review deep`): it covers more, but takes several times
    longer and consumes much more tokens. For a PR or branch, `diff` is the fastest: `/appsec-review` on its own
    reviews the current branch against its base plus uncommitted changes, or name a branch (for example
    `/appsec-review feature/login against main`)."
  - `deep`: "This run consumed much more time and tokens than `standard` would. For routine reviews use `standard`
    (`/appsec-review whole repo`), or `diff` for a PR or branch: `/appsec-review` on its own reviews the current
    branch against its base plus uncommitted changes, or name a branch (for example
    `/appsec-review feature/login against main`)."
- In a multi-repository review, also give the time for each repository (start a new timer value for each).
- Never print secret values, card numbers, CVVs, OTPs or tokens. Refer to them by location only.
- Report only. Change code only when the user asks for fixes, and then update or add the matching negative tests.

## CI gate

The review itself never stops early and never fails a pipeline: every run finishes its scope, and the result is
the same whether it finds nothing or many issues. To gate a pipeline, a CI step checks the finished ledger
afterwards: `python -I <skill folder>/method/ledger.py <ledger> --inventory <inventory> --fail-on <severity>`.
It exits 3 when a reported finding is at or above that severity (`critical`, `bug`, `warning` or `suggestion`),
1 when the ledger is invalid or misses inventory coverage, and 0 otherwise. `needs_confirmation` findings count
by `severity_if_confirmed`; rejected findings never count. `--accepted <file>` waives findings a team accepted,
each until an expiry date and up to a severity, and `--sarif <file>` exports the findings for code scanning
(`docs/ci-pipeline.md`). Never pass `--fail-on` or `--accepted` during a review run (step 9); pass `--sarif` after
step 9 only when the user asks for SARIF, and write the file where they say. Never write or change an
accepted-risk file unless the user asks, and never shorten a review because a critical finding turned up.

## Report

When the user asks for a report (a page, artifact, export or document of the findings), read `report/REPORT.md`
and follow it exactly:

- Use its section structure (1.0 Document Control to 6.0 Recommendation) and finding card fields, and its
  multi-repository rules when more than one repository is in scope.
- State the security standards the review is based on in 2.4 (REPORT.md "Security standards") and give every
  finding its References. Include ASVS V3, WSTG-CLNT and RFC 10017 for browser findings, and MASVS, MASTG,
  MASWE, Mobile Top 10 and RFC 8252 for mobile findings, plus PCI DSS, NIST SP 800-63B-4 or RFC 9700 where
  they apply.
- Score every finding with a CVSS 3.1 base vector and rate it by the CVSS band. Compute each score with
  `python -I <skill folder>/report/cvss31.py "<vector>"`; never estimate.
- Build the page from `report/report-template.html`, keeping its CSS and layout and replacing only the content.
- Publish it privately and warn before wider sharing, because it contains attack details for open issues.

## Maintaining the skill

Changing the skill (rules, stacks, inventory patterns, scripts, benchmarks) is covered in `CONTRIBUTING.md` in the
skill folder. Don't read it during a review.
