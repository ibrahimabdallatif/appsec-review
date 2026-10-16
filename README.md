# appsec-review

A Claude Code skill for manual security reviews and pentest-style assessments of back-end, web front-end and
mobile code, in any language or framework. It reviews a diff, branch, PR, file, endpoint, a whole repository, or
every repository under a directory, and reports verified findings with attack scenarios, impact and concrete fixes.

The skill runs only when invoked explicitly (`disable-model-invocation: true`); it is never triggered
automatically or as part of a PR check.

## Standards covered

- OWASP Top 10:2025 and OWASP API Security Top 10:2023
- OWASP ASVS 5.0, including V3 Web Frontend Security, and WSTG-CLNT
- OWASP MASVS, MASTG, MASWE and Mobile Top 10:2024
- CWE Top 25
- PCI DSS
- NIST SP 800-63B-4
- RFC 9700 (OAuth security BCP), RFC 8252 (OAuth for native apps), RFC 10017 (OAuth for browser-based apps)

## Installation

Clone the repository into your Claude Code skills folder:

```sh
git clone https://github.com/ibrahimabdallatif/appsec-review.git ~/.claude/skills/appsec-review
```

The skill is then available in every Claude Code session. Python 3 is needed for the helper scripts.

## Usage

```
/appsec-review                               # current branch vs. its base, plus uncommitted changes
/appsec-review feature/login against main    # a branch or PR
/appsec-review src/payments/                 # specific files or folders
/appsec-review whole repo                    # the whole repository (standard mode)
/appsec-review deep                          # in-depth review (deep mode)
/appsec-review ~/work/services               # every repository under a directory
/appsec-review whole repo, write a report    # adds a published HTML report
```

### Review modes

| Mode | When | Subagents | Coverage ledger |
|---|---|---|---|
| `diff` | Default; a diff, branch, PR or files | None, except one verifier for a surviving `critical` | None |
| `standard` | A whole repository, an endpoint, or several repositories | One combined hunter and one batch verifier | Module × category |
| `deep` | Only when the user explicitly asks for "deep" | Two hunters (wildcard/obvious-things and a backward sink tracer), one verifier per `critical`/`bug` candidate, plus the deep playbooks | Entry point × category |

Every mode reads all in-scope code and follows each input to its sinks; modes only change how many subagents run
and how detailed the ledger is. `deep` takes several times longer and uses much more tokens than `standard`.

## How a review runs

1. Start a run timer and note the token budget.
2. Pick the repositories (single or multi-repository review).
3. Identify the stack from manifests, pick matching stack rules, and build a scripted inventory of entry points
   and sinks (`method/inventory.py`), so every run starts from the same list.
4. Set the scope and load the category rules whose `paths` match files in scope.
5. Seed the coverage ledger (`standard` and `deep`).
6. Assess the code (trust boundaries, STRIDE, rule checks) forward from each entry point, while hunters run in
   parallel: wildcard and obvious-things, and in `deep` a sink tracer working backward from every sink.
7. Optionally run installed tools: gitleaks, trivy/osv-scanner, ecosystem audits, semgrep.
8. Verify every candidate with a disproof pass and, depending on the mode, independent verifier subagents.
9. Close the ledger and validate it against the inventory (every entry point has a unit, every sink file was read), then report.

Findings are ordered by severity (`critical`, `bug`, `warning`, `suggestion`), each with `file:line`, the attack,
the impact and a fix that uses the codebase's own helpers. Rejected candidates are listed with the verifier's
reason so they can be overruled. Every run ends with a run summary (mode, time, tokens, subagents, counts).
Secret values, card numbers, OTPs and tokens are never printed.

## Repository layout

| Path | Contents |
|---|---|
| `SKILL.md` | The skill definition: modes, steps, output and report rules |
| `rules/00-overview.md` | Method, STRIDE pass, severity scale and reporting format |
| `rules/*.md` | Framework-neutral category checklists: access control, authentication and sessions, injection, cryptography and data protection, business logic, configuration and supply chain, logging, client side, AI/LLM agents, web protocol and identity |
| `rules/stacks/*.md` | Framework add-ons: Java/Spring, Node, web front end, mobile, Python, .NET, Go |
| `rules/deep/*.md` | `deep`-mode playbooks: object-level authorization, payment callbacks, payment state and idempotency, race conditions, business-logic flaws |
| `method/` | Coverage ledger, hunter and verifier prompts, `inventory.py` (entry points and sinks by script), `ledger.py` validator and `run_stats.py` timer |
| `report/` | Report structure (`REPORT.md`), CVSS 3.1 calculator (`cvss31.py`) and HTML template |
| `evals/` | `benchmark.py`, which scores one run, or several runs for stability, against known findings |

## Reports

Ask for a report and the skill builds an HTML page from `report/report-template.html`, with document control,
the standards used, CVSS 3.1 scored findings (computed by `report/cvss31.py`, never estimated) and
recommendations. Reports are published privately, since they contain attack details for open issues.

## CI gate

The review always runs to completion. To fail a pipeline on its results, check the finished ledger afterwards:

```sh
python -I method/ledger.py ~/.appsec-review/<repo>/coverage-ledger.json \
  --inventory ~/.appsec-review/<repo>/inventory.json --fail-on critical
```

Exit codes: `0` pass, `3` a finding at or above the given severity (`critical`, `bug`, `warning`, `suggestion`;
"needs confirmation" findings count by their severity if confirmed), `1` invalid ledger or missing coverage,
`2` bad arguments.

## Development

Run the tests after changing the helper scripts:

```sh
python -I method/test_ledger.py
python -I method/test_run_stats.py
python -I method/test_inventory.py
python -I evals/test_benchmark.py
python -I report/cvss31.py --selftest
```

After changing `rules/`, `method/` or the steps, re-run the skill against a benchmark repository and score it
with `evals/benchmark.py` to make sure no known finding is lost. Pass several fresh runs' ledgers to see which
findings are found in every run and which only sometimes. See "Maintaining the skill" in `SKILL.md`.

## Credits

Parts of this skill are adapted from MIT-licensed projects by Cloudflare, Vasiliy Uvarov, Riyan Dhiman and
Mohamed AboElKheir, with ideas inspired by Trail of Bits. See [NOTICE.md](NOTICE.md) for details.
