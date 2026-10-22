<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.png">
    <img alt="appsec-review logo" src="docs/assets/logo-light.png" width="128" height="128">
  </picture>
</p>

<h1 align="center">appsec-review</h1>

<p align="center">
  <b>Threat-model-driven security reviews: full attack surface coverage, every finding verified by an independent pass and scored with CVSS 4.0.</b><br>
  Claude Code, Cursor and Codex load this one skill folder. Spring, Node.js, Python, PHP, .NET and Go back ends, browser front ends, mobile apps, Supabase and Firebase,
  CI pipelines, containers and infrastructure as code.
</p>

<p align="center">
  <a href="https://github.com/ibrahimabdallatif/appsec-review/actions/workflows/tests.yml"><img src="https://github.com/ibrahimabdallatif/appsec-review/actions/workflows/tests.yml/badge.svg" alt="tests"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT license"></a>
  <img src="https://img.shields.io/badge/skills-Claude%20Code%20%C2%B7%20Cursor%20%C2%B7%20Codex-d97757" alt="Claude Code, Cursor and Codex skill">
  <img src="https://img.shields.io/badge/OWASP-Top%2010%3A2025-000000" alt="OWASP Top 10:2025">
  <img src="https://img.shields.io/badge/python-3.10%2B-3776ab" alt="Python 3.10+">
</p>

<p align="center">
  <a href="docs/getting-started.md">Getting started</a> ·
  <a href="docs/platforms.md">Platforms</a> ·
  <a href="docs/how-it-works.md">How it works</a> ·
  <a href="docs/ci-pipeline.md">CI pipeline</a> ·
  <a href="https://ibrahimabdallatif.github.io/appsec-review/sample-report.html">Sample report</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/pipeline-dark.svg">
  <img alt="Pipeline: attack surface inventory, threat model with abuse paths, STRIDE assessment in three directions, adversarial verification by a second agent, proven findings with CWE, CVSS 4.0 and SARIF" src="docs/assets/pipeline-light.svg">
</picture>

## 🧭 Why it's different

<table>
  <tr>
    <td width="50%"><b>Attack surface mapped by script.</b><br>A scripted inventory lists every entry point and dangerous sink. The ledger validator fails the run if any of them was skipped, so every run covers the same attack surface.</td>
    <td width="50%"><b>Threat-model driven.</b><br>Trust boundaries, data classes and a STRIDE pass, then abuse paths worked as an attacker would, either to the goal or to the line that stops them. Verified findings are chained into worse end-to-end exploits.</td>
  </tr>
  <tr>
    <td><b>Findings are disproved, not just found.</b><br>A fresh verifier agent that never sees the finder's reasoning tries to refute each candidate. A rejection must cite the line of code that stops the attack, and rejected candidates are listed so you can overrule them.</td>
    <td><b>It knows your framework.</b><br>Rules for Spring, Node, Python, PHP (Laravel, Symfony, WordPress), .NET, Go, web front ends, mobile apps, Supabase/Firebase, and CI, Docker, Kubernetes and Terraform, plus deep playbooks for BOLA/IDOR, payment callbacks, idempotency and race conditions.</td>
  </tr>
  <tr>
    <td><b>Audit-ready output.</b><br>Each finding gives <code>file:line</code>, the exploit path, the impact and a fix using your own helpers, mapped to OWASP, ASVS, MASVS, CWE and PCI DSS. CVSS 4.0 vectors are computed by script, never estimated.</td>
    <td><b>Built for the pipeline.</b><br><code>--fail-on &lt;severity&gt;</code> gates merges, accepted risks expire on a date, and SARIF 2.1.0 export feeds GitHub code scanning or Jenkins.</td>
  </tr>
</table>

## ⚖️ How it compares

appsec-review adapts its hunters, verifier and coverage ledger from Cloudflare's
[security-audit](https://github.com/cloudflare/security-audit-skill) ([NOTICE.md](skills/appsec-review/NOTICE.md)). It is also compared
with Claude Code's built-in [`/security-review`](https://github.com/anthropics/claude-code-security-review). All
three make an agent try to disprove a finding before it is reported. They are built for different jobs:

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/comparison-dark.svg">
  <img alt="Comparison of appsec-review, Claude Code /security-review and Cloudflare security-audit" src="docs/assets/comparison-light.svg">
</picture>

Use appsec-review for PR reviews, web, API, mobile and Supabase/Firebase apps, audit deliverables, CI gates and a
predictable cost. Use `/security-review` for a quick, zero-setup check of a branch's high-confidence issues. Use
security-audit for native code, messaging-heavy systems, proving bugs by running the code, or the widest coverage of
a large codebase when cost matters less.

<sub>Compared in October 2026 with security-audit at commit `c1c8a8c` and claude-code-security-review at commit
`0c6a49f`.</sub>

## ✨ Features

### 🔍 Code review engine

- **Scripted inventory**: lists every route, handler, resolver, consumer, screen, deep link, CI pipeline,
  internet-facing resource and dangerous sink per stack, so each run starts from the same ground
  (`method/inventory.py`)
- **Forward and backward assessment**: follows each input from entry point to sink, while a sink tracer works back
  from every dangerous call (`deep`)
- **STRIDE and threat model**: trust boundaries, data classes, attacker goals and abuse paths, each worked to its
  goal or to the line that stops it
- **Change-aware diff review**: finds the commit that added a removed control, reads the callers of changed
  helpers, and flags security controls without a negative test
- **Library-aware**: reads the source of the locked dependency version instead of guessing what it does
- **Chain pass**: combines verified findings into worse end-to-end outcomes and verifies each hand-off

### 🧪 Vulnerability coverage

- **Access control**: IDOR/BOLA, function-level authorization, mass assignment, multi-tenancy, SSRF
- **Authentication and sessions**: JWT, OAuth and OIDC, step-up and OTP, passwords, session handling, SAML,
  WebAuthn and passkeys, MFA downgrade, account recovery and linking, API keys, mTLS
- **Injection and input**: SQL and LIKE, command, expression language, CRLF, XXE, deserialization, file handling
- **Business logic**: workflow integrity, money movement, payment callbacks, idempotency, race conditions, replay,
  enumeration, resource limits
- **Web protocol**: request smuggling, cache poisoning and deception, host and forwarded-header trust
- **Client side**: DOM XSS, token storage, CSP, deep links, WebViews, mobile storage and platform APIs
- **Cryptography and data**: secrets, crypto misuse, TLS, card and personal data (PCI DSS)
- **Configuration and supply chain**: exposed tooling, headers and cookies, dependencies, CI, containers, IaC
- **AI and LLM agents**: dangerous capability combinations, tool authorization, MCP identity, RAG and memory tenant
  isolation, model output handling, spend limits
- **Logging and errors**: missing security events, secrets in logs, verbose errors, fail-open handling

### 🤖 Independent verification

- **Hunters**: wildcard, obvious-things and sink-trace subagents look for what the main pass missed
- **Fresh verifiers**: a subagent that never saw the finder's reasoning tries to disprove each candidate
- **Rejection review**: every rejected `critical` or `bug` candidate gets a second, independent look
- **Transparent rejections**: rejected candidates are listed with the line that disproves them, so you can
  overrule them

### 📊 Reporting and CI

- **Audit-ready report**: private HTML report with executive summary, threat model, remediation plan and appendix,
  plus a Markdown copy to feed to another session, both saved locally with their paths printed
- **CVSS 4.0 by script**: every score computed by `report/cvss40.py`, never estimated
- **Coverage ledger**: entry point × category units, validated against the inventory by `method/ledger.py`
- **CI gate and SARIF**: `--fail-on <severity>`, time-limited accepted risks, SARIF export for code scanning
- **Multi-repository reviews**: findings shared across repositories reported once as platform-wide
- **Benchmarks**: `evals/benchmark.py` scores runs against known findings and decoys

## 🧱 Supported stacks

| Stack | Frameworks |
|---|---|
| Java and Kotlin | Spring Boot, MVC, WebFlux, Security, Data |
| Node.js and TypeScript | NestJS (REST and GraphQL), Express, Fastify, Koa, Hapi, Hono, and server code in Next.js and other full-stack frameworks |
| Python | Django, Django REST Framework, FastAPI, Flask, Starlette |
| PHP | Laravel (with Livewire), Symfony, WordPress, Slim, CodeIgniter, CakePHP, Laminas |
| .NET | ASP.NET Core MVC, Web API, minimal APIs, Blazor |
| Go | net/http, Gin, Echo, Fiber, chi, gRPC |
| Browser front ends | React, Next.js, Angular, Vue, Nuxt, Svelte, Solid, Astro |
| Mobile | React Native, Expo, Flutter, native Android and iOS |
| Backend as a service | Supabase, Firebase |
| CI, containers and IaC | GitHub Actions, GitLab CI, Jenkins, Docker, Kubernetes, Helm, Terraform |

Each stack has a rule file in `rules/stacks/` and inventory patterns that list its entry points and sinks. Code
in other stacks gets only the general category checks, without a scripted inventory, so coverage is weaker; the
report says when no stack file matched.

## 🛡️ Standards covered

> [!IMPORTANT]
> Every finding is mapped to the standards below, and the report lists the ones each review was based on.

| Standard | Used for |
|---|---|
| **OWASP Top 10:2025** | Web application risk categories |
| **OWASP API Security Top 10:2023** | API risks: BOLA, broken function-level authorization, mass assignment |
| **OWASP ASVS 5.0** (incl. V3 Web Frontend Security) | Verification requirements for back ends and browser front ends |
| **OWASP WSTG-CLNT** | Client-side testing for web front ends |
| **OWASP MASVS, MASTG, MASWE** | Mobile app security requirements and testing |
| **OWASP Mobile Top 10:2024** | Mobile risk categories |
| **CWE Top 25** | Root-cause weakness IDs on every finding |
| **PCI DSS** | Card data handling and payment flows |
| **NIST SP 800-63B-4** | Passwords, authenticators and session rules |
| **RFC 9700** | OAuth 2.0 security best current practice |
| **RFC 8252** | OAuth 2.0 for native apps |
| **RFC 10017** | OAuth 2.0 for browser-based apps |
| **CVSS 4.0** | Severity scoring, computed by script |

## 🚀 Quick start

Install the skill once, then invoke it inside the repository you want reviewed. Exact commands, sequential
mode and the test boundary are in [docs/platforms.md](docs/platforms.md).

```sh
python -I skills/appsec-review/method/install_links.py
```

That links `skills/appsec-review/` into the Claude Code, Cursor and Codex user skill directories. It does not
copy the methodology. Or copy via the skills CLI (this writes a snapshot, not a link):

```sh
npx skills add ibrahimabdallatif/appsec-review --skill appsec-review -g -a claude-code -a cursor -a codex -y
```

| Host | Invoke |
|---|---|
| Claude Code | `/appsec-review` |
| Cursor | `/appsec-review` |
| Codex | `/skills`, then appsec-review, or `$appsec-review` |

```
/appsec-review                               # current branch vs. its base, plus uncommitted changes
/appsec-review whole repo                    # the whole repository
/appsec-review deep                          # in-depth review for high-stakes code
```

Add "sequential" to skip subagents. The same steps still run.

> [!TIP]
> Start with a plain `/appsec-review` on a branch. It is the fastest mode and shows you the output format before
> you spend time on a whole repository. More commands: [Getting started](docs/getting-started.md).

The skill runs only when you invoke it (`disable-model-invocation: true` on Claude Code and Cursor). Codex
does not document that flag; the description tells it not to run for a general security question.

## 🧩 Compatibility

What is implemented is the shared skill, the discovery adapters, and the scripts. What was executed in this
change is the Python test suite. Live skill invocation was not re-run on each host; details and versions are
in [docs/platforms.md](docs/platforms.md).

| Requirement | Details |
|---|---|
| **Claude Code** | Skills and subagents. Project adapter `.claude/skills/appsec-review/`. User install `~/.claude/skills/appsec-review`. Headless CI example: `claude -p` in [docs/ci-pipeline.md](docs/ci-pipeline.md) |
| **Cursor** | Project adapters `.cursor/skills/appsec-review/` and `.agents/skills/appsec-review/`. User install `~/.cursor/skills/appsec-review`. Subagents when the session can spawn them; otherwise the sequential fallback |
| **Codex** | Project adapter `.agents/skills/appsec-review/`. User install `~/.agents/skills/appsec-review` and `~/.codex/skills/appsec-review`. Subagents when the session can spawn them; otherwise the sequential fallback |
| **Python** | 3.10+ on your `PATH` as `python`, for the helper scripts (standard library only, tested on 3.10 and 3.13) |
| **Git** | Needed for diff, branch and PR reviews and for multi-repository discovery |
| **Node.js** | Only to install with `npx skills add`. Not required for `install_links.py` or for a review |
| **OS** | Linux, macOS and Windows (tests run on Linux and Windows) |
| **Optional tools** | gitleaks, trivy or osv-scanner, semgrep, your ecosystem's audit tool and, for pipelines and infrastructure, zizmor, actionlint, checkov and hadolint; used when installed, never installed by the skill |
| **Report publishing** | Local HTML and Markdown always, under `~/.appsec-review/<repo>/`. A private claude.ai artifact only when you explicitly ask, and only on Claude Code. Cursor and Codex do not publish |

## 🎚️ Modes

| Mode | Use it for | Subagents | Coverage ledger |
|---|---|---|---|
| `diff` | A branch, PR or files (default) | None, except one verifier for a surviving `critical` | None |
| `standard` | A whole repository, an endpoint, or several repositories | One hunter, one batch verifier, one reviewer for rejected serious candidates | Module × category |
| `deep` | High-stakes code, only when you say "deep" | Two hunters (incl. a backward sink tracer), one verifier per serious candidate | Entry point × category |

Every mode reads all in-scope code and follows each input to its sinks; modes change how many agents run and how
detailed the ledger is. Say "sequential", or set `APPSEC_REVIEW_PARALLEL=0`, to run those agent steps in the
same session. `deep` takes several times longer and uses much more tokens than `standard`.

## 📋 What you get

Findings ordered by severity (`critical`, `bug`, `warning`, `suggestion`), each one like this (illustrative):

```
[Security] Order id not bound to caller (API1, CWE-639)        critical
src/orders/OrderController.java:42

Attack: any signed-in user sends GET /orders/{id} with another customer's order id.
Impact: read access to every customer's orders.
Fix:    load through orderRepository.findByIdAndCustomerId(id, principal.customerId()).
```

Then the "needs confirmation" findings with the exact fact to check, what was checked and found clean, the
coverage summary, the candidates rejected by verification, and a run summary with time and tokens.

`standard` and `deep` runs also write a report (a `diff` run asks first) with CVSS 4.0 scores and standards references for each finding to
`~/.appsec-review/<repo>/`: `report.html` for people and `report.md`, the same content in Markdown, to feed to
another session ("read report.md and fix finding 4.1.2"). The run ends by printing where the local files are.
A private claude.ai artifact is added only when you ask to publish, and only from Claude Code:

```
Report
- HTML: C:\Users\<you>\.appsec-review\cards-service\report.html
- Markdown: C:\Users\<you>\.appsec-review\cards-service\report.md
```

CI and other headless runs write the same local files and do not publish.

## 🔁 In CI

The review always runs to completion. A separate gate reads the finished ledger and fails the build on findings at
or above a severity:

```sh
python -I <skill folder>/method/ledger.py ~/.appsec-review/<repo>/coverage-ledger.json \
  --inventory ~/.appsec-review/<repo>/inventory.json --fail-on critical
```

Exit codes: `0` pass, `3` blocking findings, `1` incomplete review or invalid ledger, `2` bad arguments. Add
`--accepted <file>` to waive findings the team has accepted, each until an expiry date and up to a severity;
waived findings are still printed. `--sarif <file>` exports the findings for GitHub code scanning or Jenkins.
Agent setup, accepted risks, SARIF, a Jenkins example and scheduling advice:
[docs/ci-pipeline.md](docs/ci-pipeline.md).

> [!WARNING]
> Ledgers, inventories and reports describe how to attack open issues. They are kept in `~/.appsec-review/`,
> outside your repository. Nothing is published unless you ask. Check who can see a report before sharing.

## 📚 Reference

<details>
<summary><b>🪜 How a review runs, step by step</b></summary>

1. Start a run timer (paused while waiting for the user) and note the token budget.
2. Pick the repositories (single or multi-repository review).
3. Identify the stack from manifests, pick matching stack rules, and build the scripted inventory of entry points
   and sinks (`method/inventory.py`).
4. Set the scope and load the category rules whose `paths` match files in scope.
5. Seed the coverage ledger, and write the threat model and abuse paths: what an attacker wants and how they
   would try to get it (`standard` and `deep`).
6. Assess the code forward from each entry point (trust boundaries, STRIDE, rule checks) while hunters run in
   parallel: wildcard and obvious-things, and in `deep` a sink tracer working backward from every sink. Then
   work each abuse path to its goal, or to the line of code that stops it.
7. Optionally run installed tools: gitleaks, trivy/osv-scanner, ecosystem audits, semgrep, and zizmor,
   actionlint, checkov or hadolint for pipelines and infrastructure.
8. Verify every candidate with a disproof pass and, depending on the mode, independent verifier subagents,
   then look for chains: findings that combine into a worse outcome, verified as a chain.
9. Close the ledger, validate it against the inventory, then report.

The full picture, with a diagram: [docs/how-it-works.md](docs/how-it-works.md).

</details>

<details>
<summary><b>🗂️ Repository layout</b></summary>

The skill itself is `skills/appsec-review/`, the folder `npx skills add` installs; paths below inside it are
relative to that folder.

| Path | Contents |
|---|---|
| `skills/appsec-review/SKILL.md` | The skill definition: modes, steps, output and report rules. This is the only copy of the methodology |
| `rules/00-overview.md` | Method, STRIDE pass, severity scale and reporting format |
| `rules/*.md` | Framework-neutral category checklists: access control, authentication and sessions, injection, cryptography and data protection, business logic, configuration and supply chain, logging, client side, AI/LLM agents, web protocol and identity |
| `rules/stacks/*.md` | Framework add-ons: Java/Spring, Node, web front end, mobile, Python, PHP, .NET, Go, Supabase and Firebase, CI pipelines, containers and IaC |
| `rules/deep/*.md` | `deep`-mode playbooks: object-level authorization, payment callbacks, payment state and idempotency, race conditions, business-logic flaws |
| `method/` | Coverage ledger, hunter and verifier prompts, orchestration, `inventory.py`, `ledger.py` validator and CI gate, `accepted_risks.py`, `sarif.py`, `run_stats.py`, `parallel_mode.py`, `install_links.py` |
| `report/` | Report structure and Markdown copy rules (`REPORT.md`), CVSS 4.0 calculator (`cvss40.py`), HTML template, the logos in `assets/` and `embed_logos.py`, which embeds them in each report, and `build_sample.py`, which builds the sample report from the fictional fixture in `sample/` |
| `docs/` | Getting started, platforms, how it works, CI pipeline guide, the README images, and the sample report (Markdown, and HTML served on GitHub Pages) |
| `.claude/skills/appsec-review/`, `.cursor/skills/appsec-review/`, `.agents/skills/appsec-review/` | Thin discovery adapters. They point at `skills/appsec-review/` and are not a second methodology |
| `evals/` | `benchmark.py`, which scores one run, or several runs for stability, against known findings |
| `NOTICE.md`, `LICENSE` | Third-party notices and the license, shipped with the skill so every install carries them |
| `.github/workflows/tests.yml` | Runs every test suite on Linux and Windows on each push and pull request |

</details>

<details>
<summary><b>🛠️ Development</b></summary>

Run the tests after changing the helper scripts (GitHub Actions runs the same commands on every push):

```sh
python -I skills/appsec-review/method/test_inventory.py
python -I skills/appsec-review/method/test_ledger.py
python -I skills/appsec-review/method/test_accepted_risks.py
python -I skills/appsec-review/method/test_sarif.py
python -I skills/appsec-review/method/test_threat_model.py
python -I skills/appsec-review/method/test_run_stats.py
python -I skills/appsec-review/method/test_parallel_mode.py
python -I skills/appsec-review/method/test_install_links.py
python -I skills/appsec-review/method/test_layout.py
python -I skills/appsec-review/evals/test_benchmark.py
python -I skills/appsec-review/report/test_cvss40.py
python -I skills/appsec-review/report/cvss40.py --selftest
python -I skills/appsec-review/report/test_embed_logos.py
python -I skills/appsec-review/report/test_build_sample.py
```

After changing `rules/`, `method/` or the steps, score the skill against a benchmark repository with
`evals/benchmark.py`, over several fresh runs, to make sure no known finding is lost or only found sometimes. See
[CONTRIBUTING.md](CONTRIBUTING.md).

</details>

## 📄 Credits and license

MIT, see [LICENSE](LICENSE). Parts of this skill are adapted from MIT-licensed projects by Cloudflare, Vasiliy
Uvarov, Riyan Dhiman and Mohamed AboElKheir, with ideas from Trail of Bits and autoresearch; see
[NOTICE.md](skills/appsec-review/NOTICE.md).
