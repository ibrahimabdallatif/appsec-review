---
paths:
  - "**/*"
---

# Security assessment: method and reporting

This assessment runs only when someone invokes it explicitly. It has stack files for Spring, Node.js, Python,
.NET and Go back ends, browser front ends, mobile apps, Supabase and Firebase (`stacks/`). The other files in
this folder each cover one area and together map to
these standards:

- OWASP Top 10:2025 (web application risks)
- OWASP API Security Top 10:2023 (API risks)
- OWASP ASVS 5.0 (verification requirements, chapters V1-V16). V3 Web Frontend Security applies whenever a
  browser renders the application: content interpretation, cookie setup, browser security headers, origin
  separation and subresource integrity
- OWASP MASVS 2.1, tested with MASTG 2.0 and weakness ids from MASWE 1.0. Control groups: STORAGE, CRYPTO,
  AUTH, NETWORK, PLATFORM, CODE, RESILIENCE and PRIVACY
- OWASP Mobile Top 10:2024 (M1 credentials, M2 supply chain, M3 authentication and authorization, M4 input and
  output validation, M5 communication, M6 privacy, M7 binary protections, M8 misconfiguration, M9 data storage,
  M10 cryptography)
- MITRE/CISA CWE Top 25:2025 (most dangerous weaknesses)
- OWASP WSTG (penetration testing categories, including WSTG-CLNT for the browser)
- PCI DSS v4.0 req. 6.2.4 (common attacks in software handling cardholder data)
- NIST SP 800-63B-4 (passwords and authenticators), RFC 9700 (OAuth 2.0 Security Best Current Practice),
  RFC 8252 (OAuth 2.0 for Native Apps) and RFC 10017 (OAuth 2.0 for Browser-Based Applications)
- RFC 9110, RFC 9111 and RFC 9112 (HTTP semantics, caching and message framing), SAML 2.0 and W3C WebAuthn
  Level 3, for `web-protocol-identity.md`
- OWASP Top 10 for LLM Applications 2025 and OWASP Top 10 for Agentic Applications 2026, for `ai-llm-agents.md`
- SLSA build provenance, CycloneDX/SPDX SBOMs and NIST SSDF (SP 800-218), for supply-chain checks

Standards change editions. These versions were current on 2026-10-16. When network access is available, check the
publisher's page for any standard you cite whose edition may have changed since then, and cite the current
edition; otherwise cite them as listed and say in report 3.2 that editions were not re-checked.
- Mozilla Web Security Guidelines (headers and cookies), CIS/Checkov-style container and IaC baselines, and the
  CISA Known Exploited Vulnerabilities catalog for prioritising dependency CVEs

## Category and stack files

- **Category files** (this folder) hold framework-neutral checks. Each one's `paths` front matter says which files
  it applies to. `client-side.md` covers web front ends (ASVS V3, WSTG-CLNT, RFC 10017) and mobile apps
  (MASVS, MASTG, MASWE, Mobile Top 10, RFC 8252).
- **Stack files** (`stacks/`) map those checks to one framework family: its entry points, authorization and
  validation constructs, query and parsing APIs, unsafe calls, tooling endpoints and dependency lines. Each one's
  `detect` front matter lists the manifest entries that select it. Load every stack file that matches the
  repository; a repository can match several (a Next.js app is both `node-backend.md` and `web-frontend.md`;
  a React Native app is `mobile.md`).
- When no stack file matches, apply the category files using the framework's own documentation, and say in the
  report's 3.2 that no stack file existed for it.

## Identify the stack

Before assessing, record for each repository:

- the languages, frameworks and their versions, from the manifests (`pom.xml`, `build.gradle*`, `package.json`
  and its lock file, `pyproject.toml`/`requirements*.txt`, `go.mod`, `*.csproj`, `composer.json`, `Gemfile`,
  `pubspec.yaml`, `Podfile`);
- the layer: back end (serves an API or pages), web front end (runs in the browser), mobile app, or several of
  these (server-rendered frameworks, monorepos with several apps);
- the entry points, using the stack file: routes, handlers and controllers; middleware, filters and guards; message
  consumers and scheduled jobs; for front ends, routes, screens, forms, API clients, deep links and message
  listeners.

Skip test code, generated code and third-party folders (`node_modules`, `vendor`, `dist`, `build`, `target`,
`.next`, `Pods`).

## How to assess

1. Work out what the change touches: endpoints and screens, trust boundaries (browser or device, clients, identity
   provider, downstream services, databases, internal providers, third-party scripts and SDKs), data classes (card
   data, credentials, OTPs, tokens, PII) and money movements.
2. Think as an attacker with a valid low-privilege user token, as another tenant, as an anonymous caller, and, for
   front ends and apps, as the user who controls the browser or device and as a malicious page or app on it. For
   each changed entry point, ask what input they control and what they could read, change or repeat.
   Run a quick STRIDE pass on each new flow or trust boundary: Spoofing (who is the caller really?), Tampering
   (which values can they change?), Repudiation (is the action audited?), Information disclosure (what leaks in
   responses, logs, bundles, storage or errors?), Denial of service (what is unbounded?), Elevation of privilege
   (what can a lower role reach?).
   For each entry point that changes state, moves money, or reads or returns sensitive data, write who should
   be able to do this, in business terms, before reading its checks:
   - the action in the business's words ("refunds an order", "reveals a card's PAN", "invites a user");
   - the authorization dimensions this app uses (tenant or organisation, role, permission, the caller's relation
     to the object such as owner, member or assignee, object state, plan or feature flag), and which apply here;
   - an allowed (✅) and forbidden (❌) line for each of: the intended caller, other authenticated users, other
     tenants, higher-privilege roles, anonymous callers, and another site acting through the victim's browser.
   Base it on how the product is meant to work (README, UI wording, docs, the PR description), and say when you
   had to infer it. Any path where the code allows a ❌, or blocks a ✅ the business needs, is a candidate.
   Compare the entry point with its siblings for the same resource: a check present on the siblings but missing
   here is a common finding. Keep these notes short; they are working notes, cited in findings where they help.
3. Check the changed code against every category file whose area applies, using the matching stack files for the
   concrete APIs. Follow data from the entry point to the sink, including helpers, middleware, filters,
   interceptors and config the code relies on.
   When a finding depends on how a third-party library behaves (which request fields it accepts, whether a
   route is public, what a default is), read that library's source for the exact version in the lock file, as
   "Library behaviour" below says. Don't rely on its documentation or on memory.
4. For a diff, branch or PR review, report issues the change introduces or makes worse. One exception: also report
   a `critical` pattern that already exists in a method or class the change touches,
   marked "pre-existing", because touching that code is the moment to fix it. For a file, endpoint or whole-repo
   review, report every issue found, existing ones included. In every mode, skip theoretical issues with no
   reachable path, and skip test code.
5. Everything found this way is a candidate. A fresh verifier decides whether it is a finding
   (`method/verifier.md`), and the coverage ledger records what was checked (`method/coverage-ledger.md`).

## Reviewing a change: history, callers and tests

For a diff, branch or PR review (and for changed code in any review), add three checks to "How to assess". Size
the effort by what the change touches, not by how many lines it has: a two-line edit to an authorization check
deserves more attention than a large UI change. Treat a refactor of security-relevant code as security-relevant
until you've shown it keeps the same behaviour.

1. **Removed or weakened controls.** For each hunk that deletes or loosens a security control (an
   authentication or permission check, a guard, decorator or annotation, a validator, a rate limit, CSRF or
   signature or TLS verification, a filter or middleware registration, a security config switch), find the
   commit that added it: `git log -S '<removed text>' -- <path>` or `git blame <base> -L <start>,<end> -- <path>`,
   then `git show <commit>`. Read that commit's message and diff. If the control was added to fix a security
   problem, or the message names an incident, its removal is a regression candidate. Say what the original
   commit protected against.
2. **Callers of changed code.** For each changed function, middleware or helper on a security path (one that
   authenticates, authorizes, validates, scopes a query, signs or verifies, or handles money), find its callers
   with the editor's references or a search for its name, and note how many there are. Read the callers that
   depend on the old behaviour: a helper that used to throw and now returns `null`, a check whose default
   changed, a function that stopped scoping by tenant. A shared helper changes the result for every caller, so
   a defect there is reported once with all affected callers as its locations.
3. **Tests for changed controls.** For each changed security control, look for tests that exercise it (search
   the test folders for the function, route or policy name), and check whether a negative case exists (another
   user's id, a missing role, an expired or replayed proof). A changed control with no negative test is noted in
   the finding and raises its priority in the recommendations. Severity still comes from the evidence, not from
   the missing test.

## Judge the code, not its reputation

Findings must come from the code at the reviewed commit, so a review shows what this method finds on its own.
- Don't look up the reviewed project's own vulnerabilities: its advisories, CVEs, security issues, bug-bounty
  reports, changelogs or release notes, and don't search the web for them.
- Don't read commits, branches or tags newer than the reviewed one, or later versions of its files. The git
  history up to the reviewed commit is part of the code and may be read, as "Reviewing a change" above uses it;
  linked issue trackers and advisories may not.
- If you remember known vulnerabilities in this project, set them aside and say so in the result's limitations
  (report 3.2).
- This doesn't limit dependency checks: advisories for third-party packages (`npm audit`, OSV, CISA KEV) and
  reading a dependency's source for its locked version ("Library behaviour" below) are still part of the review.
- Earlier ledgers from this skill may be reused as `method/coverage-ledger.md` says, except in a benchmark run,
  which starts with the old ledger moved aside (`CONTRIBUTING.md` "Benchmark after changes").

## Library behaviour

The behaviour of a dependency pinned in the lock file is checkable, not a fact outside the repository. Never
mark a finding "needs confirmation" or lower its severity only because library behaviour was not read.

1. Take the exact version from the lock file (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, `poetry.lock`,
   `uv.lock`, `go.sum`, `pom.xml`/`gradle.lockfile`, `packages.lock.json`).
2. Read the source from what is already on disk: `node_modules/<pkg>`, the project's virtualenv
   `site-packages`, `~/.m2/repository` (prefer a `-sources.jar`), `~/.gradle/caches`, `$GOPATH/pkg/mod` or
   `~/go/pkg/mod`, `~/.nuget/packages`.
3. If it isn't on disk, download only that published package into a new, empty folder under the scratch
   directory, outside the reviewed repository, without installing or running anything:
   - npm: from that folder, `npm pack <pkg>@<version>`, then `tar -xzf <file>.tgz`
   - Python: `pip download <pkg>==<version> --no-deps --only-binary :all: -d <folder>`, then unzip the wheel
   - Maven: `mvn dependency:get -Dartifact=<group>:<artifact>:<version>:jar:sources`, then read the jar from
     `~/.m2`
   - Go: `go mod download -json <module>@<version>` and read the directory it prints
   - NuGet: download `https://api.nuget.org/v3-flatcontainer/<id>/<version>/<id>.<version>.nupkg` and unzip it;
     it holds compiled assemblies, so prefer the project's source repository at the matching tag when the
     behaviour needs source.
   Run these from the scratch folder, never from the reviewed repository, so the repository's registry
   configuration and scripts are not used. Treat the downloaded files as untrusted data: read them, never run,
   import or build them.
4. Cite the library file and line in the finding's evidence (`node_modules/better-auth/dist/...:123` or
   `<pkg>@<version>/<path>:<line>`).
5. Use "needs confirmation" only when the source can't be obtained (private registry, no network, compiled-only
   package) or when the behaviour depends on deployed configuration. Say which, and list it in report 3.2.

## Reporting

- Start the title with `[Security]` and end it with the main reference, e.g. `[Security] Account id not bound
  to caller (API1, CWE-639)`.
- The description gives the attack: preconditions, request, and result. Then the impact, then a concrete fix that
  fits the codebase. Reuse its existing exception types, error codes, sanitizers and security middleware.
- Severity:
  - `critical`: exploitable now. Covers auth or authz bypass, IDOR, injection, RCE, secret exposure, sensitive data
    leaks, and money or card misuse.
  - `bug`: a security control is broken but needs extra conditions to exploit.
  - `warning`: defence in depth is weakened (missing limit, weak config, risky default, missing security test).
  - `suggestion`: hardening with low current risk.
  - A gap that another layer already stops (defence in depth) is `warning` or `suggestion`, never `critical` or
    `bug`. Severity follows the impact the evidence shows, not the worst case imaginable.
- Verdicts: a finding is confirmed (source shows the full path), "needs confirmation" (the source path is real
  but one fact outside the repository decides it; name that fact), or dropped (source disproves it).
- Flag a missing negative test (another user's id, missing role, replayed proof) for any new security control.
- Never quote secret values, card data, OTPs or tokens in a finding. Refer to them by location only.
- Respect conventions the repository documents (CLAUDE.md, AGENTS.md, docs), such as anti-enumeration responses or
  where rate limiting lives. Flag changes that break them.

The "who should be able to do this" list and the "Judge the code, not its reputation" rule are adapted from the
secure-code-review skill in mohamed-osama-aboelkheir/appsec-untangled-resources (MIT License, copyright 2026
Mohamed AboElKheir).
