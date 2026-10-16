# Hunters: wildcard and obvious things

The category files find what is on the checklist. These two hunters find what isn't. They run alongside the main
assessment (SKILL.md step 6), not instead of it.

## When and how to run them

| Review mode (SKILL.md "Review modes") | How |
|---|---|
| `diff` | Run both lists **inline yourself**, limited to the changed files and the code they call. No subagents. |
| `standard` | **One** hunter subagent gets both prompts below, one after the other, and returns one result. Start it in parallel with your own assessment. Claude Code: Agent tool, `general-purpose`, `model: sonnet`. |
| `deep` | **Two** hunter subagents in parallel, one per prompt, on the session's model. |
| No subagent tool available | Run both lists inline and say so in the result (report 3.2). |

Context block to put before each hunter prompt:

- repository path and branch, stack and layer, the stack files picked;
- the entry points and trust boundaries you mapped in steps 2–5;
- the coverage ledger units assigned to the hunter (`method/coverage-ledger.md`), so it reports against them
  (`standard` and `deep` only);
- the instruction to read code only: no builds, no tests, no network, no installs, no edits;
- the instruction to read only what it needs: start from the entry points given, open files on demand, and don't
  re-read the rule files (they are not part of its task).

Hunters return **candidates**, not findings. Every candidate goes to independent verification
(`method/verifier.md`) like your own.

## Return format (both hunters)

Return one JSON object and nothing else:

```json
{
  "units": [
    {"id": "<ledger unit id>", "status": "covered|finding|blocked",
     "reviewed_paths": ["repo/relative/path"], "checks": ["what was checked and the result"],
     "unresolved": ["exact fact that blocked the check, if blocked"]}
  ],
  "candidates": [
    {"key": "<stable root-cause key, no line numbers>", "title": "...", "category": "<rules file or hunter>",
     "trace": ["path:line entry point", "path:line propagation", "path:line sink"],
     "attack": "preconditions, request, result", "impact": "...", "proposed_severity": "critical|bug|warning|suggestion",
     "needs_confirmation": "exact external fact, or null"}
  ],
  "uncovered": [{"surface": "...", "reason": "boundary found that no ledger unit covers"}]
}
```

## Wildcard hunter prompt

```text
You are not given a category. Find security weaknesses outside the standard checklist areas
(access control, authentication, injection, crypto, business logic, configuration, logging,
client side, web protocol and identity), which other reviewers already cover.

Read code that looks boring or disconnected from security. Follow incomplete, experimental,
compatibility and fallback features. Starting points, not limits:
- What is the strangest code in the repository? Why does it exist? What if it is abused?
- Which features feel half-finished, experimental or bolted on? They got the least review.
- What can the API do that the UI never asks for? The UI constrains users; the API does not.
- Hidden or undocumented endpoints, parameters, headers or feature flags in route registrations,
  middleware and config.
- Features combined in ways nobody designed for: localisation + preview + caching, import + plugins
  + webhooks, OAuth + impersonation + API keys.
- Git history: reverted security fixes, commented-out auth checks, secrets committed then removed.
  Refer to secrets by commit and path only, never quote them.
- Valid-account actions that affect other users, shared integrity, availability or operator cost.
- Irreversible operations: is approval bound to the final principal, action and resource?
- Environment assumptions: local database, accurate clock, trustworthy DNS, case-sensitive files.
- Tests: compare the edge cases the developers tested with the ones they did not.

Pursue an anomaly until you can say whether it is safe. If a comment explains why something is safe,
verify the explanation. Read variables named temp, hack, legacy or old closely.

Every candidate needs a concrete lower-trust principal, the input they control, the control that
should stop them, the source path to the effect, and the affected principal or resource. A missing
best practice with no affected principal is not a candidate. Stop investigating a line once the
answer is settled either way.
```

## Obvious-things hunter prompt

```text
Other reviewers hunt subtle bugs. You check the basic exposures everyone assumes someone else
checked. Be thorough and literal: check every item and report each result in "checks".

- Hardcoded passwords, API keys, tokens or private keys (grep password, secret, apikey, token,
  Bearer, -----BEGIN, common default passwords). Report location only, never the value.
- TODO/FIXME/HACK/XXX comments about security ("TODO: add auth", "FIXME: validate", "skip check").
- Debug or dev mode that production can switch on through an environment variable, query
  parameter, header or profile.
- Test, example or seed credentials that would work in production.
- Unprotected /debug, /admin, /test, /status, /health, /metrics, /env, /.env, /config,
  /actuator, /swagger, /graphql playground routes.
- .env, .env.local, credentials.json, *.pem, *.key, *.p12, *.jks files in the repository, and
  whether .gitignore covers secrets, uploads and local config.
- Unpinned dependencies and lock files with known CVEs (read lock files; do not run installs).
- eval, exec, Function(), child_process, Runtime.exec, ProcessBuilder, subprocess with shell=True,
  vm.runInContext, dynamic import() or reflection fed by input.
- CORS with "*" or a reflected origin together with Access-Control-Allow-Credentials.
- Session or auth cookies missing HttpOnly, Secure or SameSite.
- Open redirects: parameters named redirect, return, returnUrl, next, url, goto, continue, callback
  that reach a redirect without an allow-list.
- Plain-HTTP endpoints or clients, and TLS verification disabled.
- Production error responses with stack traces, internal paths, SQL errors or framework banners.

A flag is not a finding. Trace the impact before proposing a candidate: if a cookie lacks HttpOnly,
check whether it holds anything sensitive and whether scripts must read it by design; if an error
contains a field name, check whether sensitive data ever reaches it.
```
