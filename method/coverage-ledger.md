# Coverage ledger

The ledger shows what the review covered: every entry point checked against every category that applies, with
the paths read and the checks made. A sentence like "auth reviewed" is not coverage; a ledger unit with paths and
checks is. Validate it with `method/ledger.py`.

| Review mode (SKILL.md "Review modes") | Ledger |
|---|---|
| `diff` | **None.** The result's "checked and found clean" list is enough. If a ledger already exists for the repository, leave it untouched. |
| `standard` | Coarse units: one per **module** (a controller, router, handler file, consumer, screen or config file) × category. `surface` is the file path, with no `#route` part. |
| `deep` | Fine units: one per **entry point** (route, handler, consumer, screen, deep link) × category. `surface` is `<path>#<route or handler>`. |

A later run may switch profile; the new run re-seeds units at its own granularity and keeps earlier findings.

## Where it lives

`~/.appsec-review/<repo-name>/coverage-ledger.json`, outside the reviewed repository. It holds attack details,
so never commit it or copy it into the repository. One ledger per repository; a multi-repository review keeps one
per repository.

## Shape

```json
{
  "repo": "card-service",
  "source_ref": "<HEAD commit sha>",
  "dirty": false,
  "profile": "standard|deep",
  "scope": "diff|repo|endpoint|files",
  "base_ref": "<merge-base sha for a diff review, else null>",
  "stopped_early": false,
  "runs": [{"date": "2026-10-15", "source_ref": "<sha>", "scope": "repo", "note": "first full review"}],
  "units": [
    {
      "id": "src/main/java/.../CardController.java::access-control",
      "surface": "src/main/java/.../CardController.java",
      "area": "access-control",
      "status": "covered",
      "owner": "main",
      "reviewed_paths": ["src/main/java/.../CardController.java", "src/main/java/.../CardService.java"],
      "checks": ["card id resolved via findByIdAndCustomerId(principal) at CardService.java:88"],
      "finding_keys": [],
      "unresolved": [],
      "source_ref": "<sha when last reviewed>"
    }
  ],
  "findings": [
    {"key": "cards/reveal-without-step-up", "title": "Card reveal without OTP step-up",
     "decision": "confirmed", "severity": "critical", "paths": ["src/main/java/.../CardController.java"],
     "source_ref": "<sha>"},
    {"key": "cards/owner-check-in-cms", "title": "Card ownership relies on CMS scoping",
     "decision": "needs_confirmation", "severity": null, "severity_if_confirmed": "critical",
     "paths": ["src/main/java/.../CardService.java"], "source_ref": "<sha>"},
    {"key": "cards/otp-header-brute-force", "title": "OTP brute force on header path",
     "decision": "rejected", "severity": null, "disproof": "src/main/java/.../OtpFilter.java:57 attempt counter",
     "paths": ["src/main/java/.../OtpController.java"], "source_ref": "<sha>"}
  ]
}
```

- **surface**: a stable, repository-relative name. In `standard`, the module's file path
  (`src/.../CardController.java`); the validator rejects a `#` part. In `deep`, `<path>#<route or handler>`
  (`#GET /x`, `#consumer card-events`, `#screen Login`, `#deep link app://pay`), or `<path>` for config files, CI
  and manifests. Never contains `::`.
- **area**: a category file stem from `rules/` (`access-control`, `web-protocol-identity`, …) or a hunter
  (`wildcard`, `obvious-things`). The validator reads the allowed list from `rules/`.
- **id**: `<surface>::<area>`. No line numbers, dates or agent names, so it stays the same across runs.
- **owner**: `main` (you), `wildcard`, `obvious-things`, or `verifier`.
- **finding key**: a stable root-cause key such as `cards/reveal-without-step-up`. No line numbers or severities.
  One root cause seen from several entry points is one finding linked from several units.

## Unit status

| Status | reviewed_paths and checks | finding_keys | unresolved |
|---|---|---|---|
| `planned` | empty | empty | empty |
| `covered` | required | empty | empty |
| `finding` | required | required (at least one not rejected) | optional |
| `blocked` | required | empty | required: the exact fact that stopped the check |
| `deferred` | empty | empty | required: why. **Only allowed when the user stopped the run** (`stopped_early: true`); never for time, size or mode |
| `out_of_scope` | empty | empty | required: why (outside the diff, user narrowed the scope) |
| `not_applicable` | empty | empty | required: why the area does not apply (no card data, no UI) |

Finding decisions come from `method/verifier.md`: `confirmed` and `hardening` (`warning` or `suggestion`) have a
severity; `needs_confirmation` and `rejected` have `null`. A `needs_confirmation` finding also has
`severity_if_confirmed`, and a `rejected` one has `disproof` with the `path:line` of the stopping control; the
validator enforces both. Keep rejected findings so later runs don't repeat them.

`stopped_early` is `true` only when the user stopped the run; it is the one case where in-scope units may stay
`deferred`. A large repository is not a reason to defer: review every unit, and if the run is long, say so.

## How to build it

1. **Seed** after mapping the stack and entry points (SKILL.md step 5). For each module (`standard`) or entry
   point (`deep`), add one unit per category file loaded in SKILL.md step 4 whose `paths` match its files, and skip categories that plainly
   don't apply rather than writing `not_applicable` units for them, plus one unit per repository-wide category (configuration and
   supply chain, logging) on the manifests, CI and container files. Add one `wildcard` and one
   `obvious-things` unit with the surface `<repo>` (`deep`: one per subsystem in a large repository). For a
   review narrowed to an endpoint or files, seed only those surfaces.
2. **Close units** as you and the hunters work: write the paths read and one short line per check. Keep checks
   terse; the ledger is a record, not the write-up.
3. **Link findings** after verification, and set each unit's status from the verdicts.
4. **Gap pass.** Before writing the result, read the ledger once as a critic (yourself, no subagent): entry points in the stack file's
   list with no unit, parallel paths to the same effect (batch, legacy, mobile, admin, retry) with no unit, units
   closed without real checks. Add what is missing and review it now.
5. **Validate**: `python -I <skill folder>/method/ledger.py ~/.appsec-review/<repo>/coverage-ledger.json`. Fix
   every error before reporting. The summary it prints gives the counts for the result and report sections 3.2
   and 4.1.

## Later runs on the same repository

If a ledger already exists, read it first:

- Run `git -C <repo> diff --name-only <old source_ref> HEAD`. A unit whose `reviewed_paths` didn't change keeps its
  status but stays visible; a unit whose paths changed goes back to `planned`.
- Re-verify every earlier `confirmed` and `needs_confirmation` finding against the current code before reporting it
  again. Mark fixed ones in the report's Status column instead of deleting them.
- Make earlier `blocked`, `deferred` and `out_of_scope` units current work when they are now in scope.
- Bring a ledger written under older rules up to date before validating: review its `deferred` units, add
  `severity_if_confirmed` to each `needs_confirmation` finding, and re-verify each `rejected` finding that has no
  `disproof` line (keep it rejected only if a verifier cites one; otherwise it becomes `needs_confirmation`).
- An earlier `rejected` finding suppresses only that same claim on unchanged code, not review of its unit.
- Append a `runs` entry and update `source_ref`. Never imply that one run covered everything; say how many units
  are covered, blocked and deferred.
