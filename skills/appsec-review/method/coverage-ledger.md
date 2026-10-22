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

The `ledger` path from `python -I <skill folder>/method/review_paths.py <repo-name> --mkdir`, outside the
reviewed repository, next to the run's `inventory.json`. It holds attack details,
so never commit it or copy it into the repository. A run reads only `coverage-ledger.json` and `inventory.json`
from this folder. Ignore anything else there (moved-aside ledgers, saved benchmark runs): reading an earlier
run's results would make this run copy them instead of reviewing the code. One ledger per repository; a multi-repository review keeps one
per repository.

## Shape

```json
{
  "repo": "card-service",
  "source_ref": "<HEAD commit sha>",
  "dirty": false,
  "profile": "standard|deep",
  "scope": "diff|repo|endpoint|files",
  "layers": ["backend", "web-frontend"],
  "base_ref": "<merge-base sha for a diff review, else null>",
  "stopped_early": false,
  "runs": [{"date": "2026-10-15", "source_ref": "<sha>", "scope": "repo", "note": "first full review"}],
  "threat_model": {
    "assets": [{"id": "card-pan", "what": "PAN and CVV returned by CardController.reveal"},
               {"id": "wallet", "what": "balances moved by TransferService"}],
    "actors": ["anonymous", "customer", "support-agent"],
    "boundaries": ["browser -> API (JwtAuthFilter)", "API -> card vault (VaultClient)"]
  },
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
    },
    {
      "id": "abuse/customer-reads-other-pan::abuse-path",
      "surface": "abuse/customer-reads-other-pan",
      "area": "abuse-path",
      "status": "covered",
      "owner": "main",
      "abuse": {"actor": "customer", "asset": "card-pan", "goal": "read another customer's PAN"},
      "reviewed_paths": ["src/main/java/.../CardController.java", "src/main/java/.../CardService.java"],
      "checks": ["blocked: reveal loads via findByIdAndCustomerId(principal) at CardService.java:88"],
      "finding_keys": [],
      "unresolved": []
    }
  ],
  "findings": [
    {"key": "cards/reveal-without-step-up", "title": "Card reveal without OTP step-up",
     "decision": "confirmed", "severity": "critical", "paths": ["src/main/java/.../CardController.java"],
     "layer": "backend", "source_ref": "<sha>"},
    {"key": "cards/owner-check-in-cms", "title": "Card ownership relies on CMS scoping",
     "decision": "needs_confirmation", "severity": null, "severity_if_confirmed": "critical",
     "paths": ["src/main/java/.../CardService.java"], "layer": "backend", "source_ref": "<sha>"},
    {"key": "cards/otp-header-brute-force", "title": "OTP brute force on header path",
     "decision": "rejected", "severity": null, "disproof": "src/main/java/.../OtpFilter.java:57 attempt counter",
     "paths": ["src/main/java/.../OtpController.java"], "layer": "backend", "source_ref": "<sha>"}
  ]
}
```

- **surface**: a stable, repository-relative name. In `standard`, the module's file path
  (`src/.../CardController.java`); the validator rejects a `#` part. In `deep`, `<path>#<route or handler>`
  (`#GET /x`, `#consumer card-events`, `#screen Login`, `#deep link app://pay`), or `<path>` for config files, CI
  and manifests. Never contains `::`.
- **area**: a category file stem from `rules/` (`access-control`, `web-protocol-identity`, …) or a hunter
  (`wildcard`, `obvious-things`, `sink-trace`), or `abuse-path` for an abuse path. The validator reads the
  category list from `rules/`.
- **id**: `<surface>::<area>`. No line numbers, dates or agent names, so it stays the same across runs.
- **owner**: `main` (you), `wildcard`, `obvious-things`, `sink-trace`, or `verifier`.
- **title**: the weakness in words a reader understands, at least three ("Card reveal without OTP step-up"),
  never a working candidate id such as `C9`. It is what the result, SARIF and reports show.
- **finding key**: a stable root-cause key such as `cards/reveal-without-step-up`. No line numbers or severities.
  One root cause seen from several entry points is one finding linked from several units.
- **layers** and **layer**: the repository's layers from step 2 (`backend`, `web-frontend`, `mobile`), in that
  order. Leave `layers` out for a repository with one layer. When it lists two or more, every finding needs a
  `layer` from the list, chosen as `rules/00-overview.md` ("Findings in a repository with several layers") says;
  the validator enforces it and prints the reported findings per layer.
- **threat_model** and **abuse paths**: written as `method/threat-model.md` says. An abuse path unit has area
  `abuse-path`, surface `abuse/<slug>`, and an `abuse` object whose `actor` and `asset` come from the threat
  model. A ledger needs at least 3 and one per asset. Closed `covered`, one check cites the `path:line` of the
  control that blocks it; closed `finding`, it links the findings that realise it. Abuse paths count separately
  from the coverage units in the summary.
- **chain**: on a finding from the chain pass, the keys of the two or more findings it combines (never rejected
  findings or other chains). It is `needs_confirmation` while any link is, and more severe than its worst link.

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
`severity_if_confirmed`, and a `rejected` one has `disproof` with the `path:line` of the stopping control and
`proposed_severity`, the severity the candidate had before verification. A rejected `critical` or `bug`
candidate also has `rejection_reviewed: true` once a second verifier upheld it (`method/verifier.md`, "Rejection
review"); the validator enforces all of these. Keep rejected findings so later runs don't repeat them.

`stopped_early` is `true` only when the user stopped the run; it is the one case where in-scope units may stay
`deferred`. A large repository is not a reason to defer: review every unit, and if the run is long, say so.

## How to build it

1. **Seed** from the inventory (SKILL.md step 2, `method/inventory.py`), then add what the mapping found that the
   inventory missed. For each module in the inventory's `modules` (`standard`) or each entry point `surface` in
   its `entry_points` (`deep`, used verbatim as the unit surface), add one unit per category file loaded in
   SKILL.md step 4 whose `paths` match its files, and skip categories that plainly don't apply rather than
   writing `not_applicable` units for them, plus one unit per repository-wide category (configuration and supply
   chain, logging) on the manifests, CI and container files. Every file in the inventory's `sinks` must end up in
   the `reviewed_paths` of a unit of the sink's `area`, or be excused by a `not_applicable` or `out_of_scope`
   unit of that area whose surface is the sink's path. Add one `wildcard` and one `obvious-things` unit with the
   surface `<repo>` (`deep`: one per subsystem in a large repository), and in `deep` one `sink-trace` unit with
   the surface `<repo>`. For a review narrowed to an endpoint or files, build the inventory with `--only` and seed
   only those surfaces.
2. **Close units** as you and the hunters work: write the paths read and one short line per check. Keep checks
   terse; the ledger is a record, not the write-up.
3. **Link findings** after verification, and set each unit's status from the verdicts.
4. **Gap pass.** Before writing the result, read the ledger once as a critic (yourself, no subagent). This is the
   coverage-reviewer role in `method/orchestration.md`: entry points in the stack file's
   list with no unit, parallel paths to the same effect (batch, legacy, mobile, admin, retry) with no unit, units
   closed without real checks. Add what is missing and review it now.
5. **Validate**: `python -I <skill folder>/method/ledger.py <ledger path> --inventory <inventory path>`, using
   the paths `review_paths.py` printed. Fix every error before reporting: an inventory error
   means an entry point without a unit or a sink file nobody read under its category. The summary it prints gives the counts for the result and report sections 2.3
   and 3.1.

## Later runs on the same repository

If a ledger already exists, read it first:

- Rebuild the inventory for the current commit; new entry points and sinks become new units.
- Run `git -C <repo> diff --name-only <old source_ref> HEAD`. A unit whose `reviewed_paths` didn't change keeps its
  status but stays visible; a unit whose paths changed goes back to `planned`.
- Re-verify every earlier `confirmed` and `needs_confirmation` finding against the current code before reporting it
  again. Mark fixed ones in the report's Status column instead of deleting them.
- Make earlier `blocked`, `deferred` and `out_of_scope` units current work when they are now in scope.
- Re-check the threat model: add assets, actors and boundaries the new code brings, and re-work abuse paths
  whose `reviewed_paths` changed, as for any unit.
- Bring a ledger written under older rules up to date before validating: add the `threat_model` and abuse
  paths if it has none, review its `deferred` units, add
  `severity_if_confirmed` to each `needs_confirmation` finding, and re-verify each `rejected` finding that has no
  `disproof` line (keep it rejected only if a verifier cites one; otherwise it becomes `needs_confirmation`),
  and add `proposed_severity` to each `rejected` finding and send the `critical` and `bug` ones to rejection
  review.
- An earlier `rejected` finding suppresses only that same claim on unchanged code, not review of its unit.
- Append a `runs` entry and update `source_ref`. Never imply that one run covered everything; say how many units
  are covered, blocked and deferred.
