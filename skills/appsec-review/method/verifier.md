# Independent verification

The agent that found a candidate never decides whether it is real. Every candidate (yours from the category
files, and the hunters') goes to a **fresh verifier** whose job is to disprove it. This replaces self-checking and
is the main defence against false positives and overstated severity.

## Who verifies what

| Review mode (SKILL.md "Review modes") | Verifiers |
|---|---|
| `diff` | When parallel: **disproof pass** (below) for every candidate. One fresh verifier subagent only if a candidate is still `critical` after that pass; it gets all `critical` candidates in one batch. When sequential: disproof pass only. |
| `standard` | When parallel: **one** fresh verifier subagent gets every candidate (`critical`, `bug`, `warning` and `suggestion`) in one batch, on the session's model. When sequential: disproof pass for every candidate. |
| `deep` | When parallel: one fresh verifier subagent **per** `critical` or `bug` candidate, and one per category file for batched `warning` and `suggestion` candidates, in parallel, on the session's model. When sequential: disproof pass for every candidate. |
| Sequential | `method/parallel_mode.py` printed `sequential`, or the host cannot spawn a fresh agent (`method/orchestration.md`). Disproof pass for everything. Say "self-verified; sequential fallback" and the reason, in the result and in report 2.3. A rejected `critical` or `bug` candidate is not recorded as `rejected` unless a second agent upholds it; otherwise it becomes `needs_confirmation` as `method/orchestration.md` describes. |

Spawn a verifier as `method/orchestration.md` describes for this host. A verifier must not be an agent that hunted, and must not see another verifier's conclusion (except the
`disproof` line in a rejection review).

## Disproof pass

The cheap, inline form of verification. Do it yourself **after** the whole assessment is finished, never while
still hunting. For each candidate, re-open every cited line and work through steps 1–5 of the verifier prompt
below as if someone else wrote the candidate: look for the control that stops it, then decide `confirmed`,
`needs_confirmation`, `rejected` or `hardening`. Record the decision in the same form. In the result, mark
findings decided this way as self-verified (each report finding card shows how it was verified).

Keep the verifier's input small: it opens files itself, so send the paths, not file contents. Give each
verifier: the candidate(s) exactly as recorded, the repository path and branch, the stack and stack
files, the architecture notes it needs to read the path (entry points, middleware, trust boundaries), the
relevant category or stack file sections (in `deep` mode, also the matching `rules/deep/` playbook), and the
prompt below. Don't give it your reasoning about why the
candidate is real.

## Verifier prompt

```text
You did not write these candidates. For each one, try to refute it from the repository source.
Read code only: no builds, tests, installs or edits. The one network use allowed is downloading a
locked dependency's published package to read its source, as rules/00-overview.md "Library behaviour"
describes.

0. Before reading code, restate the candidate in one precise sentence: which caller, sending
   which input, through which entry point, reaches which line, with what result. A candidate you
   cannot state that precisely is usually not a real finding; find the missing piece in the code,
   or decide needs_confirmation or rejected. Keep in mind that models tend to see bugs where there
   are none and to rate them too high: the evidence must earn both the verdict and the severity.
1. Open every cited file and line. Confirm the code says what the candidate claims and that the
   first trace step is a real entry point a lower-trust caller can reach (route, handler, consumer,
   screen, deep link, job input).
2. Reconstruct the strongest control on the path: authentication and authorization middleware,
   filters, guards, interceptors, global config, framework defaults for the version in the
   manifest, validation, ORM scoping, gateway or edge config present in the repository. Read the
   helpers the code calls; don't judge a hunk in isolation.
3. Decide:
   - confirmed: the path is reachable, the input is attacker-controlled, no visible control stops
     it, and the impact crosses a real boundary (another user, tenant, role, money, card data,
     credentials, code execution, shared availability).
   - needs_confirmation: the source path is real, but one fact outside the repository decides it
     (proxy or CDN behaviour, IdP or gateway policy, deployed config, downstream system checks).
     Library behaviour is NOT such a fact: when the decision depends on what a dependency does,
     read its source for the locked version first (node_modules, local caches, or the downloaded
     package) and decide confirmed or rejected from it, citing the library file:line. Use
     needs_confirmation for library behaviour only if its source can't be obtained, and say why.
     Name that exact fact and a safe way for the owner to check it, and give the severity the
     finding has if the fact turns out to be unsafe (severity_if_confirmed).
   - rejected: source disproves it (a control stops it, the path is unreachable, the input is not
     attacker-controlled, it is test code, or it is intended same-principal behaviour). You MUST
     give the path:line of the code that disproves it in "disproof". Not finding proof either way
     is never a rejection: use needs_confirmation (fact outside the repository) or confirmed.
   - hardening: real but with no reachable boundary failure (defence in depth, missing limit, weak
     default). This is the warning/suggestion tier, never critical or bug.
4. Check severity against what the evidence shows, not the worst case: critical = exploitable now
   (auth or authz bypass, IDOR, injection, RCE, secret exposure, sensitive data leak, money or card
   misuse); bug = a broken control that needs extra conditions; warning/suggestion = hardening.
   Don't turn a crash into code execution, ordinary load into a denial of service, or a
   same-user action into privilege gain.
5. Check that the fix enforces the invariant at the last trusted decision point and uses the
   codebase's existing helpers, rather than moving trust somewhere else.

Reasons that never justify rejected or a lower severity on their own. If one is your only
reason, look further; if nothing in source actually stops the attack, the candidate stands.
- Authentication: "the route requires login" proves who the caller is, not that the object,
  field, price or action is theirs. "It's an internal endpoint": if a user or another tenant
  can reach it, the check must hold.
- Unguessable ids: "the id is a random UUID" slows guessing; it does not bind the object to
  the caller.
- One protected path: "the read path checks ownership" says nothing about update, delete,
  batch, export, admin, job or consumer paths to the same object.
- Validation: "the input is validated" for type or format is not validation of who may set
  it or which object it selects.
- UI limits: "the UI never sends that field" or "the UI won't allow it"; the API accepts
  what the server allows.
- A check exists: a check counts only if it runs before the sink on every path, fails
  closed on errors and empty values, and is enforced, not just computed.
- Timing: "there is a check right above it"; if check and act aren't atomic, the gap is the
  bug. "Requests are basically serial" and "the database will sort it out" need a
  transaction, constraint, lock or conditional update to be true.
- Frameworks: "we use an ORM" protects bound values, not raw fragments, identifiers or
  operator objects. "The library verifies the token" against which algorithm and key?
- Callbacks: "the provider calls us back" and "the callback URL is secret" don't
  authenticate a sender; only a verified signature does. "The redirect said success" is a
  client-carried value.
- Retries: "retries are just noise"; a non-idempotent money handler doubles on any retry.
- Purpose: "it only fetches avatars", "it's only a preference change", "it only reads
  data" don't limit what an attacker can do with the same code path.

Return one JSON array and nothing else, one object per candidate:
[{"key": "<same key>", "decision": "confirmed|needs_confirmation|rejected|hardening",
  "severity": "critical|bug|warning|suggestion|null",
  "severity_if_confirmed": "critical|bug|warning|suggestion|null",
  "disproof": "path:line of the stopping control, or null", "evidence": ["path:line what it shows"],
  "reason": "why, citing the decisive line or missing fact",
  "corrections": "changed trace, impact, severity or fix, or null"}]
severity is null for rejected and needs_confirmation. severity_if_confirmed is set only for
needs_confirmation. disproof is set only for rejected.
```

## Rejection review

A wrong rejection drops a real finding without anyone noticing, so one verifier's rejection is not final for a
serious candidate. In every mode, each `critical` or `bug` candidate (by the severity proposed before
verification, chains included) that a verifier subagent rejected goes to one more fresh verifier: in `diff` and
`standard`, one for all of them in one batch; in `deep`, one per candidate. It must not be an agent that hunted or
the verifier that rejected it. Give it what a verifier gets, plus the rejected `disproof` line but not the
verifier's reason, and the verifier prompt with this addition:

```text
Another reviewer rejected these candidates, citing the line in "disproof" as the control that stops
each one. Don't take that line on trust. Read the cited control and every path from the entry point
to the sink, including update, delete, batch, admin, job, retry and consumer paths. Keep a candidate
rejected only if the cited control, or another you cite, runs before the sink on every path, fails
closed on errors and empty values, and binds the object or action to the caller. Otherwise decide
confirmed or needs_confirmation, with the severity the evidence supports.
```

Its decision stands. An upheld rejection stays `rejected` with `rejection_reviewed: true` in the ledger; an
overturned one is reported with the new decision. If the two disagree on the facts and the review can't settle
them from source, report the candidate as `needs_confirmation` with both views. Rejected `warning` and
`suggestion` candidates, and rejections from the disproof pass alone, skip this review. In `standard` and
`deep`, do not store a disproof-pass rejection of a `critical` or `bug` candidate as `rejected` unless that
second agent ran: store `needs_confirmation` instead, as `method/orchestration.md` describes. `diff` has no
ledger, so a disproof rejection there is only listed in the result.

## Chains

Chain candidates from the chain pass (`method/threat-model.md`, section 3) go to a fresh verifier like any
candidate: in `diff`, the disproof pass; in `standard`, one more verifier subagent for all chains, in one batch;
in `deep`, one verifier per chain. Give it the chain, its links as verified, and this addition to the prompt:

```text
This candidate is a chain of findings that were each verified already; don't re-verify them. Decide
whether they combine as claimed: does the output of each link give the next one exactly what it
needs (same identifier, same user or tenant, same environment, reachable in the order claimed,
within any time or rate limits)? Cite the path:line where each hand-off happens. Rate the severity
of the end-to-end outcome. If a hand-off does not hold, the chain is rejected with that line as
the disproof; the links keep their own verdicts.
```

## After verification

- **Use the verifier's decision.** `rejected` candidates leave the findings list but are **listed at the end of
  the result** with their reason and disproof line, so the user can overrule a wrong rejection; keep them in the
  ledger so later runs don't repeat them. A rejection without a `path:line` disproof is invalid: treat it as
  `needs_confirmation`. `needs_confirmation` findings stay **in the main findings list**, ordered by
  `severity_if_confirmed`, with the "Needs confirmation" tag and the exact fact. `hardening` becomes `warning` or
  `suggestion`.
- **Escalation check.** If a verifier or the disproof pass raises a candidate **to `critical`**, send it to one
  more fresh verifier before accepting it. In `deep` mode, also do this when a verifier raises any severity,
  changes the root cause, or turns `needs_confirmation` into `confirmed`. Lowering severity or rewording never
  needs another verifier; rejecting a `critical` or `bug` candidate does ("Rejection review").
- **Malformed results** (prose around the JSON, missing candidates): don't repair them. Re-run that candidate with
  a fresh verifier once; if it fails again, report the candidate as "needs confirmation: verification failed".
- **Disagreement.** If you believe a verifier is wrong, don't overrule it silently. Either give the candidate and
  your counter-evidence to one more fresh verifier and accept its decision, or report it as "needs confirmation"
  and state both views.
- Only verified findings appear in a report (`report/REPORT.md`). Score a `needs_confirmation` finding as if the
  missing fact makes it exploitable, with `AC:H` for the unconfirmed condition as REPORT.md says, and name that
  fact in its Description.
- Record every decision, including `rejected`, in the coverage ledger (`method/coverage-ledger.md`).
