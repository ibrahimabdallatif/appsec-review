# Threat model, abuse paths and chains

The category files and hunters work bottom-up: every entry point, every sink, every rule. This file adds the
top-down view: what an attacker would want from this system, and whether they can get it. It runs in `standard`
and `deep` (SKILL.md steps 5, 6 and 8). In `diff` mode only the chain pass runs, inline.

Everything here is grounded in the code and recorded in the coverage ledger (`method/coverage-ledger.md`), where
`method/ledger.py` checks it. A threat model that cites no code, or an abuse path closed without evidence, fails
validation.

## 1. Threat model (step 5)

Write the ledger's `threat_model` block from what you mapped in steps 2–4 (manifests, inventory, docs, README, UI
wording). Keep it short: it is a working record, not a design document.

- **assets**: what an attacker wants, most valuable first, each with a stable `id` and one line `what` naming
  where it lives in the code: card data and credentials, money movements and balances, accounts and sessions,
  other tenants' data, admin and role changes, signing keys and secrets, personal data, shared availability or
  operator cost. Usually 3–8 for a service; one asset per distinct kind of harm, not per table.
- **actors**: who could attack, as short ids: `anonymous`, `customer` (any signed-in user), `other-tenant`,
  `low-role` (e.g. a support agent), `admin`, `partner` or `webhook-sender`, `malicious-page` (another site in
  the victim's browser), `malicious-app` (on the same device), `compromised-dependency`. Use the roles the app
  actually has.
- **boundaries**: the trust boundaries data crosses, as `from -> to`, citing where the code enforces each
  (`browser -> API (JwtFilter.java)`, `API -> card vault (VaultClient)`, `queue -> consumer (card-events)`).

## 2. Abuse paths (step 5, worked in step 6)

An abuse path is a concrete goal an actor would pursue against an asset, across one or more entry points:
"a customer reads another customer's PAN", "an anonymous caller completes checkout without paying", "a support
agent grants themselves admin", "a malicious page moves money through the victim's session".

Write them as ledger units with area `abuse-path` and surface `abuse/<slug>` (rules in `coverage-ledger.md`):

- at least 3, and at least one aimed at every asset; `standard` usually needs 5–10, `deep` 10–20;
- start from the most valuable assets and the actors closest to them (the lowest-privilege actor that can
  reach the asset's boundary);
- include at least one path that crosses two boundaries or needs two steps (find an id, then use it; sign up,
  then escalate; trigger a callback, then replay it), since those are what per-entry-point checks miss;
- include the paths the business would care about most, even when you expect them to be blocked; proving a
  control holds is a result.

**Work each path in step 6**, after your forward pass over the entry points, as an attacker would: pick the
cheapest route to the goal from the inventory's entry points, follow it through the code, and at each step find
the control that should stop it. Close the unit:

- `finding`: the goal is reachable. Link the finding keys that realise it (one finding, or the links and the
  chain from section 3). The findings still go through verification in step 8; if they are all rejected there,
  the path goes back to `covered` with the disproof lines as its checks.
- `covered`: blocked. One check must cite the `path:line` of the control that stops it, the same standard as a
  verifier's rejection. "Looked fine" is not a check.
- `blocked`: one fact outside the repository decides it; name the fact in `unresolved`.

Give the abuse path list to the hunters as extra targets (`method/hunters.md`): they report candidates against
them like any other, and you close the units.

## 3. Chain pass (step 8, after verification)

Per-finding verification judges each weakness on its own, so two `warning`s that together take over an account
stay two warnings. After the verifiers decide, look for chains among the findings that were not rejected:

- one finding gives the precondition another needs: an id, a token or a URL leaked in one place and used in
  another; an open redirect that carries an OAuth code; self-XSS plus a CSRF that plants it; an SSRF that reaches
  metadata credentials; a race that bypasses a limit another finding relies on; a weak reset plus user
  enumeration;
- several findings on the route of one abuse path that, together, reach its goal.

A chain is a finding of its own, with key `chain/<slug>`, a `chain` list of the linked finding keys (two or more;
never another chain), the paths of the step where the impact lands, and the severity of the end-to-end outcome.
Its links stay reported with their own severities. The ledger validator rejects a chain that is not more severe
than its worst link (report the links alone then), and a `confirmed` chain with an unconfirmed link (it is
`needs_confirmation` until every link is confirmed).

Verify chains like any candidate (`method/verifier.md`, "Chains"): the verifier checks the links between the
findings, not the findings again. Link each verified chain from the abuse path it realises, or from the units
of its links when no abuse path covers it.
