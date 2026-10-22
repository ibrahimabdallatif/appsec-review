# Getting started

## 1. Install

Python 3.10 or newer must be on your PATH as `python`. The helper scripts use only the standard library.
gitleaks, trivy or osv-scanner, semgrep and your ecosystem's audit tool are optional: the skill runs them when
they are installed and never installs them itself.

From a clone of this repository, link the one skill folder into the user directories for Claude Code, Cursor
and Codex:

```sh
python -I skills/appsec-review/method/install_links.py
```

Or install a copy with the skills CLI:

```sh
npx skills add ibrahimabdallatif/appsec-review --skill appsec-review -g -a claude-code -a cursor -a codex -y
```

Paths, sequential mode and troubleshooting: [Platforms](platforms.md).

## 2. Run your first review

Open the repository you want to review.

| Host | Command |
|---|---|
| Claude Code | `/appsec-review` |
| Cursor | `/appsec-review` |
| Codex | `/skills`, then appsec-review, or `$appsec-review` |

With no arguments the skill reviews the current branch's changes against its base branch (`develop` if it
exists, else `main`) plus uncommitted changes, in `diff` mode. This is the fastest way to see what it does.
Say "sequential" in the same request when you do not want subagents. The checks do not change.

When that looks useful, review the whole repository:

```
/appsec-review whole repo
```

This runs `standard` mode: it builds the inventory of entry points and sinks, reads every in-scope module, starts
one hunter subagent, verifies the candidates with one verifier subagent (and a second one for any rejected
`critical` or `bug` candidate), and keeps a coverage ledger in
`~/.appsec-review/<repo>/`.

| You want | Type |
|---|---|
| Review a branch or PR | `/appsec-review feature/login against main` |
| Review specific files or a folder | `/appsec-review src/payments/` |
| Review the whole repository | `/appsec-review whole repo` |
| Go deep on high-stakes code | `/appsec-review deep` |
| Review every repository in a folder | `/appsec-review ~/work/services` |
| Get a shareable report | add "write a report" to any of the above |

`deep` takes several times longer and uses much more tokens than `standard`. The skill only uses it when you say
"deep".

## 3. Read the result

The result is ordered by severity: `critical`, `bug`, `warning`, `suggestion`. The example below shows the shape
of one finding; it is illustrative, not output from a real run.

```
[Security] Order id not bound to caller (API1, CWE-639)        critical
src/orders/OrderController.java:42

Attack: any signed-in user sends GET /orders/{id} with another customer's order id.
        OrderService.find(id) loads the order without checking its owner.
Impact: read access to every customer's orders, including addresses and payment status.
Fix:    load through orderRepository.findByIdAndCustomerId(id, principal.customerId()),
        the method the other order endpoints already use, and return 404 when it is empty.
```

After the findings come:

- **Needs confirmation**: findings that depend on one fact outside the code (proxy behaviour, gateway policy,
  deployed config). They stay in the list at the severity they would have, with the exact fact to check.
- **Checked and found clean**: what was reviewed and held up, and what was out of scope.
- **Coverage**: in `standard` and `deep`, units covered, with findings, blocked and deferred.
- **Rejected by verification**: candidates a verifier disproved, each with the line of code that stops the
  attack. If you think a rejection is wrong, you can overrule it.
- **Run summary**: mode, time, tokens and subagents used, and counts of findings and affected locations.

`standard` and `deep` runs then write the report to `~/.appsec-review/<repo>/` as `report.html` and `report.md`
(the Markdown copy is the one to feed to another session) and print the absolute paths of both files. A private
claude.ai artifact is created only when you ask to publish, and only on Claude Code. Cursor and Codex leave the
report on disk. A `diff` run skips the report by default and instead asks whether to fix
the findings, generate the report, or both.
Non-interactive runs (CI) skip the questions; a non-interactive `diff` run writes the report anyway.

## 4. Fix and re-check

The review only reports. To fix something, ask for it (for example "fix the critical findings"); the skill then
changes the code and adds or updates the tests that prove the attack no longer works. Run the review again
afterwards. In `standard` and `deep`, a later run reuses the ledger: it re-verifies earlier findings against the
new code and marks fixed ones instead of starting over.

## 5. Keep results private

Ledgers, inventories and reports describe how to attack open issues. They live in `~/.appsec-review/`, outside
your repository, so they are not committed by accident. Publishing is a separate request. Check who can see a
report before sharing.

## Next steps

- [Platforms](platforms.md): install, invoke, sequential fallback, and what was tested.
- [How it works](how-it-works.md): the inventory, the hunters, the verifiers and the coverage ledger.
- [CI pipeline](ci-pipeline.md): run the skill on a schedule and fail builds on serious findings.
- [Contributing](../CONTRIBUTING.md): add rules, stacks and patterns, and check the skill with benchmarks.
