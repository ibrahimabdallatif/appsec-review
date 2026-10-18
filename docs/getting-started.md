# Getting started

## 1. Install

```sh
git clone https://github.com/ibrahimabdallatif/appsec-review.git ~/.claude/skills/appsec-review
```

The skill is then available in every Claude Code session. You also need Python 3 on your PATH as `python`; the
helper scripts use only the standard library. gitleaks, trivy or osv-scanner, semgrep and your ecosystem's audit
tool are optional: the skill runs them when they are installed and never installs them itself.

## 2. Run your first review

Open Claude Code in the repository you want to review and start small:

```
/appsec-review
```

With no arguments the skill reviews the current branch's changes against its base branch (`develop` if it
exists, else `main`) plus uncommitted changes, in `diff` mode. This is the fastest way to see what it does.

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

The review then asks what to do next: whether to generate a report (when you didn't ask for one) and whether to
fix a specific finding, all of them, or none for now. Non-interactive runs (CI) skip these questions.

## 4. Fix and re-check

The review only reports. To fix something, ask for it (for example "fix the critical findings"); the skill then
changes the code and adds or updates the tests that prove the attack no longer works. Run the review again
afterwards. In `standard` and `deep`, a later run reuses the ledger: it re-verifies earlier findings against the
new code and marks fixed ones instead of starting over.

## 5. Keep results private

Ledgers, inventories and reports describe how to attack open issues. They live in `~/.appsec-review/`, outside
your repository, so they are not committed by accident. A published report is private by default; check who can
see it before sharing.

## Next steps

- [How it works](how-it-works.md): the inventory, the hunters, the verifiers and the coverage ledger.
- [CI pipeline](ci-pipeline.md): run the skill on a schedule and fail builds on serious findings.
- [Contributing](../CONTRIBUTING.md): add rules, stacks and patterns, and check the skill with benchmarks.
