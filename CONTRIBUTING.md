# Contributing

This guide is for changing the skill itself: its rules, method, scripts and report. It is kept out of `SKILL.md`
so a review never loads it. For how a review runs, see [docs/how-it-works.md](docs/how-it-works.md).

## Layout and where changes go

| Change | Where | Never in |
|---|---|---|
| What the review checks | `rules/` category files, `rules/stacks/`, `rules/deep/` | `SKILL.md` |
| How the review runs (ledger, hunters, verification, inventory) | `method/` | `rules/` |
| Report structure, scoring, design | `report/` (`REPORT.md`, `cvss31.py`, `report-template.html`) | `rules/` |
| Regression checks for the skill | `evals/` | `rules/` |

Step 4 of `SKILL.md` loads files from `rules/` as checklists, so anything that is not a checklist stays outside it.
`disable-model-invocation: true` in `SKILL.md` keeps the skill manual; don't remove it.

## Rules

- Keep the `paths` front matter on every category file and the `detect` front matter on every stack file in
  `rules/stacks/`; step 4 uses them to pick rules.
- Keep category files framework-neutral and put framework APIs in the stack files. Add a new stack file rather
  than framework detail in a category file.
- Keep the `parent` and `when` front matter on every playbook in `rules/deep/`; step 4 uses them in `deep` mode. A
  playbook adds depth to its parent category and is not a ledger area of its own.
- The ledger's allowed areas come from the file names in `rules/`, so a new category file needs no validator
  change.
- Don't move the rules under `.codecanary/rules/`: CodeCanary applies anything there to every PR automatically.

## Adding a stack

1. Add `rules/stacks/<name>.md` with `detect` front matter and the stack's entry points, constructs and unsafe
   APIs.
2. Add a matching `<name>` entry to `STACKS` in `method/inventory_patterns.py`: manifest detection, source file
   extensions, entry point patterns (`entry_if` for ones that depend on the whole file, such as exports of a
   `'use server'` module) and sink patterns. Each sink names the category file that reviews it as its
   area. `test_inventory.py` fails if the stack names in the two places disagree.
3. Add one sample line per new pattern to `SAMPLES` in `method/test_inventory.py`.
4. When a sink-trace hunter reports a sink under "uncovered", the inventory missed it: add a pattern and a sample.

Patterns favour recall: a false hit costs a short review, a missed sink can hide a finding.

## Scripts and tests

Every script has a test file next to it. Update the tests with each change, and run all of them before you commit:

```sh
python -I method/test_inventory.py      # inventory.py, inventory_patterns.py
python -I method/test_ledger.py         # ledger.py (validator, inventory coverage, --fail-on gate)
python -I method/test_accepted_risks.py # accepted_risks.py (--accepted for the gate)
python -I method/test_sarif.py          # sarif.py (--sarif export)
python -I method/test_threat_model.py   # threat_model.py (threat model, abuse paths, chains)
python -I method/test_run_stats.py      # run_stats.py
python -I evals/test_benchmark.py       # benchmark.py
python -I report/cvss31.py --selftest   # cvss31.py
```

The same commands run in GitHub Actions on every push and pull request (`.github/workflows/tests.yml`), on Linux
and Windows. Run scripts with `python -I` so they never import code from the reviewed repository.

## Credits

When you adapt material from another project, credit it at the end of the file that uses it and add it to
`NOTICE.md` with its copyright line and license.

## Benchmark after changes

After changing `rules/`, `method/` or the steps in `SKILL.md`, check that the skill still finds what it used to.

1. Benchmarks live in `~/.appsec-review/benchmarks/<repo>.json`, outside the skill, because they list a
   repository's vulnerabilities. Each names the repository, the commit, and the expected findings with a minimum
   severity and a matcher (path substrings and a key/title regex). Set `human_confirmed: true` on findings a
   person has checked in the code; set `expect_confirmed: true` where "needs confirmation" counts as a miss.
2. Check out the benchmark's commit, run `/appsec-review whole repo` (or `deep`, matching the benchmark), and
   score the run: `python -I <skill folder>/evals/benchmark.py ~/.appsec-review/benchmarks/<repo>.json
   ~/.appsec-review/<repo>/coverage-ledger.json`. To score a fresh run on its own, move the old ledger aside
   first; otherwise findings carried from earlier runs count too.
3. Every expected finding should be `FOUND`. `MISSED`, `REJECTED` or `DOWNGRADED` means the change lost recall:
   fix it before keeping the change. Review the extra findings it lists, and add the real ones to the benchmark.
4. **Stability.** One run proves little, because runs vary. After a significant change, run the same mode three
   to five times on the benchmark commit, each from a fresh start: move the ledger aside before each run and copy
   it out afterwards (`~/.appsec-review/<repo>/runs/run-<n>.json`). Score them together:
   `python -I <skill folder>/evals/benchmark.py ~/.appsec-review/benchmarks/<repo>.json
   ~/.appsec-review/<repo>/runs/run-*.json`. Each expected finding is `STABLE` (found in every run), `FLAKY` or
   `LOST`. Fix what makes a finding flaky (a missing sink pattern, an unclear rule, a hunter prompt) before
   keeping the change. Extras that only some runs report are either noise or real findings the other runs
   missed; check them.

## Commits

Keep commit messages to one short line. Never commit ledgers, inventories, review output or benchmarks: they
describe how to attack real systems (`.gitignore` blocks the common file names).
