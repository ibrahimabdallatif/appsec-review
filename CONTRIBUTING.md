# Contributing

The skill lives in `skills/appsec-review/`; paths below are relative to that folder, and test commands run
from the repository root. This guide is for changing the skill itself: its rules, method, scripts and report. It is kept out of `SKILL.md`
so a review never loads it. For how a review runs, see [docs/how-it-works.md](docs/how-it-works.md).

## Layout and where changes go

| Change | Where | Never in |
|---|---|---|
| What the review checks | `rules/` category files, `rules/stacks/`, `rules/deep/` | `SKILL.md` |
| How the review runs (ledger, hunters, verification, inventory) | `method/` | `rules/` |
| Report structure, scoring, design | `report/` (`REPORT.md`, `cvss40.py`, `report-template.html`) | `rules/` |
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
python -I skills/appsec-review/method/test_inventory.py      # inventory.py, inventory_patterns.py
python -I skills/appsec-review/method/test_ledger.py         # ledger.py (validator, inventory coverage, --fail-on gate)
python -I skills/appsec-review/method/test_accepted_risks.py # accepted_risks.py (--accepted for the gate)
python -I skills/appsec-review/method/test_sarif.py          # sarif.py (--sarif export)
python -I skills/appsec-review/method/test_threat_model.py   # threat_model.py (threat model, abuse paths, chains)
python -I skills/appsec-review/method/test_run_stats.py      # run_stats.py
python -I skills/appsec-review/evals/test_benchmark.py       # benchmark.py
python -I skills/appsec-review/report/test_cvss40.py         # cvss40.py
python -I skills/appsec-review/report/cvss40.py --selftest   # cvss40.py against FIRST reference scores
python -I skills/appsec-review/report/test_embed_logos.py    # embed_logos.py
python -I skills/appsec-review/report/test_build_sample.py   # build_sample.py (fails when docs/sample-report.* is out of date)
```

After changing `report-template.html` or `report/sample/acme-shop.json`, rebuild the public sample report with
`python -I report/build_sample.py` and commit `docs/sample-report.html` and `docs/sample-report.md` with the change.
Keep the fixture fictional: never copy names, paths or code from a real review into it.

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
   List decoys under `absent` (`id`, `paths_any`, `text`): code that looks vulnerable but is safe, such as a
   guarded admin route or a parameterised query built in pieces. They measure false positives.
2. Check out the benchmark's commit, run `/appsec-review whole repo` (or `deep`, matching the benchmark), and
   score the run: `python -I <skill folder>/evals/benchmark.py ~/.appsec-review/benchmarks/<repo>.json
   ~/.appsec-review/<repo>/coverage-ledger.json`. To score a fresh run on its own, move the old ledger out of
   `~/.appsec-review/<repo>/` first; otherwise findings carried from earlier runs count too.
3. Every expected finding should be `FOUND`. `MISSED`, `REJECTED` or `DOWNGRADED` means the change lost recall:
   fix it before keeping the change. Every decoy should be `CLEAN` or `REJECTED`; `FALSE-POSITIVE` means the
   change lost precision, and the scorer prints the precision over labelled findings. Review the extra findings
   it lists: add the real ones to `expected` and the false ones to `absent`.
4. **Stability.** One run proves little, because runs vary. After a significant change, run the same mode three
   to five times on the benchmark commit, and keep the runs independent:
   - start each run in a **new Claude Code session**, so it can't reuse what an earlier run found;
   - before each run, empty `~/.appsec-review/<repo>/` of everything but `inventory.json`; after it, move the
     ledger to a folder outside it, such as `~/.appsec-review/benchmark-runs/<repo>/<mode>-<n>.json`. A run
     looks in its own folder, and a saved run or a moved-aside ledger there turns the next run into a copy.

   A run is suspect if its ledger shares asset ids, abuse path slugs and extra findings, in the same order, with
   another run. Score them together: `python -I <skill folder>/evals/benchmark.py
   ~/.appsec-review/benchmarks/<repo>.json ~/.appsec-review/benchmark-runs/<repo>/standard-*.json`. Each
   expected finding is `STABLE` (found in every run), `FLAKY` or
   `LOST`, and each decoy any run reported is listed with its run count. Fix what makes a finding flaky (a missing sink pattern, an unclear rule, a hunter prompt) before
   keeping the change. Extras that only some runs report are either noise or real findings the other runs
   missed; check them.

## Commits

Keep commit messages to one short line. Never commit ledgers, inventories, review output or benchmarks: they
describe how to attack real systems (`.gitignore` blocks the common file names).
