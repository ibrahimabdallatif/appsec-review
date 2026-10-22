# Platforms

One skill folder, `skills/appsec-review/`, holds the methodology, rules, scripts and report template. Claude
Code, Cursor and Codex do not each get a copy. Thin adapters exist only so a host that does not scan
`skills/` can still find `SKILL.md` when this repository is the workspace.

| Host | Adapter in this repository | What it loads |
|---|---|---|
| Claude Code | `.claude/skills/appsec-review/SKILL.md` | Points at `skills/appsec-review/SKILL.md` |
| Cursor | `.cursor/skills/appsec-review/SKILL.md` and `.agents/skills/appsec-review/SKILL.md` | The same pointer |
| Codex | `.agents/skills/appsec-review/SKILL.md` | The same pointer |

The adapters set `metadata.internal: true`. The skills CLI (`npx skills add`) skips internal skills unless
`INSTALL_INTERNAL_SKILLS=1`, and it discovers `skills/appsec-review/` first, so an install copies the full
skill rather than an adapter. Cursor may list the skill more than once while this repository is open, because
it reads `.cursor/skills/`, `.agents/skills/` and `.claude/skills/`. Each entry is the same adapter.

Live skill invocation was not executed on Claude Code, Cursor, or Codex in this change. The checks that did
run are the Python suites, including `method/test_layout.py`, `method/test_install_links.py` and
`method/test_parallel_mode.py`. Claude Code `2.1.306` was present on the machine used for that work. The
Codex CLI was not installed. `cursor.cmd` launches the editor; it was not used as a skill runner.

Documentation checked on 2026-10-22:

- Claude Code skill paths: project `.claude/skills/`, user `~/.claude/skills/`. Claude Code's skill page does not list `.agents/skills/`.
- Cursor skill paths: project `.agents/skills/` and `.cursor/skills/`, user `~/.agents/skills/` and `~/.cursor/skills/`, plus Claude and Codex compatibility directories. Invocation is `/` then the skill name.
- Codex skill paths: repository `.agents/skills/` from the working directory up to the repo root, user `$HOME/.agents/skills`. Codex follows symlinks. Invocation is `/skills` or `$` then the skill name. Older global installs also use `~/.codex/skills/`.
- Skills CLI agent ids: `claude-code` (`.claude/skills/`), `cursor` (project `.agents/skills/`, global `~/.cursor/skills/`), `codex` (project `.agents/skills/`, global `~/.codex/skills/`).

## Install for every repository you review

Python 3.10 or newer must be on `PATH` as `python`. The helper scripts use the standard library and are run
with `python -I` so they do not import the repository under review. Git is required for diff, branch and
multi-repository reviews. Optional scanners (gitleaks, trivy, osv-scanner, semgrep, and the ecosystem audit
tools named in `SKILL.md`) are used when they are already installed. The skill does not install them.

From a clone of this repository, link the canonical folder into the user directories (no copy):

```sh
python -I skills/appsec-review/method/install_links.py
```

That creates directory links:

| Path | Hosts that read it |
|---|---|
| `~/.claude/skills/appsec-review` | Claude Code |
| `~/.cursor/skills/appsec-review` | Cursor |
| `~/.agents/skills/appsec-review` | Codex, and Cursor |
| `~/.codex/skills/appsec-review` | Codex builds and the skills CLI that still use this global path |

The command refuses to replace a real directory. `--replace` retargets an existing link only. `--dry-run`
prints the paths and writes nothing. `--home` and `--skill-dir` are for tests and non-default locations.

Or let the skills CLI copy the canonical folder (Node.js required; the CLI's current Node requirement is its
own, separate from the skill):

```sh
npx skills add ibrahimabdallatif/appsec-review --skill appsec-review -g -a claude-code -a cursor -a codex -y
```

A copy does not track later edits in your clone. Re-run the command, or `npx skills update`, to refresh it.
A link from `install_links.py` stays on the clone you linked.

To install only inside one repository, drop `-g`. The CLI then writes that repository's project skill
directory (`.claude/skills/` or `.agents/skills/`, depending on the agent). Prefer a user-level link when you
review many repositories.

## Invoke

Open the repository to review, not the skill repository, after a user-level install.

| Host | First review | Whole repository | Deep | Sequential |
|---|---|---|---|---|
| Claude Code | `/appsec-review` | `/appsec-review whole repo` | `/appsec-review deep` | `/appsec-review whole repo` and say sequential |
| Cursor | `/appsec-review` | `/appsec-review whole repo` | `/appsec-review deep` | the same, and say sequential |
| Codex | `/skills`, then appsec-review, or `$appsec-review` | ask for the whole repository | say deep | say sequential |

With no scope, the review is `diff`: the current branch against its base (`develop` if it exists, otherwise
`main`) plus uncommitted changes. `deep` runs only when you say deep.

## Parallel and sequential

The default is parallel: `standard` and `deep` spawn the hunters and verifiers in `method/hunters.md` and
`method/verifier.md` when the host can. `diff` stays inline except for one verifier when a `critical`
candidate survives the disproof pass.

Sequential runs the same steps in the coordinator session. Choose it by saying so in the prompt, or set
`APPSEC_REVIEW_PARALLEL=0` (also `false`, `off`, `no`, `sequential`) in the environment of the session. `1`,
`true`, `on`, `yes` and `parallel` keep the default. Any other value makes `method/parallel_mode.py` exit 2
and the review stops.

If a spawn fails, the coordinator finishes that role inline, says so, and does not retry in a loop. A
rejected `critical` or `bug` is recorded as `rejected` only after a second agent upholds it. Without that
agent it stays `needs_confirmation`, so the ledger is not given a `rejection_reviewed` flag the second
verifier did not earn.

## Output and CI

Reports and ledgers go to `~/.appsec-review/<repo>/` (`report.html`, `report.md`, `inventory.json`,
`coverage-ledger.json`). They are not written into the repository. Publishing a claude.ai artifact happens
only on Claude Code, and only when you ask. Cursor and Codex stop at the local files.

The CI gate and SARIF export do not care which host wrote the ledger:

```sh
python -I <skill folder>/method/ledger.py ~/.appsec-review/<repo>/coverage-ledger.json \
  --inventory ~/.appsec-review/<repo>/inventory.json --fail-on critical --sarif appsec.sarif
```

[ci-pipeline.md](ci-pipeline.md) shows a Claude Code headless example. The gate commands are the portable
part. A Cursor or Codex review is not given a CI recipe here, because those hosts were not run headless in
this change.

## Security

The review reads code. It does not modify the application, commit, push, install packages, or run the
repository's own scripts unless you explicitly ask for a fix afterwards. Fixes are a separate step. Scanners
run only if they are already installed. Ledgers and reports describe open attacks; keep them outside the
repository and do not upload them by habit.

## Troubleshooting

| What you see | What to check |
|---|---|
| The skill is not in the `/` menu | The host was started before the adapter or link existed. Restart it. On Cursor, look in Customize → Skills. A global `~/.cursor/skills/` copy and this repo's adapters can both appear. |
| The agent cannot find `rules/` | It followed an adapter that was copied without `skills/appsec-review/`. Install the canonical folder, not `.claude/skills/appsec-review` from this repo alone. |
| `python` is missing | Install Python 3.10+ and, on Debian or Ubuntu, `python-is-python3`. The skill calls `python -I`. |
| `parallel_mode.py` exits 2 | `APPSEC_REVIEW_PARALLEL` is not one of the values listed above. |
| A link install refuses a destination | A real directory is already there. Move it aside yourself. `--replace` will not delete it. |
| Windows reports that it cannot create a symlink | `install_links.py` falls back to a junction. If that fails, the printed error is the one to use; do not copy the tree by hand unless you accept that updates will not follow the clone. |
| Codex never spawns a hunter | Sequential fallback is the supported behaviour. The result must say so. Do not treat a missing subagent as a passed parallel run. |
| Two Cursor entries named appsec-review | Expected while this repository is open. Both adapters point at the same canonical folder. |

## Adding rules

Framework checks and stack patterns stay in `skills/appsec-review/`. [CONTRIBUTING.md](../CONTRIBUTING.md)
is the procedure. Do not add a second copy under `.claude/`, `.cursor/` or `.agents/`.
