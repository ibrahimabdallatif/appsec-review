# Orchestration

The review steps stay in `SKILL.md`. This file says who performs them and how that maps onto Claude
Code, Cursor and Codex. It does not add a second methodology. Read it once at step 0 and follow it at
steps 6, 8 and 9.

## Roles

These are responsibilities, not four processes. Do not start four agents unless the mode table already
asks for that many, and do not start any when the run is sequential.

| Role | Who | Does |
|---|---|---|
| Coordinator | The session that loaded this skill | Steps 1–5 and 7, merging, the chain pass, the gap pass, the ledger, the result and the report |
| Hunter | A fresh agent, or the coordinator when sequential | The prompts in `method/hunters.md`. Returns candidates, never findings |
| Verifier | A fresh agent that did not hunt and did not write the candidate, or the coordinator's later disproof pass when sequential | `method/verifier.md`. Does not receive the finder's reasoning |
| Coverage reviewer | The coordinator, after verification | The gap pass in `method/coverage-ledger.md` (section "How to build it", step 4). Not a subagent |

The coverage reviewer reads the ledger as a critic: missing entry points, parallel paths, units closed
without checks. A unit is `covered` only with the paths and checks the ledger requires. Statuses stay
`planned`, `covered`, `finding`, `blocked`, `deferred`, `not_applicable` and `out_of_scope`. Do not call
the review complete while inventory errors remain.

## Parallel or sequential

At step 0, run:

```text
python -I <skill folder>/method/parallel_mode.py
```

Pass `--sequential` when the user asked for a sequential run, "no subagents", or "parallel off". The
script prints `parallel` or `sequential`, a tab, and the reason. Keep both for the run summary. A
non-zero exit stops the review; report the script error and do not guess.

`parallel` means the mode tables in `method/hunters.md` and `method/verifier.md` may spawn subagents.
`sequential` means those tables' inline path, even if the host can spawn agents. `diff` already keeps
hunters inline; sequential also skips its optional critical verifier.

If `parallel` was selected but a spawn fails or the host has no delegation tool, finish that role inline
and record `sequential` in the run summary with the host's reason. Keep candidates already returned. Do
not restart the review and do not retry a failed spawn in a loop.

Subagents are read-only. Tell each one: read code only; no builds, tests, installs, network (except the
one dependency-source download `rules/00-overview.md` already allows), edits, commits, pushes, or
publishing. Do not create a git worktree for a review. Hunters and verifiers must not edit files. Fixes
are a separate step after the review, and only when the user asks; do not run those edits in parallel
against the same files.

Partition a parallel `deep` run by the mode table (one hunter for wildcard and obvious-things, one sink
tracer, verifiers split by candidate or category). Do not split one file across two writers. Review
output goes to `~/.appsec-review/<repo>/` and to the session, not into the repository.

## What a delegated agent returns

Hunters return the JSON object in `method/hunters.md`. Verifiers return the JSON array in
`method/verifier.md`. The coordinator merges candidates by stable root-cause key before verification,
keeps one candidate per key, and unions traces that disagree. The verifier's decision stands. Do not
average severities. Duplicate keys across repositories follow the multi-repository rules in `SKILL.md`.

A verifier is not independent just because it is another agent. It is independent only when it did not
hunt, did not write the candidate, and was not shown the finder's reasoning. A second pass in the same
session is the disproof pass, which the result calls self-verified.

## Rejection review when no second agent is available

`method/ledger.py` accepts a rejected `critical` or `bug` candidate only when `rejection_reviewed` is
true, which means a second verifier upheld it. Set that flag only when a different agent from the one
that rejected the candidate returns the rejection-review decision.

When no such agent can be spawned, do not set `rejection_reviewed` and do not record the decision as
`rejected`. Record `needs_confirmation` with `severity_if_confirmed` set to the proposed severity, and
the missing fact: the disproof `path:line`, plus "independent rejection review did not run" and the
sequential reason. The same rule applies when a candidate is raised to `critical` and the extra verifier
in `method/verifier.md` ("Escalation check") cannot be spawned: do not accept the new `critical` as
`confirmed`. Say so in the result and in report 2.3.

## Spawn on each host

Use the session's model. Do not invent a tool name if the host has a different one. Pass the prompt and
the context block from the method file, not the conversation history.

### Claude Code

Spawn with the Agent tool, subagent type `general-purpose`. This is the tool the existing mode tables
call "the Agent tool". Token counts are whatever that tool reports. If it reports none, pass `-` to
`method/run_stats.py` and do not estimate.

### Cursor

Spawn a fresh general-purpose subagent in readonly mode (the Task tool: `subagent_type` general-purpose,
`readonly` true, model inherit). Launch the `deep` hunters together so they run at the same time. The
built-in explore subagent is a search helper, not the verifier and not the hunter. If the Task tool is
absent, use the sequential fallback. Cursor does not report Claude's `/cost` or `/usage`; leave token
figures out when the host does not show them.

### Codex

Ask Codex to spawn a subagent, which current OpenAI documentation allows when a skill requests it. The
subagent inherits the parent sandbox; instructions to stay read-only do not create a separate sandbox, so
repeat the read-only rules in the prompt. If subagents are disabled, the spawn fails, or this Codex build
has no multi-agent tool, use the sequential fallback and say so. Do not tell the user to flip an
experimental flag as part of the review. Do not assume Claude's Agent tool, `/cost`, or `/usage`.

## Publishing and fixes

Write the local report files when `SKILL.md` says to. Do not publish them anywhere, including a private
claude.ai artifact, unless the user explicitly asks to publish. A host that cannot publish skips that
step after the user asked and says so; the local files remain. Do not upload the ledger, the inventory,
source code, or secrets.

Do not edit the application under review during the review. Change code only after the user asks for a
fix, then update or add the negative tests `SKILL.md` already requires.
