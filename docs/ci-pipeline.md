# Running appsec-review in a CI pipeline

The skill can run headless in a pipeline: a scheduled or main-branch job runs the review with `claude -p`, then a
separate gate step fails the build when the finished ledger holds findings at or above a chosen severity.

## How it works

1. **Review.** `claude -p "/appsec-review whole repo"` runs the skill in `standard` mode. The review always runs
   to completion and `claude` exits `0` whatever it finds, so this step only fails if the run itself breaks.
2. **Gate.** `method/ledger.py --fail-on <severity>` reads the finished ledger and decides the build result.

| Gate exit code | Meaning | Build |
|---|---|---|
| `0` | Ledger valid, no finding at or above the threshold | pass |
| `3` | A reported finding is at or above `--fail-on` and not waived by an accepted risk | fail |
| `1` | Ledger or accepted-risk file invalid, or inventory coverage missing | fail |
| `2` | Bad arguments | fail |

`--fail-on` takes `critical`, `bug`, `warning` or `suggestion`. Confirmed and hardening findings count by their
severity, "needs confirmation" findings by the severity they have if confirmed, and rejected findings never count.
The gate only reads the ledger after the review; it never stops a review early.

## Accepted risks

Some findings are known and accepted for a while: a compensating control elsewhere, a fix already scheduled. So
that the gate does not stay red on them, pass an accepted-risk file:

```sh
python -I <skill folder>/method/ledger.py ~/.appsec-review/<repo>/coverage-ledger.json \
  --inventory ~/.appsec-review/<repo>/inventory.json --fail-on bug \
  --accepted ~/.appsec-review/accepted-risks/<repo>.json
```

```json
{"accepted": [
  {"id": "legacy-orders-idor",
   "paths_any": ["src/legacy/OrderController"],
   "text": "order.*(owner|idor|caller)",
   "max_severity": "bug",
   "reason": "Endpoint removed in the Q1 release; the gateway blocks cross-tenant order ids until then",
   "accepted_by": "payments security review, 2026-10-16",
   "expires": "2027-01-31"}
]}
```

- **Matching.** An entry matches a finding when one of its paths contains a `paths_any` substring and its key or
  title matches the `text` regex (case-insensitive), the same matcher as the benchmarks. A fresh run that names the
  issue differently still matches.
- **Limits.** A matched finding stops blocking only until `expires`, and only while it is no more severe than
  `max_severity`. An expired acceptance, or a finding that has grown more severe, blocks again and the gate says
  why. Every field is required.
- **Nothing is hidden.** Waived findings are printed as `ACCEPTED` with the reason and expiry, and entries that
  match no reported finding are printed as `UNUSED`, so fixed issues can be removed from the file.
- **Keep it private and reviewed.** The file describes open vulnerabilities. Keep it outside the repository (the
  path above survives the fresh ledger each build), for example as a secret file credential in Jenkins or in a
  private repository where changes need a security reviewer's approval. Keep expiry dates short.

## SARIF for code scanning

`--sarif <file>` writes the reported findings of a valid ledger as SARIF 2.1.0, so they show up as annotations in
GitHub code scanning, the Jenkins Warnings plugin or any other SARIF viewer. It needs no `--fail-on` and does not
change the exit code; it is not written when the ledger is invalid.

- One result per affected path, at the line the ledger gives (line 1 when it names only the file).
- `critical` and `bug` are errors, `warning` a warning, `suggestion` a note; GitHub's `security-severity` is set
  so alerts show as critical, high, medium or low. "Needs confirmation" findings use the severity they would have.
- Rejected findings are left out. With `--accepted`, waived findings are included but marked as suppressed, with
  the reason and expiry.
- Each result carries the finding key as its rule id and fingerprint, so an alert stays the same alert when lines
  move, as long as the key stays the same.
- Messages hold only the finding's title, never the attack steps. Code scanning alerts are still a list of open
  weaknesses: check who can see them in that repository before uploading.

Jenkins, with the Warnings Next Generation plugin, after the gate step (the file must be inside the workspace):

```groovy
sh 'python -I "$SKILL_DIR/method/ledger.py" "$REVIEW_DIR/$(basename "$PWD")/coverage-ledger.json" --sarif appsec.sarif'
recordIssues(tools: [sarif(pattern: 'appsec.sarif', id: 'appsec-review', name: 'appsec-review')])
```

GitHub Actions, in a job with `permissions: security-events: write` and `SKILL_DIR`, `REVIEW_DIR` and `REPO` set
as in the review step:

```yaml
- run: python -I "$SKILL_DIR/method/ledger.py" "$REVIEW_DIR/$REPO/coverage-ledger.json" --sarif appsec.sarif
- uses: github/codeql-action/upload-sarif@v4
  with:
    sarif_file: appsec.sarif
    category: appsec-review
```

## Requirements on the build agent

- Node.js 18+ for the Claude Code CLI (`npm install -g @anthropic-ai/claude-code`).
- Python 3 available as `python` (the skill calls `python -I`; on Debian or Ubuntu install `python-is-python3`).
- git, and a full clone of the repository (the review reads history for changed security code).
- An Anthropic API key stored as a CI secret and exposed as `ANTHROPIC_API_KEY`.
- Optional: gitleaks, trivy or osv-scanner, semgrep, and the ecosystem's audit tool. The skill runs them when
  present and never installs them.

## Jenkins example

```groovy
pipeline {
  agent { label 'linux' }

  triggers { cron('H 2 * * *') }      // nightly; see "When to run it"

  options {
    timeout(time: 90, unit: 'MINUTES')
    disableConcurrentBuilds()
  }

  parameters {
    choice(name: 'FAIL_ON', choices: ['critical', 'bug', 'warning'],
           description: 'Fail the build on findings at or above this severity')
  }

  environment {
    ANTHROPIC_API_KEY = credentials('anthropic-api-key')   // Jenkins secret text credential
    SKILL_REF  = '<skill commit sha>'                       // pin the skill version; bump deliberately
    SKILL_SRC  = "${env.HOME}/appsec-review-src"            // checkout of the skill repository
    SKILL_DIR  = "${env.HOME}/.claude/skills/appsec-review"
    REVIEW_DIR = "${env.HOME}/.appsec-review"              // outside the workspace: ledgers hold attack details
    ACCEPTED   = credentials('appsec-accepted-risks')       // secret file; drop it and --accepted if unused
  }

  stages {
    stage('Install') {
      steps {
        sh '''
          npm install -g @anthropic-ai/claude-code
          rm -rf "$SKILL_SRC" "$SKILL_DIR"
          git clone -q https://github.com/ibrahimabdallatif/appsec-review.git "$SKILL_SRC"
          git -C "$SKILL_SRC" checkout -q "$SKILL_REF"
          mkdir -p "$(dirname "$SKILL_DIR")"
          cp -r "$SKILL_SRC/skills/appsec-review" "$SKILL_DIR"
        '''
      }
    }

    stage('Security review') {
      steps {
        sh '''
          REPO=$(basename "$PWD")
          rm -rf "$REVIEW_DIR/$REPO"          # fresh ledger: score this commit, not earlier runs
          mkdir -p "$REVIEW_DIR"
          claude -p "/appsec-review whole repo" \
            --add-dir "$REVIEW_DIR" \
            --allowedTools "Read,Grep,Glob,Agent,Write,Edit,Bash(git:*),Bash(python:*),Bash(gitleaks:*),Bash(trivy:*),Bash(semgrep:*)" \
            > "$REVIEW_DIR/$REPO-review.txt"
        '''
      }
    }

    stage('Gate') {
      steps {
        script {
          def repo = sh(script: 'basename "$PWD"', returnStdout: true).trim()
          def code = sh(returnStatus: true, script: """
            python -I "\$SKILL_DIR/method/ledger.py" \
              "\$REVIEW_DIR/${repo}/coverage-ledger.json" \
              --inventory "\$REVIEW_DIR/${repo}/inventory.json" \
              --fail-on ${params.FAIL_ON} \
              --accepted "\$ACCEPTED"
          """)
          if (code == 3) { error("Security findings at or above '${params.FAIL_ON}'") }
          if (code != 0) { error("Review incomplete or ledger invalid (exit ${code})") }
        }
      }
    }
  }
}
```

The same three steps (install, review, gate) carry over to GitHub Actions, GitLab CI or any other runner: map the
credential to `ANTHROPIC_API_KEY`, run the review, then run the gate and fail the job on a non-zero exit.

## Choices made in the example

- **Narrow permissions.** `--allowedTools` lets Claude read code, run git and Python, start the hunter and
  verifier subagents, and use the listed scanners. `--add-dir` limits writes outside the checkout to the ledger
  folder. Avoid `--dangerously-skip-permissions`.
- **Pinned skill version.** `SKILL_REF` keeps a rule change in the skill from changing CI results until you
  update it on purpose.
- **Fresh ledger per build.** Deleting the previous ledger makes each build score its own commit. On a persistent
  agent you may keep it instead, so later runs re-verify earlier findings ("Later runs" in
  `method/coverage-ledger.md`); then pin `SKILL_REF` and expect the ledger to grow.
- **Findings stay private.** The review output and the ledger describe how to attack open issues. The example keeps
  them outside the workspace and does not archive them. If you archive them, restrict who can read the job.

## When to run it

- **Nightly or on the main branch:** `standard` mode on the whole repository, as in the example. This is the
  intended CI use.
- **High-stakes services:** a scheduled `deep` run (`/appsec-review deep`) takes several times longer and uses
  much more tokens; run it weekly or before a release rather than on every build.
- **Pull requests:** not supported for gating yet. `diff` mode, the right mode for a PR, writes no ledger, so the
  gate has nothing to read. Run `diff` reviews on PRs for their report only, and gate on the nightly run.

## Cost and time

A `standard` run uses the main session plus one hunter and one verifier subagent, and one more verifier when a
`critical` or `bug` candidate is rejected or chains are found, all on the session's model. Time and tokens grow
with the size of the repository, because every in-scope module is read. The run summary at the end of the review
output gives the time and token figures for each build; use them to set the job timeout and schedule.
