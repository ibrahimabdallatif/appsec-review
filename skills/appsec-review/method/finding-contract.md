# Finding contract

This file names the fields a review already produces. It is not a new schema. `method/ledger.py` is the
validator for the ledger, `SKILL.md` "Output" is the terminal result, and `report/REPORT.md` is the
report card. Do not invent a parallel JSON format. If a script that writes the ledger, the SARIF file, or
the report fails, put that error in the result. Do not drop the finding or invent a missing value.

## Ledger finding

`method/ledger.py` requires `key`, `title`, `decision`, `severity` and `paths` on every finding.

| Field | Role |
|---|---|
| `key` | Stable root-cause id. No line numbers. One key per weakness, shared when the same weakness is platform-wide |
| `title` | The weakness in words. At least three words, never a bare id such as `C9` |
| `decision` | `confirmed`, `needs_confirmation`, `rejected`, or `hardening` |
| `severity` | `critical`, `bug`, `warning`, or `suggestion`. Null for `needs_confirmation` and `rejected` |
| `paths` | Repository-relative locations (`path` or `path:line`). Evidence the coordinator can reopen |
| `severity_if_confirmed` | Required for `needs_confirmation`. The severity used if the missing fact is unsafe |
| `disproof` | Required for `rejected`: a `path:line` of the control that stops the attack. Forbidden otherwise |
| `proposed_severity` | Required for `rejected`: the severity the candidate had before verification |
| `rejection_reviewed` | Required true for a rejected `critical` or `bug`. Set only after a second agent upholds it (`method/orchestration.md`) |
| `layer` | `backend`, `web-frontend`, or `mobile` when the repository has more than one layer |

`decision`, `severity` and the CVSS score are different facts. CVSS is computed later by
`report/cvss40.py` and stored in the report, not estimated into `severity`. Confidence is the
verification label in the result: independent verifier, rejection reviewed, or self-verified sequential
fallback. Do not fold that label into the severity.

A candidate is not a finding. Hunters return candidates in the JSON shape in `method/hunters.md`. Only
verifier decisions are copied into the ledger.

## Coverage

Each ledger unit has `id`, `surface`, `area`, `status`, `reviewed_paths`, `checks`, `finding_keys` and
`unresolved`. `method/ledger.py --inventory` fails the run when an inventory entry point has no unit or a
sink file was not read under its category. Do not report full coverage when that command prints an error
or when units are `blocked` or `deferred`; list those units.

## Terminal result and report

The terminal block in `SKILL.md` carries the attack, the impact and the fix for each reported finding,
plus the rejected list with its disproof line. The report card in `report/REPORT.md` adds the CVSS 4.0
vector and score, references, the proof excerpt and the verification label. Build both from the same
findings. SARIF (`method/sarif.py`) carries the title and the location, not the attack steps, so a code
scanning upload does not become a copy of the exploit write-up.

`needs_confirmation` stays in the reported list. `rejected` stays in the ledger and in the rejected list,
and stays out of the report's vulnerability section. A conclusion without a reopened `path:line` is not a
confirmed finding.
