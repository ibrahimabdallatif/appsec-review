---
name: appsec-review
description: "Use only when the user explicitly invokes appsec-review (/appsec-review on Claude Code and Cursor, $appsec-review or /skills on Codex) for a diff, branch, PR, file, endpoint, the whole repository, or every repository under a directory. Manual pentest-style security review of Spring, Node.js, Python, PHP (Laravel, Symfony, WordPress), .NET and Go back ends, browser front ends (React, Next.js, Angular, Vue, Svelte), mobile apps (React Native, Flutter, native Android and iOS), Supabase and Firebase against OWASP Top 10:2025, OWASP API Top 10:2023, ASVS 5.0, MASVS, MASTG, Mobile Top 10:2024, CWE Top 25, PCI DSS, NIST SP 800-63B-4, RFC 9700, RFC 8252 and RFC 10017, with verified findings, CVSS 4.0 scores and SARIF export. Do not run for a general security question. Keywords: security review, appsec, pentest, vulnerability, OWASP, IDOR, threat model, STRIDE, CVSS, SARIF"
license: MIT
compatibility: "Python 3.10+ on PATH as python (standard library only). Git for diff and branch reviews. Read-only unless the user asks for fixes. Parallel subagents only when the host can spawn them; otherwise the same steps run sequentially."
metadata:
  internal: true
disable-model-invocation: true
---

# appsec-review

This file is a discovery adapter. The methodology, rules and scripts are not stored here.

The canonical skill directory is `../../../skills/appsec-review` relative to this file. Read `../../../skills/appsec-review/SKILL.md` and follow it. That directory is the skill folder for every `rules/`, `method/` and `report/` path.

If that file is missing, this adapter was separated from the repository. Stop. Install the canonical `skills/appsec-review` folder from https://github.com/ibrahimabdallatif/appsec-review. Do not review code from this adapter alone.

Do not modify the application under review, commit, push, or publish a report unless the canonical skill says the user asked for that.
