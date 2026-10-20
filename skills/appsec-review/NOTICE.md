# Third-party notices

appsec-review includes material adapted from four projects under the MIT License, listed below with their
copyright notices; the MIT permission notice is reproduced at the end. It ports one project under the BSD
2-Clause License, whose notice follows its entry. It also credits two projects whose ideas, but none of their
text, inspired parts of the skill.

## Cloudflare security-audit

- Source: https://github.com/cloudflare/security-audit-skill
- Copyright (c) 2025-2026 Cloudflare, Inc.
- Adapted in: `method/hunters.md` (wildcard and obvious-things hunter prompts), and the ideas behind
  `method/verifier.md` (independent verification that tries to disprove each candidate) and
  `method/coverage-ledger.md` (coverage units, statuses and reuse across runs).

## software-security-appsec

- Source: https://github.com/vasilyu1983/AI-Agents-public (skills/universal/software-security-appsec)
- Copyright (c) 2024-2026 Vasiliy Uvarov
- Adapted in: `rules/ai-llm-agents.md` (agentic and LLM threat-to-control guidance) and the supply-chain
  additions in `rules/configuration-supply-chain.md`.

## security-agent-skills

- Source: https://github.com/UnboundCompute/security-agent-skills
- Copyright (c) 2026 Riyan Dhiman
- Adapted in: `rules/deep/*.md` (object-level authorization, payment callback integrity, payment state and
  idempotency, race conditions, business-logic flaws) and the "reasons that never justify rejected" list in
  `method/verifier.md`.

## AppSec Untangled resources

- Source: https://github.com/mohamed-osama-aboelkheir/appsec-untangled-resources
- Copyright (c) 2026 Mohamed AboElKheir
- Adapted in: `rules/00-overview.md` (the "who should be able to do this" list per entry point, and "Judge the
  code, not its reputation") and `rules/access-control.md` (check-one-id-act-on-another, check-then-change and
  type-mismatch bypass checks).

## FIRST CVSS v4.0 calculator

- Source: https://github.com/FIRSTdotorg/cvss-v4-calculator
- Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors
- Ported in: `report/cvss40.py` (the base score algorithm and its MacroVector lookup, max-vector and
  max-severity tables, translated from `cvss_score.js`, `cvss_lookup.js`, `max_composed.js` and
  `max_severity.js`).

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
   following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
   following disclaimer in the documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Ideas from Trail of Bits skills (no text reproduced)

- Source: https://github.com/trailofbits/skills (CC BY-SA 4.0, Trail of Bits)
- Ideas from its `differential-review` and `fp-check` plugins inspired three checks written independently for
  this skill: tracing removed security controls through git history, counting the callers of changed
  security code and checking its tests (`rules/00-overview.md`, "Reviewing a change"), and restating each
  candidate precisely while guarding against severity inflation (`method/verifier.md`, step 0). No text from
  that project is included, so its share-alike terms don't apply; it is credited here as inspiration.

## Ideas from autoresearch (no text reproduced)

- Source: https://github.com/uditgoenka/autoresearch (MIT, Copyright (c) 2026 Udit Goenka)
- Its `/autoresearch:security` command's `--fail-on <severity>` flag inspired the CI gate in `method/ledger.py`
  (`--fail-on`), written independently for this skill. No text or code from that project is included; it is
  credited here as inspiration.

## MIT License (applies to each MIT project above)

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and
to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of
the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO
THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF
CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
IN THE SOFTWARE.
