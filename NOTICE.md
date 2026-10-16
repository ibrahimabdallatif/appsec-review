# Third-party notices

appsec-review includes material adapted from four projects under the MIT License, listed below with their
copyright notices; the MIT permission notice is reproduced at the end. It also credits one project whose ideas,
but none of its text, inspired parts of the skill.

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

## Ideas from Trail of Bits skills (no text reproduced)

- Source: https://github.com/trailofbits/skills (CC BY-SA 4.0, Trail of Bits)
- Ideas from its `differential-review` and `fp-check` plugins inspired three checks written independently for
  this skill: tracing removed security controls through git history, counting the callers of changed
  security code and checking its tests (`rules/00-overview.md`, "Reviewing a change"), and restating each
  candidate precisely while guarding against severity inflation (`method/verifier.md`, step 0). No text from
  that project is included, so its share-alike terms don't apply; it is credited here as inspiration.

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
