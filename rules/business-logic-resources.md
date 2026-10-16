---
paths:
  - "**/*.{java,kt,scala,groovy,ts,tsx,js,jsx,mjs,cjs,vue,svelte,py,go,cs,rb,php,rs,dart,swift}"
---

# Business logic, abuse and resource consumption

OWASP A06:2025, API4/API6:2023, ASVS V2/V15, WSTG-BUSL, PCI DSS 6.2.4. CWE-841, CWE-837, CWE-362, CWE-367, CWE-770,
CWE-400, CWE-190, CWE-681, CWE-1284, CWE-204, CWE-602.

## Workflow integrity
- Multi-step flows (verify, then confirm, then execute) must enforce order on the server. Flag steps that can be
  skipped, repeated or called directly, and step state taken from the client. (CWE-841)
- Limits, eligibility, status, ownership and cut-off times must be enforced on the server: in this service, or in
  the downstream system of record it calls. Flag rules enforced only in the client (mobile app, web front end,
  caller-supplied flags), and server code that assumes the client already checked. (CWE-602)
- Verification results (KYC, identity, document, payment status) must be fetched or verified by the server from
  the trusted provider. Flag status flags accepted from the client or trusted from a client-relayed response.
- Amounts, fees, FX rates, prices and debit accounts must be computed or resolved on the server. Flag
  client-supplied prices, fees, rates, balances or source accounts that are trusted.

## Money and numbers
- Use a decimal type with explicit scale and rounding, or integer minor units, for money (`BigDecimal`,
  `decimal.Decimal`, `System.Decimal`, a decimal library in JavaScript). Flag binary floating point (`double`,
  `float`, JavaScript `number` for amounts with fractions), lossy conversions and unchecked parsing. (CWE-681)
- Reject negative, zero, oversized or over-precise amounts and quantities. Flag arithmetic that can overflow or
  change sign. (CWE-1284, CWE-190)

## Concurrency, replay and idempotency
- Operations that move money, change state or use one-time proofs must be atomic and idempotent. Flag
  check-then-act on balances, limits, counters or one-time tokens without locking, a unique constraint or an atomic
  update. (CWE-362, CWE-367)
- Rate limits and attempt counters must check and increment in one atomic operation (DB update with a condition,
  or a distributed limiter), or parallel requests exceed them. In-memory limiters don't hold across several
  instances.
- Flag one-time actions that can run twice through replay, double submit or parallel requests, and creation flows
  that can make duplicate accounts or records for the same subject. (CWE-837)
- Retries on non-idempotent calls must not cause duplicate effects.

## Abuse of sensitive business flows
- Flows attractive to automation (OTP send, login, password reset, card data reveal, registration, beneficiary add,
  transfers, messaging) need per-user, per-device or per-IP rate limits on the server. (API6)
- Flag endpoints that send SMS, email or push messages, or cost money per call, with no throttling (SMS pumping,
  cost abuse). Flag message endpoints where the caller controls the recipient, the content or an HTML flag.
- Identity lookups, login and recovery must not reveal whether a user, card or account exists: same status, body
  shape, message and similar timing either way. (CWE-204, CWE-208)
- Rate limits keyed on client IP must use the real peer address. Flag IPs read from `X-Forwarded-For`, `X-Real-IP`
  or `Forwarded` without a trusted-proxy setup, because attackers can rotate those headers freely.

## Resource consumption
- Flag unbounded page sizes, list lengths, request body or upload sizes, regexes on user input (ReDoS) and loops
  driven by client values. (API4, CWE-770, CWE-400)
- Outbound calls must have connect and read timeouts. Flag HTTP clients without them, and unbounded retries.
- Thread pools, caches, queues and event loops must be bounded and must not be blocked. Flag unbounded executors,
  blocking I/O on shared pools or the event loop, and caches with no size or TTL.
