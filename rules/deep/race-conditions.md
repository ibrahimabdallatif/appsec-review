---
parent: business-logic-resources
when: "a check followed by an action on shared state: balances, limits, quotas, counters, one-time codes or tokens, coupons, uniqueness checks, file checks, or shared in-memory state used by concurrent requests or workers"
---

# Deep: race conditions

`deep` mode only. Extends `business-logic-resources.md` "Concurrency, replay and idempotency". A06:2025,
CWE-362, CWE-367, CWE-366, CWE-662.

## Method
For each shared resource (database row, cache key, counter, file, singleton or static field), ask who else
touches it concurrently and whether the decision and the action are one atomic step. A race finding states an
**interleaving**: two orders of the same operations, one safe and one reachable by an attacker that is not.

1. **Check-then-act without atomicity.** "If balance ≥ n, deduct n"; "if not used, redeem"; "if not exists,
   create"; "if attempts < 5, try". Two requests both pass the check before either acts: double-spend, limit
   overrun, coupon or OTP reuse, duplicate accounts, attempt counters beaten by parallel requests. Look for the
   control: a transaction at the right isolation level, `SELECT … FOR UPDATE`, a unique constraint, a conditional
   update with its affected-row count checked, an atomic counter (Redis `INCR`, Lua), or a distributed lock held
   across both steps.
2. **TOCTOU.** A value is validated, then used, and can change in between: file `exists`/`stat` then `open`,
   permission checked then the object re-read, a token checked then consumed later.
3. **Unsynchronised shared state.** Fields, maps or counters in singletons, static members, module globals or
   request-scoped context reused across requests or async tasks, written without a lock or atomic. In Node,
   watch shared objects mutated across `await` points; in Java and .NET, singleton beans and services with
   mutable fields.
4. **Compound updates.** Several fields that must change together (balance and ledger entry, status and amount)
   updated outside one transaction, so a concurrent reader or writer sees or creates a torn state.
5. **Lock misuse.** The lock is taken after the read, released before the write, differs between reader and
   writer, is in-process only while the service runs several instances, or covers some paths but not others.
6. **Confirm or rule out from source.** Confirm with the shared resource, the check line, the act line, and the
   interleaving. Rule out only by citing the atomic control that spans both steps on every path.

## Rationalizations to reject
- "There is a check right above it." Unless check and act are atomic, the gap between them is the bug.
- "There is a lock in the function." Does it span both the decision and the action, on every path, with the same
  lock as every writer, across every instance?
- "Requests are basically serial." Assume concurrency unless the runtime guarantees otherwise.
- "The database will sort it out." Only with a transaction at the right isolation, a constraint, or a
  conditional update. A plain read-then-write won't.

Adapted from `detecting-race-conditions` in UnboundCompute/security-agent-skills (MIT License, copyright 2026
Riyan Dhiman).
