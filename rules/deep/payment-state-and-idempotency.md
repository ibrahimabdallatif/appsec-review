---
parent: business-logic-resources
when: "code that moves an order, payment, transfer, refund, payout, card or account through states, or releases value (fulfilment, refund, payout, credit, limit change)"
---

# Deep: payment state machine and idempotency

`deep` mode only. Extends `business-logic-resources.md` "Workflow integrity" and "Concurrency, replay and
idempotency". A06:2025, API6:2023, CWE-841, CWE-837, CWE-362, CWE-799.

## Method
1. **Write the intended state machine.** List the legal states, the only allowed transitions, and which
   transition each value-releasing action (fulfilment, refund, payout, credit, limit increase) requires first.
   The diagram is usually unwritten; derive it from enums, status columns and service methods.
2. **Paid-state precondition.** Find where the state that gates value release is set. It must follow
   provider-confirmed settlement, not an authorisation hold, a client-supplied status, or a request flag.
3. **Skipped and out-of-order steps.** For each transition, check the handler validates the current state on the
   server before moving it. Flag handlers that set a later state directly, accept the target state from the
   client, or can be called without their prerequisite (verification, OTP step, approval, settlement).
4. **Idempotency of value-releasing handlers.** Charge, fulfilment, refund, payout and credit handlers must act
   once per logical operation: an idempotency key enforced by a unique constraint or atomic insert, or a
   conditional state update (`UPDATE … WHERE status = 'PENDING'`) whose affected-row count is checked. Flag keys
   read but not enforced, keys skipped on some routes, and retries of non-idempotent downstream calls.
5. **Refund and cancel symmetry.** A refund may return only captured value, at most once in total across partial
   refunds, and must move the state so it cannot repeat. Flag refunds that credit without reversing the capture,
   ignore pending refunds when checking the remaining amount, or can run concurrently.
6. **Confirm or rule out from source.** Confirm with the transition or handler line and the missing precondition,
   state check or idempotency control, and the sequence of requests that releases value twice or without payment.

## Where it leaks
- Paid set on authorisation or on a client-reported result.
- A value-releasing state reachable without the steps before it.
- An idempotency interceptor that skips the routes that move money.
- Duplicate-refund checks that count only completed refunds, not pending ones.
- State moved by a plain read-then-write, so two requests both pass.

## Rationalizations to reject
- "The payment page redirected with success." Confirm settlement server-side with the provider.
- "The charge was authorised." Authorisation is not settlement.
- "Retries are just network noise." A non-idempotent handler turns every retry into a double charge or payout.
- "Refunds go through the finance team." If the endpoint can repeat or over-credit, it is a payout primitive.
- "The client tracks the order state." Derive every transition from server-confirmed events.

Adapted from `auditing-payment-state-machine-and-idempotency` in UnboundCompute/security-agent-skills
(MIT License, copyright 2026 Riyan Dhiman).
