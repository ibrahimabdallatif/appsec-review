---
parent: business-logic-resources
when: "code that receives payment-provider callbacks, webhooks or redirect results, or marks an order, payment, transfer or top-up as paid or settled"
---

# Deep: payment callback and amount integrity

`deep` mode only. Extends `business-logic-resources.md` "Workflow integrity" and "Money and numbers". A06:2025,
A08:2025, API6:2023, PCI DSS v4.0 6.2.4, CWE-345, CWE-347, CWE-294, CWE-602.

## Method
1. **Name the trusted settlement signal.** Write down what the server must verify before treating a payment as
   settled: the provider's signature over the payload it acts on, the amount and currency against the order the
   server created, the notification's binding to that one order, and confirmation with the provider out of band.
   A flow that does all four is correct; each missing one is a candidate.
2. **Signature.** Find the verification of the callback or webhook signature. Check it runs before any state
   change, over the raw bytes or the exact fields acted on, with the provider's key from configuration, in
   constant time, and that a failed or missing signature stops the flow. A verify call whose result is ignored,
   or a path that skips it, is the bug.
3. **Amount and currency.** Find where the paid amount and currency are compared with the server's own order
   record. Flag amounts, currencies, fees or statuses read from the callback, redirect parameters or client and
   used without that comparison.
4. **Order binding and replay.** Check the notification is tied to one order (reference plus amount) and that a
   provider event or transaction id is single-use (unique constraint or atomic check). An unbound success from a
   small payment can settle a larger order.
5. **Out-of-band confirmation.** A status carried back by the browser redirect must never mark an order paid on
   its own. Settlement comes from a verified webhook or a server-side query to the provider.
6. **Confirm or rule out from source.** Confirm with the callback entry point, the state-change line, and the
   missing check. Rule out only by citing the signature check, the reconciliation, the single-use binding and the
   provider confirmation.

## Where it leaks
- An unverified or wrongly scoped signature accepts a forged success.
- Amount or currency trusted from the message settles a large order for a small payment.
- An event id that is not single-use replays onto another order.
- A redirect `status=success` drives fulfilment.
- A signature verified over a re-serialised body, or over fields other than the ones acted on.

## Rationalizations to reject
- "The provider calls us back." Anyone can post to the callback URL; only the signature authenticates it.
- "The callback URL is secret." A URL is not a credential; it leaks in logs, referrers and history.
- "The callback includes the amount." Then it is attacker-controlled; reconcile against the server's order.
- "The redirect said success." A client-carried status is spoofable.
- "Each payment has a transaction id." Only safe if it is single-use and bound to this order.
- "We verify the signature." Over which bytes, is the result enforced, and is it constant-time?

Adapted from `auditing-payment-callback-and-amount-integrity` and `auditing-webhook-authenticity-and-callback-trust`
in UnboundCompute/security-agent-skills (MIT License, copyright 2026 Riyan Dhiman).
