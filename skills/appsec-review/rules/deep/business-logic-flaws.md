---
parent: business-logic-resources
when: "multi-step flows, money or quantity handling, limits, eligibility, discounts, rewards, tiers, onboarding, approvals, or any flow whose rules come from the business rather than a dangerous call"
---

# Deep: business-logic flaws

`deep` mode only. Extends `business-logic-resources.md`. A06:2025, API6:2023, CWE-840, CWE-841, CWE-1284, CWE-602.

Logic flaws have no tainted source and no dangerous sink. Every request is valid; the sequence breaks a rule the
business assumes. Scanners don't find them, so this pass is where the review earns its keep.

## Method
1. **Write down the rules the flow assumes.** For each flow: "a transfer cannot exceed the balance", "a coupon
   applies once", "step 3 requires step 2", "a card can be revealed only after OTP", "a merchant's limit holds
   across all its terminals". Each rule is a hypothesis to break.
2. **Map the states and real transitions.** Find transitions the rules forbid but the code permits: calling the
   final step directly, repeating an approval, revisiting a completed state, reaching a state without its
   precondition, editing an object after a check locked in a benefit (discount, fee, rate).
3. **Attack the arithmetic and limits.** For every amount, quantity, count, rate or balance the user influences:
   negative, zero, very large, fractional, rounding boundaries, currency or unit changes, and the value that
   pushes a cumulative total past a cap. Check limits are re-checked at commit, not only when first requested.
4. **Attack ordering, replay and concurrency.** Can a permitted request be replayed, sent out of order, or sent
   in parallel to beat a check? (`race-conditions.md` covers the concurrency shapes.)
5. **Authorise outcomes, not only endpoints.** Even when every route checks the role, does the code check this
   user may have this price, tier, limit, beneficiary or account? Reaching a premium or privileged outcome through
   allowed steps is a logic flaw.
6. **Confirm or rule out from source.** Confirm with the rule, the sequence of allowed requests that breaks it,
   and the lines where the rule should be enforced but isn't. Rule out by citing where the server enforces the
   rule at the decisive step.

## Rationalizations to reject
- "Every request is authenticated and valid." That is why it is a logic flaw; the abuse is the sequence.
- "The UI won't let you do that." The UI is not the boundary; the API accepts what the server allows.
- "The check happens on the first request." If state changes after the check and isn't re-validated, the check
  is stale.
- "A scanner found nothing here." Scanners can't model intent.

Adapted from `hunting-business-logic-flaws` in UnboundCompute/security-agent-skills (MIT License, copyright 2026
Riyan Dhiman).
