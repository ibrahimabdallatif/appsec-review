---
paths:
  - "**/*.{java,kt,scala,groovy,ts,tsx,js,jsx,mjs,cjs,vue,svelte,py,go,cs,rb,php,rs,dart,swift}"
  - "**/*.{properties,yml,yaml,json,xml,toml,ini,config}"
---

# Security logging, alerting and exceptional conditions

OWASP A09/A10:2025, ASVS V16, WSTG-ERRH, PCI DSS v4.0 req. 10. CWE-778, CWE-223, CWE-532, CWE-209, CWE-755,
CWE-636, CWE-390, CWE-396, CWE-460.

## Security events must be logged
- Log authentication failures, authorization denials, OTP and step-up failures and lockouts, ownership-check
  failures, access to sensitive data (card data reveal, PII export), and changes to credentials, limits, payees and
  account state. Each entry needs a trace id, the tenant, a non-sensitive user reference, the action and the
  outcome. (CWE-778, CWE-223)
- Flag new sensitive operations or denial paths with no log or audit entry. Denials should log at WARN so alerting
  can see them.
- Repeated failures (brute force, enumeration, IDOR probing) must be detectable from the logs.

## Logs must not leak
- Never log card numbers (unmasked), CVV, PIN, OTP, passwords, security answers, tokens, authorization headers,
  session or one-time URLs, API keys, or full request or response bodies of auth, OTP, payment or card APIs.
  (CWE-532)
- Flag logging a whole provider or downstream response (e.g. an OTP provider response with the OTP in it), and
  string representations of objects that hold `otp`, `password`, `token`, `cvv`, `pin` or `pan`. Log ids and
  status only.
- Flag request or response logging middleware, interceptors and aspects that log bodies or headers for every
  endpoint.
- When the repository has a log sanitizer or redacting converter, new sensitive keys need a redaction rule there.
- Flag exceptions logged with messages that embed sensitive values (e.g. an HTTP client error that carries the
  downstream response body).
- Front ends and apps: see `client-side.md` for console output and error-tracking tools.

## Error responses
- Clients get only a stable error code, a generic message and a trace id. Flag exception messages, stack traces,
  SQL errors, identity-provider or JWT error text, downstream payloads, internal hosts or class names in response
  bodies. This includes errors raised in security filters, middleware, guards and token providers, which must map
  to fixed codes. (CWE-209)
- Error codes and messages must not help enumeration or reveal which check failed when that leaks information.

## Mishandling of exceptional conditions
- Fail closed. On missing config, unknown status, null claims, parsing errors, timeouts or downstream errors, deny
  the operation. Flag code that defaults to allow, treats null or undefined as valid, or continues after a failed
  security check. (A10, CWE-636)
- Flag caught exceptions that are ignored or only logged where the operation must stop, catch-all handlers that
  hide security failures, empty catch blocks, unhandled promise rejections, and ignored error return values.
  (CWE-390, CWE-396)
- Exceptions from auth or token services must keep their meaning (401/403). Flag them turned into a 200, a generic
  success or an unrelated error, or swallowed so a later step runs without credentials. (CWE-755)
- Release resources and security state (request context, locks, streams, connections) in `finally`, `defer`,
  `using` or the language's equivalent. (CWE-460)
- Partial failures in multi-step money or state changes must not leave inconsistent state. Flag missing rollback
  or compensation.
