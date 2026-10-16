---
paths:
  - "**/*.{java,kt,scala,groovy,ts,tsx,js,jsx,mjs,cjs,vue,svelte,py,go,cs,rb,php,rs,dart,swift}"
  - "**/*.{properties,yml,yaml,json,xml,toml,ini,config}"
---

# Access control and authorization

OWASP A01:2025, API1/API3/API5/API7:2023, ASVS V8, WSTG-ATHZ. CWE-862, CWE-863, CWE-639, CWE-284, CWE-915, CWE-918,
CWE-668.

The checks below are framework-neutral. The stack file for the repository (`rules/stacks/`) names the framework's
authorization, binding and context constructs.

## Object level (BOLA / IDOR)
- Before any read, change or downstream call, check every object id taken from the path, query, header or body
  (card, account, customer, user, order, request, ticket, beneficiary, file) against the authenticated principal.
  Flag new ids that reach a repository, ORM, query or downstream API without that check. (API1, CWE-639)
- Flag lookups keyed on caller-controlled identity values: customer number, account or card number, username,
  national id, phone or email taken from a body field, path or query parameter instead of the security context or
  verified token claims. (CWE-639)
- Flag operations on records by reference number alone (view, comment, cancel, approve, download) without checking
  that the record belongs to the caller.
- Flag ownership checks that are missing, commented out, placed after the side effect, done only in the client,
  skipped on some branches or error paths, or replaced by an unrelated control. For example, an OTP sent to the
  caller's own phone does not prove they own the object.
- Debit, source or funding accounts, wallets and phone numbers from the request must be checked against the caller's
  linked accounts before they reach a payment or core-banking API.
- Lists and searches must be filtered to the caller's own objects on the server side.
- Flag a check on one id and an action on another: ownership verified for the path id while the write uses a
  body id, a nested or child id never tied to the checked parent (`/projects/:p/tasks/:t` checks the project but
  loads the task by its id alone), or a batch where only the first id is checked.
- Flag check-then-change: a value is authorised or validated, then trimmed, lowercased, decoded, normalised,
  re-parsed or rebuilt before use, or the record is re-fetched without the scope after the check. The value that
  is used must be the value that was checked.
- Flag ownership comparisons that can't work: different types compared (`ObjectId` vs string, number vs string),
  `==` on objects, or a comparison that is always true or always false, so the check never denies or never allows.

## Function level (BFLA)
- Every route or handler needs an explicit authorization rule with the narrowest role: an annotation, decorator,
  guard, middleware, policy or a matching rule in central security config. Flag any new or changed handler without
  one, including in new controllers, routers or modules where no handler has a rule. Be strictest with approve,
  reject, delete, activate and update operations. A sibling that has a rule is supporting evidence, not a
  condition for reporting. (API5, CWE-862)
- Flag wildcard or broad roles, admin or back-office operations reachable with a customer role, and authorization
  enforced only at the gateway or in the UI. Add a service-layer check for destructive operations.
- Flag paths missed by security filters, middleware or interceptors, and exclusion patterns that match more than
  intended. Check the order in which middleware is registered: a route mounted before the auth middleware is
  public.
- Internal-only endpoints must require service authentication and must not also be exposed on a public path.

## Property level (mass assignment and over-exposure)
- Request models must not bind fields the client must not set: status, role, owner id, limits, balance, flags,
  price, approval state. Flag ORM entities or models bound directly from the request body, spreading or merging the
  whole body into a model (`{...req.body}`, `Object.assign`, `**data`), and generic copy or mapping helpers from
  client input into entities. Use an explicit allow-listed DTO or schema. (API3, CWE-915)
- Response models must expose only the fields the client needs. Flag entities, ORM rows or raw downstream responses
  returned directly, and fields with secrets, card data, internal ids, other users' data or internal hosts.
  (CWE-213)

## Multi-tenancy
- The tenant must come from a trusted source (verified token, a server-side mapping of a path segment), never from
  the request body. Flag cross-tenant queries, repositories or connections bound to the wrong datasource, and
  caches keyed without the tenant. (CWE-668)
- Request-scoped tenant, security or logging context (thread-locals, async-local storage, context variables) must
  be cleared when the request ends. Flag async work, background jobs or executors that lose the context or leak it
  between requests.

## SSRF and URLs
- Outbound URLs must be built from configuration, never from client input. Client values must be expanded as
  encoded URI template variables or path segments, never concatenated into the URL or host. (API7, CWE-918)
- URLs returned to clients (redirects, iframes, session or download links) must be checked against a host
  allow-list over https. (CWE-601)

The check-one-id-act-on-another, check-then-change and type-mismatch items are adapted from the
broken-object-level-authorization examples in mohamed-osama-aboelkheir/appsec-untangled-resources (MIT License,
copyright 2026 Mohamed AboElKheir).
