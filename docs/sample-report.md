---
service: "acme-shop"
repository: "acme-shop"
branch: "main"
commit: "0000000"
mode: "deep"
version: "1.0"
date: "2026-10-19"
status: "Initial Review"
---

# acme-shop Source Code Review Report

Confidential · Acme Corp (fictional) · E-commerce

Sample report for a fictional online shop. Every name, path, line of code and finding in it is invented to show the report format.

| Item | Detail |
|---|---|
| Version | 1.0 |
| Date of issue | 19 October 2026 |
| Branch | `main` |
| Review mode | deep |
| Findings | 8 in 10 locations (1 critical, 2 high) |
| Status | Initial Review |

## 1.0 Executive Summary

### 1.1 Key Takeaways

This deep review covered the Acme Shop API and its React storefront on branch `main`, ahead of the 2.5 release that opens the shop to guest checkout.

Two problems need fixing before release. The API decodes admin tokens without checking their signature, so anyone can forge an admin session (4.1.1). The payment webhook trusts any caller, so an attacker can mark an unpaid order as paid (4.1.2).

Database access is parameterised throughout, passwords are hashed with Argon2id, session cookies are `HttpOnly` and `SameSite=Lax`, and file uploads are type-checked and stored outside the web root.

### 1.2 Risk Profile

| Layer | Critical | High | Medium | Low | Informational | Root causes | Locations |
|---|---|---|---|---|---|---|---|
| Backend | 1 | 2 | 1 | 1 | 0 | 5 | 6 |
| Web frontend | 0 | 0 | 1 | 1 | 1 | 3 | 4 |
| **Total** | 1 | 2 | 2 | 2 | 1 | 8 | 10 |

### 1.3 Findings at a Glance

Findings are grouped by layer, in section order.

| # | Vulnerability | Risk | CVSS 4.0 | Affected file | Status |
|---|---|---|---|---|---|
| **4.1 Backend** |  |  |  |  |  |
| 4.1.1 | Admin Token Signature Not Verified | Critical | 9.3 | `api/src/middleware/auth.js:12-19` | Initial Review |
| 4.1.2 | Payment Webhook Accepts Unsigned Callbacks | High | 8.7 | `api/src/routes/webhooks.js:18-31` | Initial Review |
| 4.1.3 | Order Details Readable by Any Customer | High | 7.1 | `api/src/routes/orders.js:42-51` | Initial Review |
| 4.1.4 | Stack Traces Returned in Error Responses | Medium | 6.9 | `api/src/app.js:88-92` | Initial Review |
| 4.1.5 | Single-Use Coupon Redeemable Twice in a Race | Low | 2.3 | `api/src/services/coupons.js:21-33` | Initial Review |
| **4.2 Web frontend** |  |  |  |  |  |
| 4.2.1 | Stored XSS in Product Reviews | Medium | 6.2 | `web/src/components/ReviewList.jsx:27-33` | Initial Review |
| 4.2.2 | Refresh Token Kept in localStorage | Low | 2.3 | `web/src/api/client.js:9-14` | Initial Review |
| 4.2.3 | No Content Security Policy | Informational | 0.0 | `web/index.html:1-12` | Initial Review |

## 2.0 Scope and Threat Model

### 2.1 Scope of Work

| Item | Detail |
|---|---|
| Repository | `acme-shop`, branch `main`, version 2.4.0 |
| Stack | Node.js 22 with Express 5 and PostgreSQL · React 19 single-page app |
| Layer | Backend: Node.js 22, Express 5, PostgreSQL 16 via `pg` in `api/`; 41 routes, 1 webhook |
| Layer | Web frontend: React 19, Vite 6, React Router 7 in `web/`; 23 screens |
| Code | 214 source files, about 18,600 lines (`api/` and `web/`), tests and generated code excluded |
| Entry points | 41 HTTP routes in `api/src/routes/`, 1 payment webhook, 23 React screens |
| Integrations | Payment provider (webhook callbacks), transactional email service, object storage for product images |

### 2.2 Threat Model

Assets: customer accounts and personal data, orders and their payment state, coupons, and the admin console. Actors: anonymous visitors, signed-in customers, admins, and the payment provider calling the webhook.

| Abuse path | Result | Evidence |
|---|---|---|
| Anonymous visitor gains admin access | Realised | 4.1.1 |
| Order marked paid without payment | Realised | 4.1.2 |
| Customer reads another customer's data | Realised | 4.1.3 |
| Script runs in another shopper's session | Realised | 4.2.1 |
| Coupon reused across orders | Blocked on an outside fact | Database isolation level (4.1.5) |
| SQL injection through product search | Blocked | Parameterised query in `api/src/db/products.js:22` |

### 2.3 Limitations

- Infrastructure, the CDN and the static host configuration were not in scope. Response headers were judged from the repository only.
- The production database isolation level could not be checked (see 5.2).
- No dynamic testing was done. Every attack was traced in the code and checked by a second agent.
- Ledger: 64 units, 61 `covered`, 3 `out_of_scope` (generated API client, Storybook stories, seed scripts).

## 3.0 Security Controls Checklist

### 3.1 Checklist Results

| Category | Vulnerable | Secure | Checks |
|---|---|---|---|
| Access control and IDOR | 1 | 8 | 9 |
| Authentication and tokens | 1 | 7 | 8 |
| Injection and input validation | 0 | 10 | 10 |
| Cryptography and secrets | 0 | 6 | 6 |
| Transport security | 0 | 3 | 3 |
| Security misconfiguration and supply chain | 0 | 7 | 7 |
| Logging and error handling | 1 | 4 | 5 |
| Business logic and abuse | 2 | 5 | 7 |
| Web frontend and mobile security | 3 | 5 | 8 |

Not applicable: OTP step-up and one-time proofs (no flow uses one), Card data protection (card entry is hosted by the payment provider) (see 2.3).

### 3.2 Controls Verified as Secure

- Backend: every SQL query uses `pg` parameters, including dynamic sorting through an allow-list (`api/src/db/products.js:22`).
- Backend: passwords are hashed with Argon2id and compared in constant time (`api/src/services/users.js:40`).
- Backend: `requireUser` verifies token signature, expiry and algorithm (`api/src/middleware/auth.js:4-10`).
- Backend: uploads are checked by content type and size and stored outside the web root (`api/src/routes/uploads.js:15`).
- Web frontend: no API keys or secrets in the built bundle; `VITE_` variables hold public values only.
- Web frontend: every other component renders user content through React escaping.

## 4.0 Vulnerability Findings

### 4.1 acme-shop · Backend

Covers `api/`.

#### 4.1.1 Admin Token Signature Not Verified

`api/src/middleware/auth.js#requireAdmin`

- **Severity:** Critical, CVSS 4.0 9.3 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N`)
- **Checklist:** Authentication and tokens
- **Verification:** Independent verifier
- **Status:** Initial Review

**Affected assets**

- `api/src/middleware/auth.js:12-19`

**References:** A07:2025, API2:2023, CWE-347, CWE-287, ASVS V9.1

**Description:** `requireAdmin` reads the bearer token with `jwt.decode`, which parses the token without checking its signature, and then trusts the `role` claim. Every route under `/api/admin` relies on this middleware.

**Attack scenario**

1. The attacker, with no account, builds a token with the payload `{"sub":"1","role":"admin"}` and any signature.
2. They send `GET /api/admin/customers` with that token in the `Authorization` header.
3. The middleware accepts the token and the API returns every customer record.

**Impact:** Full admin access without credentials: read and change every customer, order and product, and issue refunds.

**Recommendation:** Replace `jwt.decode` with `jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'] })`, as `requireUser` already does in the same file. Add a test that a token signed with another key gets 401.

**Proof of concept**

`acme-shop/api/src/middleware/auth.js`

```js
function requireAdmin(req, res, next) {
  const token = (req.headers.authorization || '').replace('Bearer ', '');
  const claims = jwt.decode(token);
  if (!claims || claims.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  req.user = claims;
  next();
}
```

Vulnerable lines: 3, 4

#### 4.1.2 Payment Webhook Accepts Unsigned Callbacks

`api/src/routes/webhooks.js#POST /api/webhooks/payment`

- **Severity:** High, CVSS 4.0 8.7 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N`)
- **Checklist:** Business logic and abuse
- **Verification:** Independent verifier
- **Status:** Initial Review

**Affected assets**

- `api/src/routes/webhooks.js:18-31`

**References:** A08:2025, API6:2023, CWE-345, ASVS V2.3

**Description:** The payment webhook marks an order as paid from the `orderId` and `status` in the request body. It never checks the provider's `Payment-Signature` header, and the route is public so the provider can reach it.

**Attack scenario**

1. The attacker places an order and stops at the payment page.
2. They send `POST /api/webhooks/payment` with `{"orderId":"<their order>","status":"succeeded"}`.
3. The order moves to `paid` and is released for shipping.

**Impact:** Goods shipped without payment, for any order the attacker can create.

**Recommendation:** Verify the `Payment-Signature` header with the provider SDK's `constructEvent` and the webhook secret before reading the body, and re-fetch the payment from the provider by id before changing the order. Add a test that an unsigned callback gets 400 and leaves the order unchanged.

**Proof of concept**

`acme-shop/api/src/routes/webhooks.js`

```js
router.post('/payment', express.json(), async (req, res) => {
  const { orderId, status } = req.body;
  if (status === 'succeeded') {
    await orders.markPaid(orderId);
  }
  res.sendStatus(200);
});
```

Vulnerable lines: 2, 4

#### 4.1.3 Order Details Readable by Any Customer

`api/src/routes/orders.js#GET /api/orders/:id`

- **Severity:** High, CVSS 4.0 7.1 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N`)
- **Checklist:** Access control and IDOR
- **Verification:** Independent verifier
- **Status:** Initial Review

**Affected assets**

- `api/src/routes/orders.js:42-51`
- `api/src/db/orders.js:30-34`

**References:** A01:2025, API1:2023, CWE-639, ASVS V8.2

**Description:** `GET /api/orders/:id` loads the order by id only. The query has no `customer_id` filter and the handler does not compare the owner with `req.user.id`. Order ids are sequential.

**Attack scenario**

1. The attacker signs up as an ordinary customer.
2. They request `GET /api/orders/1`, `/2`, `/3` and so on.
3. Each response returns another customer's name, delivery address, phone number and items.

**Impact:** Any customer can read every other customer's order history and personal data.

**Recommendation:** Load the order with `orders.findForCustomer(id, req.user.id)` (the helper the order list already uses) and return 404 when it finds nothing. Add a test that customer B gets 404 for customer A's order.

**Proof of concept**

`acme-shop/api/src/routes/orders.js`

```js
router.get('/:id', requireUser, async (req, res) => {
  const order = await orders.findById(req.params.id);
  if (!order) {
    return res.sendStatus(404);
  }
  res.json(order);
});
```

Vulnerable lines: 2

#### 4.1.4 Stack Traces Returned in Error Responses

`api/src/app.js#errorHandler`

- **Severity:** Medium, CVSS 4.0 6.9 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`)
- **Checklist:** Logging and error handling
- **Verification:** Self-verified
- **Status:** Initial Review

**Affected assets**

- `api/src/app.js:88-92`

**References:** A10:2025, CWE-209, ASVS V16.5

**Description:** The global error handler sends `err.stack` to the client in every environment. A malformed request body is enough to trigger it.

**Attack scenario**

1. The attacker sends `POST /api/cart` with an invalid JSON body.
2. The response contains the full stack trace, with file paths and library versions.

**Impact:** Reveals internal paths, library versions and query fragments that help plan further attacks.

**Recommendation:** Return `{ error: 'internal_error', requestId }` to the client and log the stack server side with the same request id.

**Proof of concept**

`acme-shop/api/src/app.js`

```js
app.use((err, req, res, next) => {
  logger.error(err);
  res.status(err.status || 500).json({ error: err.message, stack: err.stack });
});
```

Vulnerable lines: 3

#### 4.1.5 Single-Use Coupon Redeemable Twice in a Race

`api/src/services/coupons.js#redeem`

- **Severity:** Low, CVSS 4.0 2.3 (`CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N`)
- **Checklist:** Business logic and abuse
- **Verification:** Independent verifier
- **Status:** Initial Review

**Affected assets**

- `api/src/services/coupons.js:21-33`

**References:** A06:2025, API6:2023, CWE-362, ASVS V2.3

**Description:** Needs confirmation. `redeem` reads `used_at`, checks it is empty and then updates it in a separate statement. Two requests sent together can both pass the check. Whether this works depends on the database isolation level, which is not in the repository.

**Attack scenario**

1. The attacker holds one single-use coupon and two carts.
2. They send both checkout requests with the coupon at the same moment.
3. Both orders get the discount.

**Impact:** A single-use discount applied more than once. The loss per coupon is small, but the same pattern is easy to script.

**Recommendation:** Redeem with one conditional update, `UPDATE coupons SET used_at = now() WHERE code = $1 AND used_at IS NULL RETURNING id`, and reject the checkout when no row comes back. Add a test that fires two redemptions in parallel.

**Proof of concept**

`acme-shop/api/src/services/coupons.js`

```js
async function redeem(code, orderId) {
  const coupon = await db.one('SELECT * FROM coupons WHERE code = $1', [code]);
  if (coupon.used_at) {
    throw new CouponUsedError();
  }
  await db.none('UPDATE coupons SET used_at = now(), order_id = $2 WHERE id = $1', [coupon.id, orderId]);
}
```

Vulnerable lines: 3, 6

### 4.2 acme-shop · Web frontend

Covers `web/`.

#### 4.2.1 Stored XSS in Product Reviews

`web/src/components/ReviewList.jsx#ReviewBody`

- **Severity:** Medium, CVSS 4.0 6.2 (`CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:P/VC:N/VI:N/VA:N/SC:H/SI:L/SA:N`)
- **Checklist:** Web frontend and mobile security
- **Verification:** Independent verifier
- **Status:** Initial Review

**Affected assets**

- `web/src/components/ReviewList.jsx:27-33`

**References:** A05:2025, CWE-79, ASVS V3.2, WSTG-CLNT-03

**Description:** Review text is rendered with `dangerouslySetInnerHTML` so that line breaks show. The API stores review text as submitted, so any customer can store markup that runs in other shoppers' browsers.

**Attack scenario**

1. The attacker, signed in as a customer, posts a review containing `<img src=x onerror=...>`.
2. Another shopper opens the product page.
3. The script runs in the shopper's session and can act as them on the storefront.

**Impact:** Actions in a victim's session, such as changing the delivery address of an open order. The session cookie itself is `HttpOnly`.

**Recommendation:** Render the text as a React child and use CSS `white-space: pre-line` for line breaks. Add a test that a review containing `<img>` renders as text.

**Proof of concept**

`acme-shop/web/src/components/ReviewList.jsx`

```jsx
function ReviewBody({ review }) {
  return (
    <div
      className="review-body"
      dangerouslySetInnerHTML={{ __html: review.text.replace(/\n/g, '<br>') }}
    />
  );
}
```

Vulnerable lines: 5

#### 4.2.2 Refresh Token Kept in localStorage

`web/src/api/client.js#saveToken`

- **Severity:** Low, CVSS 4.0 2.3 (`CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N`)
- **Checklist:** Web frontend and mobile security
- **Verification:** Rejection reviewed
- **Status:** Initial Review

**Affected assets**

- `web/src/api/client.js:9-14`

**References:** A07:2025, CWE-922, ASVS V3.3, RFC 10017

**Description:** The storefront stores the long-lived refresh token in `localStorage`, where any script on the page can read it. Combined with 4.2.1, an attacker could take the token and keep access after the victim leaves the page.

**Attack scenario**

1. The attacker gets script running on the storefront (for example through 4.2.1).
2. The script reads `localStorage.refreshToken` and sends it to the attacker.
3. The attacker uses the token to get new access tokens for the victim's account.

**Impact:** Long-lived access to one customer's account. It needs a separate script-injection flaw first.

**Recommendation:** Have the API set the refresh token as an `HttpOnly`, `Secure`, `SameSite=Strict` cookie scoped to `/api/auth/refresh`, and keep only the short-lived access token in memory.

**Proof of concept**

`acme-shop/web/src/api/client.js`

```js
export function saveTokens({ accessToken, refreshToken }) {
  memory.accessToken = accessToken;
  localStorage.setItem('refreshToken', refreshToken);
}
```

Vulnerable lines: 3

#### 4.2.3 No Content Security Policy

`web/index.html#csp`

- **Severity:** Informational, CVSS 4.0 0.0
- **Checklist:** Web frontend and mobile security
- **Verification:** Self-verified
- **Status:** Initial Review

**Affected assets**

- `web/index.html:1-12`
- `web/vite.config.js:8-20`

**References:** A02:2025, CWE-1021, ASVS V3.4

**Description:** Neither the HTML nor the static host sends a `Content-Security-Policy`. A policy would not fix 4.2.1, but it would stop an injected script from loading code or sending data to another host.

**Attack scenario**

1. No direct attack. This is hardening that limits what an injected script can do.

**Impact:** No direct impact today. Without a policy, any script injection has full reach.

**Recommendation:** Send `Content-Security-Policy: default-src 'self'; img-src 'self' https://images.acme.example; object-src 'none'; base-uri 'none'` from the static host, first in report-only mode.

**Proof of concept**

`acme-shop/web/index.html`

```html
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Acme Shop</title>
</head>
```

Vulnerable lines: 1

## 5.0 Remediation Plan

### 5.1 Prioritised Actions

1. Verify the signature and algorithm of every token in `requireAdmin` (Backend). Closes 4.1.1 · Effort S
2. Check the provider signature on the payment webhook and re-fetch the payment before changing an order (Backend). Closes 4.1.2 · Effort M
3. Scope every order and address lookup to the signed-in customer (Backend). Closes 4.1.3 · Effort S
4. Render review text as plain text and add a lint rule against `dangerouslySetInnerHTML` (Web frontend). Closes 4.2.1 · Effort S
5. Move the refresh token to an `HttpOnly` cookie (Backend and Web frontend). Closes 4.2.2 · Effort M
6. Return generic error bodies with a request id (Backend). Closes 4.1.4 · Effort S
7. Make coupon redemption a single conditional update (Backend). Closes 4.1.5 · Effort S
8. Add a Content Security Policy, first in report-only mode (Web frontend). Closes 4.2.3 · Effort M

### 5.2 Facts to Confirm

| Finding | Fact to confirm | How to check | Rating if unsafe |
|---|---|---|---|
| 4.1.5 | The transaction isolation level used for `coupons.redeem` in production. | Run `SHOW default_transaction_isolation;` on a production read replica. | Low |

## 6.0 Appendix

### 6.1 Assessment Methodology

This review was performed with the **appsec-review** skill, commit `sample`.

- **Code enumeration.** `inventory.py` listed 41 routes, 1 webhook, 23 screens and 57 sinks across `api/` and `web/`; the coverage ledger tracked each one to a result.
- **Dependency and secret checks.** `npm audit` and gitleaks were run; neither reported an issue in scope. osv-scanner and semgrep were not installed.
- **Manual source analysis.** Followed each entry point (routes and handlers, screens and client flows) through its middleware, filters and guards to its sinks, with a STRIDE pass on every trust boundary, against the checklist in section 3.0 and the stack checks for Node.js 22 with Express 5 and PostgreSQL · React 19 single-page app.
- **Verification.** Every candidate was checked by a fresh verifier agent that did not see the finder's reasoning; one rejection was reviewed and overruled (4.2.2).
- **Run.** deep mode, 38m 12s, 1,284,500 tokens (main session and subagents).

### 6.2 Security Standards

| Standard | Version | Used for |
|---|---|---|
| OWASP Top 10 | 2025 | Web application risk categories |
| OWASP API Security Top 10 | 2023 | API risks (object level authorization, business flows) |
| OWASP ASVS | 5.0 | Verification requirements, including V3 Web Frontend Security |
| MITRE/CISA CWE Top 25 | 2025 | Weakness ids for every finding |
| OWASP WSTG | current | Penetration-testing categories, including WSTG-CLNT for the browser |
| IETF RFC 10017 | 2026 | OAuth 2.0 for browser-based applications |
| FIRST CVSS | 4.0 | Base score (CVSS-B) and rating |

### 6.3 Risk Rating Criteria

Each finding is rated by its CVSS 4.0 base score (CVSS-B: base metrics only, no threat or environmental metrics). Where log or repository access is a precondition, the score assumes low-privileged readers (PR:L).

| Risk | CVSS 4.0 |
|---|---|
| Critical | 9.0 – 10.0 |
| High | 7.0 – 8.9 |
| Medium | 4.0 – 6.9 |
| Low | 0.1 – 3.9 |
| Informational | 0.0 |

### 6.4 Candidates Rejected by Verification

| Candidate | Location | Reason | Disproof |
|---|---|---|---|
| SQL injection in product search | `api/src/routes/products.js:15` | The search term is passed as a query parameter, never concatenated. | `api/src/db/products.js:22` |
| Open redirect after login | `web/src/screens/Login.jsx:48` | The `next` value is checked against an allow-list of in-app paths. | `web/src/lib/redirect.js:6` |

### 6.5 Disclaimer

This report is confidential and intended only for Acme Corp (fictional). Its findings reflect the code on the reviewed branch on the date of issue; later changes to code, configuration or architecture may change the results. Findings marked "needs confirmation" depend on behaviour outside the review scope.

---

Confidential. Secret values, card data, OTPs and tokens are referenced by location only and never reproduced in this report.

Generated with appsec-review (https://github.com/ibrahimabdallatif/appsec-review) · Skill author: Ibrahim Abdallatif · LinkedIn (https://www.linkedin.com/in/ibrahimabdallatif/)
