---
paths:
  - "**/*.{java,kt,scala,groovy,ts,tsx,js,jsx,mjs,cjs,py,go,cs,rb,php,rs}"
  - "**/*.{properties,yml,yaml,json,xml,toml,ini,config,conf}"
  - "**/{nginx,haproxy,envoy,traefik,varnish}*"
  - "**/*.vcl"
  - "**/Caddyfile*"
  - "**/{wrangler.toml,vercel.json,netlify.toml,_headers,_redirects}"
  - "**/*.tf"
---

# Web protocol and identity: request framing, caches, SAML, WebAuthn, MFA, recovery, API keys, mTLS

OWASP A01/A02/A07:2025, API2/API8:2023, ASVS V3/V6/V7/V9/V10/V12, WSTG-INPV-15, WSTG-ATHN/WSTG-SESS, RFC 9110,
RFC 9111, RFC 9112, SAML 2.0 Core and Profiles, W3C WebAuthn Level 3, NIST SP 800-63B-4. CWE-444, CWE-524,
CWE-525, CWE-349, CWE-644, CWE-113, CWE-347, CWE-290, CWE-287, CWE-304, CWE-308, CWE-640, CWE-295, CWE-296,
CWE-384, CWE-613.

`authentication-session.md` covers login, JWT, OAuth/OIDC, OTP step-up, passwords and basic sessions. This file
asks a different question: can the HTTP or identity layer be confused about which request, response, principal,
assurance level or credential an operation belongs to? The stack file names the framework's proxy-trust, SAML and
WebAuthn APIs.

## How to judge findings here
- A framing or cache finding needs **two interpretations** of the same request, response or key. Name both
  components (proxy, CDN, app server, framework) and the exact value each one sees.
- For every credential or challenge, find its verification and every binding its role needs: issuer, audience,
  origin, relying party, client, session, principal, resource, assurance level, expiry and one-time state.
- A missing header, cookie attribute, MFA prompt or rate limit on its own is `warning` or `suggestion`. It becomes
  `critical` or `bug` only with an accepted invalid request, cross-principal impact, an assurance downgrade or a
  credential disclosure.
- Proxy chains, edge cache keys, IdP policy, certificate trust and deployed auth modes often live outside the
  repository. When the decisive fact is missing, mark the finding "needs confirmation" and name the exact fact to
  check. Don't assume the control is either present or absent.

## Request framing and desynchronization (request smuggling)
- Flag custom HTTP parsing, proxies or gateways in the repository that accept both `Content-Length` and
  `Transfer-Encoding`, accept several `Content-Length` values, tolerate obsolete line folding or bare LF, or
  normalise header names differently from the next hop. (CWE-444, RFC 9112 section 6.3)
- Flag lenient-parser switches in production (Node `insecureHTTPParser`, similar framework or proxy options) and
  HTTP/2 to HTTP/1.1 downgrades in a proxy config that forward `Transfer-Encoding`, `Connection` or CR/LF in
  header values.
- Report it only with both components named. A single app server behind an unseen managed proxy is "needs
  confirmation" at most.

## Web cache poisoning and cache deception
- Unkeyed input: flag responses whose body or security headers change with a request value missing from the cache
  key: `X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Rewrite-URL`, selected cookies, language or
  device headers, unkeyed query parameters. (CWE-349, CWE-444)
- Private-response caching: flag responses that depend on the caller's identity without `Cache-Control: private`
  or `no-store`, especially when the CDN or reverse proxy config in the repository caches by path or extension.
  (CWE-524, CWE-525)
- Cache deception: flag routing that serves a private dynamic page for `/account/profile.css`, `/api/me;x.js`,
  `/api/me/%2e%2e/static.js` or similar, while the edge config caches by suffix or static prefix. Compare the
  edge's path normalisation with the application router's.
- `Vary` must list every request header the response depends on. Flag `Vary: *` workarounds in front of
  authenticated content.

## Host and forwarded-header trust
- Flag `Host`, `X-Forwarded-Host`, `Forwarded` or `X-Forwarded-Proto` used to build password-reset links, email
  links, OAuth callbacks, absolute redirects, tenant routing or cache keys without an allow-list of hosts.
  (CWE-644, CWE-640)
- The framework must trust forwarded headers only from known proxies: a configured proxy list or hop count, not
  "trust all". Flag client-supplied forwarded headers that reach authorization, tenant or IP-based decisions.
- Flag internal headers that grant identity or privilege (`X-User-Id`, `X-Internal`, `X-Roles`,
  `X-Authenticated-User`, client-certificate headers) unless the edge config in the repository strips the client's
  copy before it sets its own.

## Response-header injection
- Flag untrusted data reaching `Location`, `Set-Cookie`, `Content-Disposition`, `Link` or a CSP header without
  CR/LF rejection or encoding. Check whether the framework already rejects CR/LF before reporting, and require a
  security-relevant change to the response. (CWE-113)

## Sessions and cookies across identity changes
- Session identifiers must rotate on login, account switch, MFA completion, impersonation start and stop, and any
  privilege change. Flag sessions that stay valid after logout, password change, MFA reset, revocation or account
  disable, including copies in refresh tokens, signed cookies, websocket connections and caches. (CWE-384,
  CWE-613)
- Flag sensitive cookies with a `Domain` broader than needed (sibling subdomains that host user content or
  third-party apps can set or read them), or two cookies with the same name that different components pick
  differently (cookie tossing). Prefer the `__Host-` prefix for session cookies.

## SAML
- The element whose signature is verified must be the element the code uses for identity. Flag code that verifies
  a signature, then reads the assertion again with an XPath or "first element" lookup (XML signature wrapping).
  (CWE-347)
- Flag accepting unsigned responses or assertions, fallbacks when the signature is missing, and any setting that
  disables signature checks (`wantAssertionsSigned: false`, `strict: false`, `skipSignatureValidation`).
- Check `Audience`, `Recipient`/`Destination`, `NotBefore`/`NotOnOrAfter` with a small clock skew,
  `InResponseTo` bound to a request the service started (or IdP-initiated SSO deliberately limited), and a replay
  cache of assertion ids. (CWE-294)
- The XML parser must forbid DTDs and external entities, and canonicalisation must come from a maintained library.
  Flag XML-signature libraries with known wrapping or canonicalisation CVEs.
- In multi-IdP setups, the IdP that signed the assertion must be the IdP configured for that tenant or account.
  Flag lookups that pick the certificate from the assertion's `Issuer` alone.

## WebAuthn and passkeys
- Registration: verify the challenge (server-generated, single-use, bound to the initiating session), the expected
  origin, the RP ID, user verification when the policy requires it, and that the credential is attached to the
  authenticated user who started the ceremony. Flag credentials registered for a `userHandle` taken from the
  request. (CWE-287)
- Authentication: verify the challenge, origin, RP ID, signature with the stored public key, that the credential
  belongs to the account being logged into, and the user-presence and user-verification flags.
- Flag challenges stored in the client, reused, or not expired; origin checks with `startsWith` or a wildcard;
  and discoverable-credential flows that map a `userHandle` to an account without checking that the credential
  belongs to it.
- The signature counter matters only if the product treats a counter regression as a cloned authenticator. Don't
  report a missing counter check on its own.

## MFA enrollment, step-up binding and assurance downgrade
- Enrolling, replacing or disabling a second factor, generating recovery codes and marking a device as trusted
  must require fresh authentication at the assurance level the policy names. Flag a first factor alone being enough
  to swap the second. (CWE-308)
- A completed challenge must upgrade only the session, account, tenant and operation it was issued for. Flag an
  assurance flag stored per user instead of per session, or a step-up result reusable for a different operation.
- Flag alternative routes to the same sensitive action (API vs UI, batch, legacy, mobile, recovery or resumed
  flows) that skip the assurance check the main route enforces. The effective policy is the weakest route.

## Account recovery and linking
- Recovery and reset tokens must be random, bound to the user and action, short-lived and single-use, and must
  invalidate earlier tokens and existing sessions when used. Reset links must be built from a configured base URL,
  not the request host. (CWE-640)
- Support, admin and helpdesk recovery, backup codes, device migration and email or phone change are often the
  weakest login path. Each needs the same assurance as the login it can replace.
- Linking a new IdP, passkey, email, phone or device to an existing account needs a current authenticated
  session, proof of ownership of the new identifier, policy-required step-up, and callback state bound to the
  account that started the linking. Flag auto-linking by an unverified email claim from an external IdP.
  (CWE-287, CWE-290)
- Draw the account graph before and after each recovery or linking step. Each edge must name the current
  principal, the proof of the new identity, the required assurance and what gets revoked.

## API keys
- A key must authenticate only to the tenant, resources, actions and environment its server-side record grants.
  Flag request parameters that widen that scope, publishable keys accepted where secret keys are needed, prefix
  matching without verifying the full secret, and keys that stay usable after revocation because of a cache.
- Keys must be stored hashed and compared in constant time. Flag keys in URLs, redirects, logs, client bundles or
  error responses. A public identifier called a "key" is not a secret; confirm what the key unlocks before
  reporting.

## mTLS and certificate identity
- Flag services that trust client-certificate identity headers (`X-SSL-Client-*`, `X-Forwarded-Client-Cert`,
  `ssl-client-subject-dn`) from any network peer. Only the terminating proxy may set them, and it must strip the
  client's copy. (CWE-290)
- Flag mapping of subject or SAN text to accounts with substring or case-insensitive matching, certificates
  accepted from the wrong trust domain or without the required extended key usage, and hostname checks disabled.
  (CWE-295, CWE-296)
- Flag fail-open behaviour when a certificate is expired, revoked or missing: silent fallback to bearer-only or
  anonymous access, or long-lived pooled connections that keep working after revocation.
