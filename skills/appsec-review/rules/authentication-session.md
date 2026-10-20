---
paths:
  - "**/*.{java,kt,scala,groovy,ts,tsx,js,jsx,mjs,cjs,vue,svelte,py,go,cs,rb,php,rs,dart,swift}"
  - "**/*.{properties,yml,yaml,json,xml,toml,ini,config}"
---

# Authentication, tokens, step-up and sessions

OWASP A07:2025, API2:2023, ASVS V6/V7/V9/V10, WSTG-ATHN/WSTG-SESS, RFC 9700, RFC 8252, RFC 10017.
CWE-287, CWE-306, CWE-307, CWE-347, CWE-294,
CWE-384, CWE-613, CWE-670.

## Authentication
- Every non-public endpoint must require valid authentication. Flag routes marked public, security exclusions, or
  a filter, middleware or guard that skips new paths. (CWE-306)
- Flag authentication decided by matching raw path strings (`contains`, `startsWith`, regex on the request URI) or
  by broad wildcard patterns on unsecured lists. Matching must use the normalised, decoded path the router uses;
  encoded `%2F`, `//`, `/./`, `;` and case variants can bypass it. (CWE-287)
- Public credential endpoints (login, forgot password, forgot username, OTP, registration) need server-side
  brute-force protection: attempt limits, lockout or throttling per user, device and IP, and CAPTCHA where the
  design calls for it. Flag CAPTCHA or throttling that is commented out or disabled. (API2, CWE-307)

## Logic flaws in authentication checks
- Flag a failed check that doesn't stop the flow, e.g. `if (!valid) { increaseTrials(); }` with no `return` or
  `throw`, so execution continues to send an OTP, issue a token or change state. (CWE-670)
- Flag expiry or age computed with `%`, integer-division wrap-around, absolute values of time differences, or mixed
  units (seconds against milliseconds). Compare timestamps or epoch values directly. (CWE-613)
- Flag security controls that are commented out, wrapped in `if (false)`, or left behind a debug or test flag.
  Treat them as removed.

## Token validation (JWT / OAuth2 / OIDC)
- Tokens must be verified for signature, expiry, not-before, issuer and audience. Flag decoding without verifying
  (a `decode` call where `verify` is needed, or reading the Base64 payload directly), `alg: none`, HMAC with an RSA
  public key, algorithm lists taken from the token, or skipping `exp`. The stack file names each library's unsafe
  calls. (ASVS V9, CWE-347)
- Claims used for authorization (subject, customer id, roles, tenant) must come from the verified result. Flag
  claims parsed separately from an unverified payload after introspection, tokens accepted when introspection
  fails, and fallbacks to headers, query or body when a claim is missing.
- Signing keys must come from trusted config or JWKS, never from token headers (`jku`, `x5u`, or `kid` used as a
  path or URL).
- OAuth/OIDC (RFC 9700, ASVS V10). Browser clients also follow RFC 10017, and native clients also follow
  RFC 8252; those client checks are in `client-side.md`.
  - Authorization code flow with PKCE. Public clients (single-page and mobile apps) must use PKCE; confidential
    clients should.
  - Flag the implicit grant (`response_type=token`) and any use of the resource owner password credentials grant
    (`grant_type=password`), which must not be used.
  - Redirect URIs must match exactly as registered; flag prefix, wildcard or regex matching. Native apps should
    be registered with claimed https redirects (app links), not a wildcard custom scheme. Validate `state` and,
    for OIDC, `nonce`. No tokens in URLs. (RFC 8252)
  - Access tokens should be audience-restricted, and resource servers must reject tokens issued for another
    audience. Refresh tokens for public clients must be sender-constrained or rotated on every use, with reuse
    detection. A browser app that handles sensitive data should keep those tokens in a backend-for-frontend,
    not in JavaScript. (RFC 10017)

## Step-up authentication (OTP / one-time proofs)
- Sensitive operations (reveal card data or CVV, PIN, card status, reissue or replacement, limits, beneficiaries,
  transfers, profile or contact changes, account deletion) need step-up authentication. Flag any new or changed
  sensitive endpoint without it, even in a class that has never used step-up. Prefer deny-by-default over opt-in
  lists. Siblings that already require step-up are supporting evidence, not a condition for reporting.
- OTPs must be verified on the server against the stored challenge. Flag OTPs compared only in the client,
  returned in an API response, or accepted from a caller-supplied code without that check.
- Flag OTP verification that a flag, DB column, property, management or admin endpoint can bypass (`bypass`,
  `skipOtp`, `verify.bypass`), and any runtime toggle that can disable a security check in production.
- A proof of OTP (stepId, challenge or verification token) must be single-use (marked used atomically), short-lived,
  and bound to the user, tenant and exact operation, plus a hash of amount and target for payments. Flag proofs
  checked only for existence, used flag or age, or reusable after the flow completes. (CWE-294)
- Flag a protected action in a separate endpoint that doesn't check a server-side proof that the OTP step
  succeeded, which leaves step order to the client.
- Flag proofs minted by a public lookup (card number, national id, username) with no OTP, then accepted to reset
  credentials.
- OTP generation and verification need per-user, per-phone and per-IP limits with lockout. Counters must be checked
  and incremented in one atomic operation, or parallel requests bypass them. Flag hardcoded OTP values or ids
  (`"11111"`, `"123456"`).

## Passwords and authenticators (NIST SP 800-63B-4 final, section 3.1.1.2)
- Minimum length: 15 characters for a password used as the only factor (SHALL). It may be shorter when used only
  inside MFA, but never under 8 (SHALL). (Earlier drafts said "8 SHALL, 15 SHOULD"; the final text above
  replaces that.)
- Maximum length of at least 64 (SHOULD), with printable ASCII, Unicode and spaces accepted. Verify the whole
  password and never truncate it (SHALL).
- Flag composition rules (forced upper/lower/digit/symbol mixes), forced periodic rotation without evidence of
  compromise, password hints, and knowledge-based security questions as an authenticator.
- New or changed passwords must be checked against breached and common-password lists.
- OTPs must be short-lived and limited in attempts. Treat SMS OTP as a weaker channel: don't use it alone to
  recover high-value accounts or change the registered phone.

## Sessions, devices and credentials
- Logout must invalidate the server session or token, not only the client copy. (CWE-613)
- Flag long-lived tokens, refresh tokens without rotation, and sessions not renewed after login or a privilege
  change. (CWE-384)
- Where device binding is in scope, login and sensitive flows must check the bound device, with step-up on a new
  device.
- Flows that create accounts or credentials must reject duplicates (unique constraint plus an existence check).
- Service-to-service calls must authenticate. Flag new internal calls without credentials. Prefer short-lived,
  per-workload credentials (mTLS or workload identity, OAuth client credentials, vault-issued dynamic secrets)
  over long-lived shared static tokens. Flag a new shared secret reused across several services (`suggestion`).
