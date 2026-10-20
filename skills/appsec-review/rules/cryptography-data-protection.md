---
paths:
  - "**/*.{java,kt,scala,groovy,ts,tsx,js,jsx,mjs,cjs,vue,svelte,py,go,cs,rb,php,rs,dart,swift}"
  - "**/*.{properties,yml,yaml,json,xml,toml,ini,config,plist,gradle}"
  - "**/.env*"
  - "**/Dockerfile*"
  - "**/docker-compose*"
  - ".github/**/*"
---

# Cryptography, secrets, transport and data protection

OWASP A04:2025, ASVS V11/V12/V14, MASVS-CRYPTO, Mobile Top 10 M10, PCI DSS v4.0 req. 3, 4 and 6.2.4.
CWE-798, CWE-321, CWE-327, CWE-328, CWE-329,
CWE-330, CWE-338, CWE-760, CWE-916, CWE-295, CWE-319, CWE-312, CWE-532, CWE-524, CWE-359.

The stack file for the repository (`rules/stacks/`) names the language's crypto, random and TLS APIs.

## Secrets
- No credentials, API keys, account SIDs, auth tokens, client secrets, DB or identity-provider passwords, private
  keys, IVs, salts or encryption keys in code, config defaults (`${ENV:literal-secret}`, `os.getenv("X", "literal")`,
  `process.env.X || "literal"`), Dockerfiles, workflows, committed `.env` files or docs. They must come from env
  vars or a vault with no committed default. (CWE-798, CWE-321)
- Look especially at constant classes and modules, config files, seeders and fixtures, and test or demo harnesses
  left in production source. Flag new literals that look like secrets (high entropy, `key=`, `secret=`,
  `password=`, `token=`, Base64 blocks).
- Anything compiled into a web bundle or mobile app is public. See `client-side.md`.
- Flag secrets passed in URLs or query strings, or printed in logs, exceptions or startup output.

## Cryptography
- Use approved algorithms and modes: AES-GCM (or AES-CBC with HMAC when an external contract requires it), RSA-OAEP
  with 2048 bits or more, ECDSA/EdDSA, SHA-256 or higher. Flag DES/3DES/RC4/Blowfish, ECB (including library
  defaults that pick ECB when no mode is named), RSA without padding, and MD5/SHA-1 for signatures or integrity.
  (CWE-327, CWE-328)
- Keys belong in env vars or a vault. IVs, nonces and salts don't: each must be random per message or record (from
  a CSPRNG), stored or sent with the ciphertext, and never reused with the same key. Flag literal or constant IVs
  and salts, one IV or salt read from config and reused for every message, and deterministic ciphertext for equal
  inputs. Moving a static IV or salt into an env var doesn't fix the reuse. (CWE-329, CWE-760)
- Accept a fixed IV, salt or KDF setting only when a named external contract (another system's API spec) requires
  it and the code says so. Even then it must not be committed (it comes from config), and report it as a `warning`
  so the contract owner can be asked to move to per-message values.
- Passwords, security answers and other compare-only secrets must be one-way hashed with bcrypt, scrypt, Argon2 or
  PBKDF2-HMAC-SHA256 with at least 600,000 iterations, never reversibly encrypted. (CWE-916)
- Use a CSPRNG for tokens, OTPs, ids and keys (`SecureRandom`, `crypto.randomBytes`/`randomUUID`/`getRandomValues`,
  Python `secrets`, Go `crypto/rand`, .NET `RandomNumberGenerator`). Flag general-purpose generators
  (`java.util.Random`, `Math.random`, Python `random`, Go `math/rand`, `System.Random`) or timestamps used for
  security values. (CWE-330, CWE-338)
- Compare MACs, tokens and OTPs in constant time (`MessageDigest.isEqual`, `crypto.timingSafeEqual`,
  `hmac.compare_digest`, `subtle.ConstantTimeCompare`, `CryptographicOperations.FixedTimeEquals`). (CWE-208)
- Don't write home-made crypto. Prefer high-level, misuse-resistant libraries (e.g. Google Tink, libsodium bindings)
  and AEAD modes over hand-assembled cipher, padding and MAC code. Flag new low-level crypto code where an existing
  helper or such a library fits.
- On a mobile app these rules are MASVS-CRYPTO and Mobile Top 10 M10. Keys created on the device should be
  non-exportable Keystore or Keychain keys. Storage and backup rules are in `client-side.md`.

## Transport
- Outbound calls carrying credentials or user data need both of these controls:
  - certificate chain validation against the platform trust store or a pinned trust store, with no trust-all or
    accept-any trust manager, callback or agent;
  - hostname verification, with no verifier that always returns true.

  One control does not replace the other: a hostname check doesn't make a trust-all trust manager safe. Flag
  disabled verification in any form: Java trust-all managers and `NoopHostnameVerifier`, Node
  `rejectUnauthorized: false` or `NODE_TLS_REJECT_UNAUTHORIZED=0`, Python `verify=False`, Go
  `InsecureSkipVerify: true`, .NET certificate validation callbacks that return true, and the mobile equivalents
  in `client-side.md`. Also flag `http://` base URLs. (CWE-295, CWE-319)
- Check where the safe client is chosen: a verifying client selected only under some environment or profile names
  is ineffective when production runs under a name not in that list.
- Flag TLS below 1.2 or weak cipher suites enabled in config.

## Card and personal data (PCI DSS)
Apply this section when the code handles cardholder data; otherwise say in the report that it was not in scope.
- Never store CVV/CVV2, PIN or full track data after authorization. Flag new columns, caches or logs holding them.
- Never return CVV in clear text in general card list or details responses. It may only reach the client through
  a dedicated flow with ownership check and step-up, preferably as a provider-hosted view the server never sees.
- Show PANs masked (first 6 / last 4 at most) unless a specific authorized, step-up-protected flow needs the full
  PAN. Flag full PANs in responses, logs, exceptions, metrics or string representations of objects. (PCI 3.4)
- Encrypt or tokenize sensitive data at rest (PAN, national id, tokens). Flag new plaintext columns or files.
  (CWE-312)
- Responses with sensitive data or one-time URLs must send `Cache-Control: no-store`. Flag sensitive data in GET
  query strings or shared caches. (CWE-524)
- Collect and return only the personal data the feature needs. Flag new PII fields with no clear use. (CWE-359)
- Models with sensitive fields need a redacting string representation and serializer (`toString`, `__repr__`,
  `inspect`, JSON output). Flag generated `toString` or default serialization on them. (CWE-532)
