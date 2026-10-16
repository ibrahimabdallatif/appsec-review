---
paths:
  - "**/*.{ts,tsx,js,jsx,mjs,cjs,vue,svelte,html,dart,swift,kt,java}"
  - "{next,nuxt,vite,webpack,angular,svelte,astro,remix}.config.*"
  - "angular.json"
  - "{app,app.config,eas}.{json,js,ts}"
  - "**/AndroidManifest.xml"
  - "**/network_security_config.xml"
  - "**/Info.plist"
  - "**/*.entitlements"
  - "**/.env*"
---

# Client-side security: web front ends and mobile apps

OWASP A01/A02/A04/A05/A07:2025, ASVS 5.0 V3 (Web Frontend Security) and V10, WSTG-CLNT, RFC 10017.
OWASP MASVS 2.1, MASTG 2.0, MASWE 1.0, Mobile Top 10:2024, RFC 8252.
CWE-79, CWE-601, CWE-922, CWE-312, CWE-346, CWE-1021, CWE-200, CWE-540, CWE-829, CWE-602, CWE-295,
CWE-926, CWE-939.

Apply this file to single-page apps, server-rendered front ends, browser extensions and mobile apps. Code that runs
on a server inside a front-end framework (server components, API routes, server actions, loaders, middleware) is
server code: apply the other category files to it as well. The stack file names the framework's own sinks.

## Trust model
- Everything shipped to the browser or device is readable and changeable by the user. Flag authorization, prices,
  limits, eligibility, feature or role flags, and step order enforced only in client code, with no matching server
  check. Hiding a button, route or menu is not access control. (CWE-602)
- Flag secrets in client code or in build-time variables exposed to the bundle (`NEXT_PUBLIC_*`, `REACT_APP_*`,
  `VITE_*`, `EXPO_PUBLIC_*`, `NG_APP_*`, Angular `environment.ts`, Flutter `--dart-define`, mobile resource and
  plist files): API secrets, signing keys, private service tokens, database or admin credentials. Public client ids
  and publishable keys are fine, including the Supabase anon or publishable key and the Firebase web `apiKey`;
  the Supabase `service_role` or `sb_secret_` key and Firebase service-account JSON are not. (CWE-540, CWE-798)
- Client-side validation is for usability only. Report the missing server check, not the client code, when only
  the client validates.

## XSS and DOM injection
- Flag HTML rendered from data without sanitizing it: `dangerouslySetInnerHTML`, `innerHTML`, `outerHTML`,
  `insertAdjacentHTML`, `document.write`, Vue `v-html`, Angular `[innerHTML]` with `bypassSecurityTrust*`,
  Svelte `{@html}`, jQuery `html()`/`append()` with strings, and markdown or rich-text renderers with raw HTML on.
  Use the framework's escaping, or a maintained sanitizer such as DOMPurify. (CWE-79)
- Flag URLs from data placed in `href`, `src`, `action`, `formaction` or `window.location` without allowing only
  `https:` (and known schemes), so `javascript:` and `data:` URLs can't run. (CWE-79)
- Flag `eval`, `new Function`, string `setTimeout`/`setInterval`, and dynamic script injection with data.
- Flag DOM clobbering: a security decision that reads an undeclared global, or a named property of `document`
  or `window`, which HTML `id` or `name` can overwrite. (ASVS 3.2.3, CWE-79)
- Render data as text (`textContent`, `createTextNode`, or the framework's text binding). Flag a path that
  parses data as HTML when it is only meant to be displayed. (ASVS 3.2.2)
- Prefer Trusted Types and a strict CSP as defence in depth.

## Tokens and storage
- Flag access, refresh or session tokens in `localStorage`, `sessionStorage`, IndexedDB or readable cookies in web
  apps. Prefer `HttpOnly` cookies (a backend-for-frontend) or keeping tokens in memory only. (CWE-922)
- Flag sensitive data (card data, national ids, OTPs, full profiles) persisted in browser storage, state
  persistence libraries, service worker caches, or URLs and browser history.
- Logout must clear client storage and caches and call the server to revoke the session.

## OAuth and sessions in the browser and apps
- Browser apps (RFC 10017, RFC 9700) are public clients: authorization code with PKCE, no implicit flow, no
  client secret in the page, `state` checked, tokens never in URLs, fragments or logs. An app that handles
  money, cards or other sensitive data should use a backend-for-frontend and keep tokens in `HttpOnly`
  cookies. If the page must hold tokens, keep them in memory only, and do not keep a refresh token in
  JavaScript.
- Native apps (RFC 8252, MASVS-AUTH) follow the same public-client rules. The authorization request must open
  in the system browser (`ASWebAuthenticationSession`, Custom Tabs), never in an embedded WebView. Redirects
  use claimed https links (App Links, Universal Links). A custom URI scheme is a weaker fallback and must not
  carry the token.

## Navigation, messaging and framing
- Flag open redirects from `returnUrl`, `next`, `redirect` or deep-link parameters without an allow-list of
  paths or hosts. (CWE-601)
- Flag `postMessage` sent with target origin `*` when the message carries data, and `message` listeners that don't
  check `event.origin` against an exact allow-list. (CWE-346)
- Flag iframes of untrusted content without `sandbox`, and pages that must not be framed without
  `frame-ancestors`. (CWE-1021)

## Content Security Policy and third parties
- Front ends need the browser headers in `configuration-supply-chain.md` (ASVS V3.4, Mozilla Web Security
  Guidelines): HSTS, CSP, `nosniff`, `Referrer-Policy`, `frame-ancestors`, `Cross-Origin-Opener-Policy` and
  `Permissions-Policy`. Flag a missing or permissive CSP. The CSP must not use `unsafe-inline` or `unsafe-eval`
  for scripts (nonces or hashes instead) and must set `object-src 'none'`, `base-uri` and `frame-ancestors`.
- Third-party scripts loaded from a CDN need Subresource Integrity (`integrity` plus `crossorigin`). Flag tag
  managers, analytics or chat widgets on pages with credentials or card data, and session-replay tools that record
  sensitive fields. (CWE-829)
- Flag personal or card data sent to analytics, crash reporting or error-tracking tools without scrubbing.

## Build and delivery
- Flag source maps published in production builds, debug or development builds shipped, verbose `console` logging
  of tokens, requests or user data, and dev servers or mock APIs reachable in production. (CWE-200, CWE-540)
- Calls with `credentials: 'include'` or `withCredentials` must go only to the app's own API origins.
- Server-rendered frameworks: flag server-only data or secrets passed to client components or embedded in page
  state (props, hydration data, `__NEXT_DATA__`), and server-only modules imported into client code.

## Mobile apps (React Native, Expo, Flutter, Android, iOS)

Map each finding to the MASVS control, a MASWE id when one fits, and the Mobile Top 10 id. MASTG 2.0 is the
test procedure. The stack file names the platform APIs.

- Storage (MASVS-STORAGE, M1, M9): tokens, keys and sensitive data go in the Keychain or Keystore
  (`expo-secure-store`, `react-native-keychain`, `flutter_secure_storage`, EncryptedSharedPreferences). Flag
  them in AsyncStorage, SharedPreferences, `UserDefaults`, plain SQLite, files, logs, or app backups
  (`android:allowBackup`). (CWE-312)
- Cryptography (MASVS-CRYPTO, M10): follow `cryptography-data-protection.md`. Flag hardcoded or embedded keys,
  a key derived only from a password with no hardware backing, static IVs, and `Math.random`, Dart `Random` or
  `java.util.Random` used for keys or tokens. Keys created on the device should be non-exportable Keystore or
  Keychain keys.
- Network (MASVS-NETWORK, M5): flag cleartext traffic (`usesCleartextTraffic`, `cleartextTrafficPermitted`,
  iOS ATS exceptions such as `NSAllowsArbitraryLoads`), custom trust that accepts any certificate, and
  user-installed CAs trusted in release builds. Banking and payment apps should pin certificates or public
  keys, with a backup pin. (CWE-295)
- Platform (MASVS-PLATFORM, M8): flag exported activities, services, receivers or providers without permissions,
  implicit intents that carry sensitive extras, and deep links or intents whose parameters drive navigation or
  actions without validation. WebViews with JavaScript enabled on untrusted content, `originWhitelist={['*']}`,
  JavaScript bridges exposed to remote pages, file access from URLs, and `onMessage` handlers without an origin
  check are the same class of bug. Sensitive screens should ignore touches while obscured (tapjacking).
  (CWE-926, CWE-939)
- User interface (MASVS-PLATFORM-3, M9): sensitive screens should block screenshots and recents previews
  (`FLAG_SECURE`, a blur overlay). Do not put OTPs, PANs or credentials on the clipboard or on the lock-screen
  notification. (CWE-200)
- Authentication (MASVS-AUTH, M3, RFC 8252): biometric unlock must release a Keystore or Keychain key bound to
  biometrics, not just set a boolean. Re-authenticate for sensitive actions. Local PIN or biometric checks do
  not replace the server check.
- Privacy (MASVS-PRIVACY, M6): request only the permissions the feature needs. Flag contacts, SMS, precise
  location, camera, microphone, photos or clipboard access with no use in that feature, and analytics or crash
  SDKs that receive those values or card data. Flag a stable device identifier (advertising id, Android ID,
  IMEI, or an IDFV used for tracking) sent off the device, and a third-party SDK started before consent. When
  the privacy text is in the repository, flag collection it does not mention.
- Code (MASVS-CODE, M4): treat deep links, intent extras, notification payloads, the clipboard and WebView URLs
  as untrusted input and validate them before they navigate or change state. Flag a `minSdk` or deployment
  target so old that the OS no longer receives security patches, and an app with no way to force an update
  after a critical fix. (MASVS-CODE-1, MASVS-CODE-2, MASVS-CODE-4)
- Resilience (MASVS-RESILIENCE, M7): root, jailbreak and tamper detection, and app attestation (Play Integrity,
  App Attest), are defence in depth and must be verified on the server. Flag `android:debuggable`, debug menus
  and dev servers in release builds.
- Updates and supply chain (MASVS-CODE, M2): over-the-air updates (Expo Updates, CodePush) must be code-signed
  and verified by the app. Flag a dependency or native SDK with a known vulnerability, same as the supply-chain
  checks.
