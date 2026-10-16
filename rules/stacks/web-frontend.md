---
detect:
  - "package.json with react, react-dom, next, @angular/core, vue, nuxt, svelte, @sveltejs/kit, solid-js, @remix-run/react or astro"
  - "index.html with a bundler config (vite, webpack, angular.json)"
---

# Stack: browser front ends (React, Next.js, Angular, Vue, Nuxt, Svelte, Solid, Astro)

Use with `client-side.md` and the category files. Server code inside these frameworks also uses
`node-backend.md`. Browser findings map to ASVS V3 and WSTG-CLNT; OAuth in the page also maps to RFC 10017.

## Entry points
- Routes and pages (React Router, Next.js `app/` and `pages/`, Angular `Routes`, Vue Router, SvelteKit routes),
  route guards and loaders, forms, API client modules (axios instances, `fetch` wrappers, generated SDKs), auth
  providers and token handling, `postMessage` listeners, service workers, and URL and query parameters read by
  components.

## Rendering and DOM sinks
- React: `dangerouslySetInnerHTML`, `ref.current.innerHTML`, `href`/`src` from data (React does not block
  `javascript:` in every version), `react-markdown` with `rehype-raw`, `html-react-parser` on untrusted HTML.
- Next.js: `dangerouslySetInnerHTML` in `next/script` or `<Script>` with data; `next/image` `remotePatterns` with
  wildcards (open image proxy); `redirect()`/`router.push` with unvalidated `callbackUrl`.
- Angular: `bypassSecurityTrustHtml`/`Url`/`ResourceUrl`/`Script`/`Style`, `[innerHTML]` with trusted values,
  `ElementRef.nativeElement.innerHTML`, `Renderer2.setProperty` with `innerHTML`, templates built at runtime.
- Vue/Nuxt: `v-html`, render functions with `innerHTML`, `:href` from data, templates compiled at runtime from
  data.
- Svelte/SvelteKit: `{@html}`. Solid: `innerHTML` prop. Astro: `set:html`.
- jQuery or direct DOM code: `html()`, `append()` with strings, `$(location.hash)`.

## Tokens, auth and API calls
- Auth libraries (`oidc-client-ts`, `@auth0/*`, `next-auth`/Auth.js, `angular-oauth2-oidc`, MSAL): PKCE on, implicit
  flow off, `userStore`/`cacheLocation` not `localStorage` for refresh tokens, silent renew via refresh tokens or a
  backend rather than third-party-cookie iframes. An app that handles money, cards or other sensitive data follows
  RFC 10017: a backend-for-frontend holds the tokens. Flag a public SPA that stores a refresh token.
- `next-auth`/Auth.js: strong `NEXTAUTH_SECRET`/`AUTH_SECRET`, `callbacks.redirect` restricted to the app's origin,
  session callbacks that don't copy access tokens to the client unless needed.
- Axios or fetch interceptors that attach tokens must send them only to the app's API origins, not to absolute URLs
  from data.
- Angular `HttpClient` XSRF support or framework CSRF tokens when the API uses cookies.

## Build-time configuration
- Public env prefixes: `NEXT_PUBLIC_`, `REACT_APP_`, `VITE_`, `NUXT_PUBLIC_`/`runtimeConfig.public`, `PUBLIC_`
  (SvelteKit, Astro), `NG_APP_`; Angular `environment*.ts`. Flag secrets there.
- `productionBrowserSourceMaps: true` (Next.js), `build.sourcemap: true` (Vite), Angular `sourceMap` in the
  production configuration, webpack `devtool` in production.
- Headers and CSP set in `next.config.*` `headers()`, middleware, the hosting config (`vercel.json`,
  `netlify.toml`, nginx) or `<meta http-equiv>`; check one of them really sets the ASVS V3.4 set from
  `configuration-supply-chain.md` (HSTS, CSP with `object-src`, `base-uri` and `frame-ancestors`, `nosniff`,
  `Referrer-Policy`, `Cross-Origin-Opener-Policy`, `Permissions-Policy`). A `<meta>` tag cannot set every
  header; HSTS and `frame-ancestors` need a real response header.

## Dependencies
- Old Angular (AngularJS 1.x is end of life), Next.js versions with the middleware authorization bypass
  (CVE-2025-29927; fixed in 12.3.5, 13.5.9, 14.2.25 and 15.2.3), React Router and Nuxt advisories, `dompurify`
  below 3.2.4, and sanitizers or markdown libraries with raw HTML on.
