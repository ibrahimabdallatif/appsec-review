---
paths:
  - "**/*.{java,kt,scala,groovy,ts,tsx,js,jsx,mjs,cjs,vue,svelte,py,go,cs,rb,php,rs,dart,swift}"
  - "**/*.{properties,yml,yaml,json,xml,toml,ini,config,plist}"
  - "pom.xml"
  - "build.gradle*"
  - "settings.gradle*"
  - "package.json"
  - "{package-lock.json,npm-shrinkwrap.json,yarn.lock,pnpm-lock.yaml,bun.lockb}"
  - "{requirements*.txt,pyproject.toml,Pipfile*,poetry.lock,uv.lock}"
  - "{go.mod,go.sum,Cargo.toml,Cargo.lock,Gemfile*,composer.*}"
  - "**/*.csproj"
  - "**/Directory.Packages.props"
  - "**/pubspec.*"
  - "**/Podfile*"
  - ".github/**/*"
  - "{.gitlab-ci.yml,Jenkinsfile,azure-pipelines.yml,bitbucket-pipelines.yml}"
  - "**/Dockerfile*"
  - "**/docker-compose*"
  - "**/compose.y*ml"
  - "**/*.tf"
  - "**/*.tfvars"
  - "**/*.tf.json"
  - "**/k8s/**/*"
  - "**/kubernetes/**/*"
  - "**/helm/**/*"
  - "**/charts/**/*"
---

# Security configuration, supply chain and API inventory

OWASP A02/A03/A08:2025, API8/API9:2023, ASVS V3/V4/V13/V15 (V3.3 cookies, V3.4 headers, V3.5 origin separation),
WSTG-CONF/WSTG-INFO, Mozilla Web Security Guidelines. CWE-1395, CWE-1104, CWE-494,
CWE-829, CWE-942, CWE-352, CWE-489, CWE-215, CWE-1021, CWE-348, CWE-614, CWE-1004, CWE-250.

The stack file for the repository (`rules/stacks/`) names the framework's tooling endpoints, config keys and
dependency lines to watch.

## Exposed tooling
- API documentation and explorers (Swagger UI, OpenAPI JSON, GraphQL introspection and playgrounds) must be off or
  authenticated outside development. Flag them in unsecured or excluded path lists, or enabled in production
  config, without a development-only guard. (CWE-215)
- Management and diagnostic endpoints (health details, metrics, environment, heap or thread dumps, profilers,
  log-level changes, admin consoles, debug toolbars) must not be reachable without strong authentication. Flag
  custom management endpoints that change security behaviour. (CWE-489)
- Flag development tooling and modes shipped to production: hot-reload or dev-tools packages in the deployable
  artifact, debug flags on, development builds or `NODE_ENV` not set to production.
- Flag debug, test or bypass endpoints, controllers or modules in production source without a development-only
  guard.

## Application configuration
- Flag detailed errors or stack traces returned to clients, SQL or ORM query logging, DEBUG logging of HTTP
  bodies, or development-only components active in production config.
- Security switches must default to the safe value. Flag `${FLAG:false}`-style defaults where the default turns a
  check off, and feature flags gating security controls whose default when missing is "off".
- Environment or profile names used to switch security on must match the names production really uses. Flag a
  control enabled only for a list of names (`prod`, `production`, ...) when deployments run under another name.
- Flag client IPs read from `X-Forwarded-For`, `X-Real-IP` or `Forwarded` for audit or access decisions without a
  trusted-proxy setup. (CWE-348)

## HTTP security (ASVS V3, Mozilla Web Security Guidelines)
- CORS: flag wildcard origins with credentials, reflected request origins, origin checks by substring or
  unanchored regex, and `null` allowed as an origin. `Access-Control-Allow-Origin: *` must not be used on a
  response that carries sensitive data. (ASVS 3.4.2, CWE-942)
- CSRF: with cookie-based auth, CSRF protection must stay on (token or `SameSite` plus origin checks). Flag it
  disabled unless auth is bearer-only. State-changing operations must not be reachable with a CORS-safelisted
  request that skips the preflight. (ASVS 3.5.1, 3.5.2, CWE-352)
- Browser security headers on document responses, and on other responses where the header still applies
  (ASVS 3.4, CWE-1021):
  - `Strict-Transport-Security` with `max-age` of at least one year (31536000). Add `includeSubDomains` when
    the deployment owns the subdomains. (ASVS 3.4.1)
  - `Content-Security-Policy` with `object-src 'none'`, `base-uri 'none'`, and either an allow-list or nonces
    or hashes for scripts. No `unsafe-inline` or `unsafe-eval` for scripts. Use `frame-ancestors` so the page
    cannot be embedded by default. `X-Frame-Options` is obsolete and does not replace `frame-ancestors`.
    (ASVS 3.4.3, 3.4.6)
  - `X-Content-Type-Options: nosniff`. (ASVS 3.4.4)
  - `Referrer-Policy` of `strict-origin-when-cross-origin` or stricter, so paths and query strings are not sent
    to other sites. (ASVS 3.4.5)
  - `Cross-Origin-Opener-Policy: same-origin`, or `same-origin-allow-popups` when the page must open popups.
    (ASVS 3.4.8)
  - `Permissions-Policy` that disables camera, microphone, geolocation and payment unless that page needs them.
  - `Cache-Control: no-store` on responses that carry credentials or sensitive data.
- Files a user uploaded, or other content that must not run in the site origin, need `Content-Disposition:
  attachment`, a matching `Content-Type`, and `nosniff` (or a CSP `sandbox`). (ASVS 3.2.1)
- Cookies carrying sessions or tokens need `Secure`, `HttpOnly` and `SameSite` (`Lax` or `Strict`). Prefer the
  `__Host-` prefix, which requires no `Domain` attribute and `Path=/`. Where a `Domain` or narrower `Path` is
  really needed, use `__Secure-` instead. Omit `Domain` whenever possible (host-only is safer). Flag tokens stored
  in readable cookies or sent in URLs. (ASVS 3.3, CWE-614, CWE-1004)
- Flag JSONP and callback parameters that reflect script: they bypass the same-origin policy. (ASVS 3.5.6)
- Flag HTTP methods allowed beyond what the endpoint needs, and TRACE enabled. State-changing actions must not
  run on GET. (ASVS 3.5.3)

## Dependencies and build (supply chain)
- Treat a dependency CVE listed in the CISA Known Exploited Vulnerabilities catalog as `critical`, whatever its
  CVSS score.
- Flag end-of-life framework or runtime lines and versions with known critical CVEs when the build file changes.
  The stack file lists the lines to watch for each ecosystem. (A03, CWE-1395)
- Flag unmaintained libraries, unpinned or ranged versions, missing or uncommitted lock files, CI installs that
  ignore the lock file (`npm install` instead of `npm ci`), registries over `http://`, dependency-confusion risks
  (internal package names resolvable from a public registry), likely typosquats, install scripts from untrusted
  packages, and build plugins that download or run code without checksums. (CWE-1104, CWE-494, CWE-829)
- CI pipelines: flag third-party actions or images not pinned to a full commit SHA or digest,
  `pull_request_target` checking out PR code, untrusted event fields (`${{ github.event.* }}`) interpolated into
  shell steps (script injection), secrets printed to logs, and write-all permissions where read is enough.
- Install scripts: CI and Docker builds should install with lifecycle scripts off (`npm ci --ignore-scripts`,
  pnpm `onlyBuiltDependencies` or `ignoredBuiltDependencies`, Yarn `enableScripts: false`) and allow only the
  reviewed packages that need a build step. Flag builds that run every dependency's install script with
  registry tokens, cloud credentials or signing keys in the environment. (CWE-829)
- Release cooldown: automated dependency updates (Renovate `minimumReleaseAge`, Dependabot `cooldown`, pnpm
  `minimumReleaseAge`) should wait a set time before adopting a new release, so a hijacked version has time to
  be caught. Flag auto-merge of brand-new releases with no cooldown (`suggestion`), and wildcard exclusions from
  it. Security fixes can be exempted per package, with an owner and an expiry.
- Publishing (repositories that publish packages, images or apps): prefer registry trusted publishing (OIDC)
  over long-lived tokens. Flag publish tokens stored as repository secrets when the registry supports OIDC,
  `id-token: write` granted to jobs that don't publish, and release workflows that anyone with write access can
  trigger without a protected environment or required reviewers.
- Provenance and SBOM: release pipelines should generate provenance (SLSA build provenance, npm `--provenance`,
  `actions/attest-build-provenance`) and an SBOM per release (`npm sbom`, syft, cdxgen; CycloneDX or SPDX). Flag
  missing ones in release workflows (`suggestion`), and consumers that pull internal artifacts without verifying
  their signature or provenance.
- MCP servers, agent plugins, editor or browser extensions, and model files used by the build or the product are
  dependencies too: pin them by version or digest and record them in the SBOM. (`ai-llm-agents.md` covers their
  runtime use.)

## Containers and infrastructure as code
- Dockerfiles: pin base images to a digest or exact version (not `latest`), run as a non-root `USER`, and use `COPY`
  rather than `ADD` with remote URLs. Flag secrets in `ENV`, `ARG` or copied files, package installs without
  pinned versions, and `curl | sh`.
- Kubernetes or Helm: flag `privileged: true`, `allowPrivilegeEscalation` not set to false, missing
  `runAsNonRoot`, writable root filesystems, `hostNetwork`/`hostPID`/`hostPath`, missing CPU and memory limits,
  secrets in plain manifests or values files, and service accounts with broad RBAC or auto-mounted tokens they
  don't need.
- Terraform and other IaC: flag public storage, `0.0.0.0/0` ingress on admin or database ports, unencrypted
  storage and databases, wildcard IAM actions or resources, and disabled audit logging.

## Integrity of data and updates
- Data from clients or third parties that drives security decisions (signed payloads, callbacks, webhooks) must
  have its signature or MAC verified before use. (A08, CWE-345)
- Release artifacts, images and over-the-air app updates should be signed and verified before they run (e.g.
  Sigstore/cosign, code-signed update bundles). Flag pipelines that deploy images built outside CI or skip
  signature checks (`suggestion`).
- Flag deserializing or executing code or config from untrusted locations.

## API inventory
- Document every new or changed endpoint (OpenAPI annotations or files, service docs) with its auth, roles and
  error codes. Flag undocumented endpoints, old API versions left reachable after a replacement, and test or debug
  endpoints in production source. (API9)
- Flag the same function exposed under two paths where one has weaker checks.
