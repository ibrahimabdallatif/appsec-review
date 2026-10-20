---
detect:
  - "package.json with @nestjs/core, express, fastify, koa, @hapi/hapi, hono, next, nuxt, @remix-run/*, @sveltejs/kit or astro"
  - "TypeScript or JavaScript server code (server.ts, main.ts, app.js, routes/, api/)"
---

# Stack: Node.js back ends (NestJS, Express, Fastify, Koa, Hapi, Hono) and server code in full-stack frameworks

Use with the category files. For Next.js, Nuxt, Remix, SvelteKit and Astro, the server parts are here and the
browser parts are in `web-frontend.md`.

## Entry points
- NestJS: `@Controller` classes and verb decorators, `@MessagePattern`/`@EventPattern`, gateways
  (`@WebSocketGateway`), GraphQL resolvers, `@Cron` jobs. Global and route `Guard`s, `Pipe`s, `Interceptor`s,
  middleware and exception filters, and their order in `main.ts`/modules.
- Express/Koa/Fastify/Hono: `app.METHOD`/`router.METHOD`/`fastify.route`, `app.use` order (routes mounted before
  auth middleware are public), Fastify hooks (`onRequest`, `preHandler`).
- Full-stack frameworks: Next.js route handlers (`app/**/route.ts`), API routes (`pages/api`), server actions
  (`'use server'`), `middleware.ts` (`proxy.ts` from Next.js 16), `getServerSideProps`; Nuxt `server/api`; Remix
  and SvelteKit loaders and actions; Astro endpoints. Server actions are public POST endpoints: each needs its own
  auth and authorization.
- Next.js `middleware.ts` alone is not authorization: re-check in each handler and data function.
- Supabase and Firebase called from this code: see `baas.md`.

## Access control
- NestJS: `@UseGuards` with `AuthGuard`, roles guards and `Reflector` metadata; global guards via `APP_GUARD`.
  Flag `@Public()`-style decorators that skip the global guard on new routes.
- Identity from the verified `req.user` set by Passport or the guard, not from `req.body`, `req.query`,
  `req.params` or headers.
- Mass assignment: `repository.save(req.body)`, `Object.assign(entity, dto)`, `{...req.body}` into Prisma,
  TypeORM, Sequelize or Mongoose models; Mongoose schemas without `strict`.
- Request context in `AsyncLocalStorage`/`cls-hooked` must be scoped per request.

## Authentication and tokens
- `jsonwebtoken`: `jwt.decode` instead of `jwt.verify`; `verify` without `algorithms`, `issuer`, `audience`; secret
  or key from the token. `jose`: `decodeJwt` used for authorization. Passport JWT strategy with
  `ignoreExpiration: true`.
- `express-session`/`cookie-session`: weak or committed `secret`, `cookie.secure` false, no `httpOnly`/`sameSite`,
  in-memory store in production, no `regenerate` after login.

## Validation and injection
- NestJS: `ValidationPipe` registered globally with `whitelist: true` and `forbidNonWhitelisted: true`, DTOs with
  `class-validator` decorators; `@Body() body: any` or plain interfaces skip validation. Express/Fastify: zod,
  joi, yup, ajv or Fastify schemas on every route.
- SQL: template literals or `+` into `query`, `$queryRawUnsafe`/`$executeRawUnsafe` (Prisma), TypeORM
  `query`/`createQueryBuilder().where(\`...${x}\`)`, Sequelize `literal`, Knex `raw` with interpolation.
- NoSQL: `req.body` fields passed into Mongoose or MongoDB filters without casting (`{ $ne: null }`), `$where`.
- Commands and code: `child_process.exec`/`execSync` with input (use `execFile` with an argument list), `eval`,
  `new Function`, `vm.runInNewContext` (not a sandbox), dynamic `require`/`import`.
- Prototype pollution: `lodash.merge`/`set`/`defaultsDeep`, `deep-extend`, custom deep merges on request JSON.
- Paths: `res.sendFile`/`fs` with input without `path.resolve` plus a base-directory check; `express.static` on
  broad folders.
- Templates: EJS/Pug/Handlebars with unescaped output (`<%-`, `!=`, `{{{`) of user data.

## Cryptography and transport
- `crypto.createCipher` (deprecated, no IV), `createCipheriv` with a constant IV, `aes-*-ecb`, `Math.random` for
  tokens; use `crypto.randomBytes`/`randomUUID` and `crypto.timingSafeEqual`.
- `https.Agent({ rejectUnauthorized: false })`, `NODE_TLS_REJECT_UNAUTHORIZED=0`, axios/got/undici configured to
  skip verification.
- Money: no JavaScript `number` arithmetic on fractional amounts; use integer minor units or a decimal library.

## Configuration and tooling
- `helmet` (or equivalent headers), `cors` with `origin: true`/reflected origins and `credentials: true`, CSRF for
  cookie sessions, `app.disable('x-powered-by')`, body size limits (`express.json({ limit })`, Fastify
  `bodyLimit`), `trust proxy` set only with known proxies.
- `@nestjs/swagger` `SwaggerModule.setup` and GraphQL `playground`/`introspection` enabled in production;
  `NODE_ENV` not `production`; stack traces in error handlers.
- Rate limiting (`@nestjs/throttler`, `express-rate-limit`) backed by a shared store when there are several
  instances.
- Event loop: synchronous crypto, `fs.*Sync` or heavy regex in request paths block every request.

## Dependencies
- Node.js past end of life, Express 4 below 4.20.0, `jsonwebtoken` below 9, `axios` below 1.6 (CSRF token leak),
  vulnerable `lodash`, `minimist`, `qs`, `xml2js`, `node-serialize`. `npm ci` in CI, committed lock files,
  `ignore-scripts` for untrusted packages, scoped registries for internal packages.

## Web protocol and identity
- Forwarded headers: Express `app.set('trust proxy', true)` trusts every hop, so `req.ip`, `req.hostname` and
  `req.protocol` become client-controlled; use the proxy count or addresses. Fastify `trustProxy`, Koa
  `app.proxy`, NestJS `app.set('trust proxy', ...)` work the same way. Flag `req.headers.host` or `req.hostname`
  in reset, email or OAuth callback links.
- Request framing: flag `http.createServer({ insecureHTTPParser: true })`, `--insecure-http-parser`, and custom
  proxies built on `http-proxy`/`http-proxy-middleware` that forward `Transfer-Encoding` or hop-by-hop headers.
- SAML: `@node-saml/node-saml` and `@node-saml/passport-saml` (legacy `passport-saml`). Flag `wantAssertionsSigned:
  false` together with `wantAuthnResponseSigned: false`, a missing `audience`, `validateInResponseTo: 'never'`, and
  outdated `xml-crypto` or `xmldom` versions.
- WebAuthn: `@simplewebauthn/server` `verifyRegistrationResponse`/`verifyAuthenticationResponse` must get
  `expectedChallenge` from the server session, a fixed `expectedOrigin` and `expectedRPID`, and
  `requireUserVerification` where the policy needs it.

## Logging and errors
- `console.log`/logger calls with `req.body`, `req.headers` or tokens; `morgan` with bodies; pino or winston
  without `redact` paths for authorization headers and secrets.
- NestJS exception filters and Express error handlers must return fixed codes, not `err.message` or `err.stack`.
- Unhandled promise rejections and missing `await` on security checks (a pending promise is truthy).
