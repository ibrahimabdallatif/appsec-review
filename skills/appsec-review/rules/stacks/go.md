---
detect:
  - "go.mod (net/http, gin-gonic/gin, labstack/echo, gofiber/fiber, go-chi/chi, gorilla/mux, grpc)"
---

# Stack: Go services (net/http, Gin, Echo, Fiber, chi, gRPC)

Use with the category files.

## Entry points
- `http.HandleFunc`/`mux.Handle`, router groups (`r.Group`, `e.Group`, `app.Group`) and their middleware, gRPC
  service implementations and interceptors, message consumers, `cmd/` mains. Check that auth middleware is attached
  to the group, not only to some routes.

## Access control and authentication
- Identity from the verified context value set by auth middleware, not from body, query or headers. Typed context
  keys, not strings.
- `golang-jwt/jwt`: a key function that doesn't check `token.Method`, `ParseUnverified` used for authorization,
  missing `WithAudience`/`WithIssuer`/`WithExpirationRequired` (v5) parser options.
- Mass assignment: binding request JSON straight into GORM models (`c.Bind(&user)` then `db.Save`), `Updates` with
  a `map` from the request.

## Validation and injection
- Validation with `go-playground/validator` tags or explicit checks; `json.Decoder.DisallowUnknownFields` where
  extra fields matter; `http.MaxBytesReader` for body limits.
- SQL: `fmt.Sprintf` into `db.Query`/`Exec`, GORM `Raw`/`Exec`/`Where` with string interpolation, `Order` from
  input.
- Commands: `exec.Command("sh", "-c", input)`. Templates: `text/template` for HTML (no escaping; use
  `html/template`), `template.HTML(userData)`.
- Paths: `filepath.Join` with input without checking the result stays under the base (use `os.Root` or
  `filepath.IsLocal`); `http.FileServer` on broad folders; archive extraction (zip slip).
- XML: `encoding/xml` is safe from XXE, but check third-party parsers.

## Cryptography and transport
- `math/rand` for tokens (use `crypto/rand`), `crypto/md5`/`sha1` for passwords (use `bcrypt`, `argon2`,
  `scrypt`), `subtle.ConstantTimeCompare` for secrets.
- `tls.Config{InsecureSkipVerify: true}`, `MinVersion` below TLS 1.2.
- `http.Client` without `Timeout` (default is none), `http.Server` without `ReadHeaderTimeout`/`ReadTimeout`
  (Slowloris).

## Concurrency
- Data races on shared maps and counters (run `go test -race`), goroutines started per request without limits,
  missing `context` cancellation on downstream calls.

## Configuration and tooling
- `net/http/pprof` imported in production binaries (it registers `/debug/pprof` on the default mux), `expvar`,
  Gin in debug mode, CORS middleware with `AllowAllOrigins` plus credentials, `X-Forwarded-For` trusted via
  `c.ClientIP()` without `SetTrustedProxies`.

## Dependencies
- Go versions past support, `govulncheck ./...` results (it reports only reachable vulnerable symbols),
  `replace` directives pointing to forks or local paths.

## Web protocol and identity
- Forwarded headers: chi `middleware.RealIP` trusts `X-Forwarded-For`/`X-Real-IP` from anyone; Gin
  `SetTrustedProxies(nil)` vs the default trust-all, and `TrustedPlatform`; Echo `IPExtractor`. Flag `r.Host` in
  reset or email links.
- Reverse proxies: `httputil.ReverseProxy` with `Director` keeps client-sent `X-Forwarded-*` headers; `Rewrite`
  with `SetXForwarded()` replaces them. Flag identity headers forwarded without stripping the client's copy.
- SAML: `crewjam/saml` `ServiceProvider`. Flag old versions with known signature-validation CVEs and
  `AllowIDPInitiated` without a replay check.
- WebAuthn: `go-webauthn/webauthn` `FinishRegistration`/`FinishLogin` with `SessionData` stored server-side and
  `RPOrigins` fixed in config.

## Logging and errors
- `log.Printf("%+v", req)` dumping structs with secrets, error strings returned to clients (`err.Error()` in
  responses), ignored `err` values on security checks.
