---
detect:
  - "*.csproj or *.sln with Microsoft.AspNetCore.* or Microsoft.NET.Sdk.Web"
---

# Stack: .NET (ASP.NET Core MVC, Web API, minimal APIs, Blazor)

Use with the category files. Blazor WebAssembly code runs in the browser: also apply `client-side.md`.

## Entry points
- Controllers (`[ApiController]`, `ControllerBase`), minimal API `app.MapGet`/`MapPost`/`MapGroup`, Razor Pages,
  SignalR hubs, gRPC services, hosted services. Middleware order in `Program.cs` (`UseAuthentication` before
  `UseAuthorization`, both before endpoints).

## Access control and authentication
- `[Authorize]` with policies or roles on controllers and endpoints, `RequireAuthorization()` on minimal API
  groups, a fallback policy that requires authentication. Flag `[AllowAnonymous]` on new actions.
- Resource-based authorization (`IAuthorizationService.AuthorizeAsync(user, resource, policy)`) for object
  ownership; identity from `User.FindFirst(...)`, not from the body.
- Mass assignment: binding EF Core entities directly, `[Bind]` missing, `TryUpdateModelAsync` without a field list.
- JWT bearer: `TokenValidationParameters` with `ValidateIssuer`, `ValidateAudience`, `ValidateLifetime`,
  `ValidateIssuerSigningKey` all true; no `SignatureValidator` that skips checks; `RequireHttpsMetadata` true.
- Cookie auth: `Cookie.SecurePolicy = Always`, `HttpOnly`, `SameSite`; antiforgery (`[ValidateAntiForgeryToken]`
  or `AutoValidateAntiforgeryToken`) on cookie-authenticated form posts.

## Validation and injection
- Data annotations or FluentValidation on request models; `[ApiController]` automatic 400 responses not turned off.
- SQL: `FromSqlRaw`/`ExecuteSqlRaw` with interpolation or concatenation (use `FromSqlInterpolated` or
  parameters), `SqlCommand` text built from input, Dapper queries built with string concatenation.
- Deserialization: `BinaryFormatter`, `NetDataContractSerializer`, `LosFormatter`, Json.NET `TypeNameHandling`
  other than `None`, `XmlSerializer` with types from input.
- XML: `XmlDocument`/`XmlReader` with `DtdProcessing.Parse` or an `XmlResolver` set.
- Commands: `Process.Start` with input and `UseShellExecute`. Razor: `Html.Raw` on user data.
- Paths: `Path.Combine` with input (an absolute second argument replaces the base), `PhysicalFile` without a
  base-directory check.

## Cryptography and transport
- `System.Random` for tokens (use `RandomNumberGenerator`), `MD5`/`SHA1` for passwords (use ASP.NET Core
  Identity `PasswordHasher` or PBKDF2 via `Rfc2898DeriveBytes.Pbkdf2` with enough iterations), and
  `CryptographicOperations.FixedTimeEquals` for comparisons.
- `HttpClientHandler.ServerCertificateCustomValidationCallback` returning true,
  `DangerousAcceptAnyServerCertificateValidator`, `ServicePointManager.ServerCertificateValidationCallback`.
- `HttpClient` from `IHttpClientFactory` with a `Timeout` and resilience policies; money in `decimal`.

## Configuration and tooling
- Secrets in `appsettings*.json` (use user secrets, environment variables or Key Vault), `UseDeveloperExceptionPage`
  outside Development, Swagger (`UseSwagger`, `UseSwaggerUI`) outside Development, `UseHsts` and
  `UseHttpsRedirection` present, CORS policies with `AllowAnyOrigin` plus credentials or
  `SetIsOriginAllowed(_ => true)`, `ForwardedHeaders` without `KnownProxies`, request size limits, rate limiting
  middleware.
- Environment checks (`IsDevelopment`, `IsProduction`, custom names) that gate security controls must match the
  environment names deployments really use.

## Dependencies
- .NET versions past support, `Newtonsoft.Json` below 13.0.1, vulnerable `System.Text.Encodings.Web`, NuGet
  packages without central version pinning or lock files (`RestorePackagesWithLockFile`).

## Web protocol and identity
- Forwarded headers: `UseForwardedHeaders` with `ForwardedHeadersOptions.KnownProxies`/`KnownNetworks` limited to
  the real proxies. Flag clearing them (`KnownNetworks.Clear()`, `KnownProxies.Clear()`) and `AllowedHosts: "*"`
  where host-based links are built from `Request.Host`.
- SAML: Sustainsys.Saml2 or ITfoxtec.Identity.Saml2. Flag disabled signature validation, missing audience or
  certificate validation (`CertificateValidationMode.None`), and unsigned-assertion settings.
- WebAuthn: Fido2NetLib (`IFido2.MakeNewCredentialAsync`, `MakeAssertionAsync`) with `Origins` fixed in config,
  the challenge options stored server-side per session, and `UserVerificationRequirement` set by policy.
- Output caching and response caching (`[ResponseCache]`, `OutputCache`) on authenticated endpoints must vary by
  user or be disabled.

## Logging and errors
- `ILogger` calls with request bodies, tokens or `Authorization` headers; HTTP logging middleware with
  `RequestBody`/`ResponseBody` fields; `ProblemDetails` exposing exception messages.
