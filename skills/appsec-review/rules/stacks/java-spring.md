---
detect:
  - "pom.xml or build.gradle* with org.springframework or spring-boot dependencies"
  - "Java or Kotlin sources under src/main"
---

# Stack: Java and Kotlin with Spring (Boot, MVC, WebFlux, Security, Data)

Use with the category files. For other JVM frameworks (Quarkus, Micronaut, Jakarta EE), map the same ideas to
their annotations.

## Entry points
- `@RestController`/`@Controller` classes (and project meta-annotations that bundle them), `@RequestMapping` and
  the verb mappings, functional `RouterFunction` beans, `@KafkaListener`/`@JmsListener`/`@RabbitListener`,
  `@Scheduled` jobs, servlet `Filter`s, `HandlerInterceptor`s, `@ControllerAdvice`.
- Follow each request through `SecurityFilterChain`/`WebSecurityConfigurerAdapter`, filters and interceptors
  (including `excludePathPatterns`) before reading the controller.

## Access control
- Method rules: `@PreAuthorize`, `@PostAuthorize`, `@Secured`, `@RolesAllowed` (method security must be enabled);
  URL rules in `authorizeHttpRequests`/`authorizeRequests`. Flag `permitAll()` and `web.ignoring()` on new paths.
- Identity from `@AuthenticationPrincipal`, `SecurityContextHolder` or verified JWT claims, not from
  `@RequestBody` fields, `@RequestParam`, `@PathVariable` or headers (e.g. `request.getCustomerNumber()`).
- Mass assignment: entities bound directly from `@RequestBody` or `@ModelAttribute`, and
  `BeanUtils.copyProperties`, `ModelMapper` or `ObjectMapper.convertValue` from request objects into entities.
- Spring Data REST exposes repositories as endpoints by default; flag it unless every repository is restricted.
- `ThreadLocal` tenant, security or MDC state must be cleared in `finally`. Flag `@Async`, `CompletableFuture`
  and executors that lose or leak it (no `TaskDecorator` or context propagation).
- Path matching: flag `getRequestURI().contains`/`startsWith` and regex on the raw URI; use the servlet path and
  Spring's `PathPatternParser`.

## Authentication and tokens
- jjwt: `parseClaimsJwt`/`parseUnsecuredClaims` accept unsigned tokens; use `parseClaimsJws`/`parseSignedClaims`
  with a fixed key. Nimbus/Spring Security resource server: check `JwtDecoder` validators include issuer and
  audience.
- Keycloak adapters: check per-realm config resolvers, bearer-only settings and introspection fallbacks.
- Compare expiry with `Instant` or epoch values, not `%` or `Math.abs` on differences.

## Validation and injection
- Validation: `@Valid`/`@Validated` on parameters and the class for `@RequestParam`/`@PathVariable` constraints,
  with `@NotNull`, `@Size`, `@Pattern`, `@Min`/`@Max`, enums. Annotations on a DTO do nothing without `@Valid`.
- SQL: string concatenation or `String.format` into `createQuery`, `createNativeQuery`, `@Query`, JDBC
  `Statement`, `JdbcTemplate` SQL strings, Criteria `ORDER BY` from input. `LIKE`: `cb.like`,
  `findBy...Containing`/`StartingWith` with unescaped `%` and `_`.
- Commands: `Runtime.exec`, `ProcessBuilder`. Expressions: `SpelExpressionParser`, `@Value` built from input,
  Thymeleaf or Freemarker templates from input.
- XML: `DocumentBuilderFactory`, `SAXParserFactory`, `XMLInputFactory`, `TransformerFactory`, `SchemaFactory`,
  JAXB `Unmarshaller` without disabling DTDs and external entities.
- Deserialization: `ObjectInputStream`, Jackson `enableDefaultTyping`/`activateDefaultTyping` or
  `@JsonTypeInfo(use = CLASS)`, XStream without an allow-list, SnakeYAML `new Yaml()` on untrusted input.
- Data binding: on Spring versions affected by Spring4Shell, `@InitBinder`/`DataBinder` without
  `setDisallowedFields` for `class.*`, `Class.*`, `*.class.*`.

## Cryptography, secrets and transport
- Secrets: constant classes (`*Constant*`, `*Constants*`), `application*.properties`/`.yml` defaults
  (`${ENV:literal}`), and demo harnesses under `src/main` (`*Main.java`, `Test*`, sample clients).
- `Cipher.getInstance("AES")` defaults to ECB. Flag `new IvParameterSpec(CONSTANT)`, `java.util.Random` or
  `Math.random` for security values; use `SecureRandom` and `MessageDigest.isEqual`.
- TLS: `TrustAllStrategy`, `TrustSelfSignedStrategy`, `(chain, type) -> true`, `NoopHostnameVerifier`,
  `ALLOW_ALL_HOSTNAME_VERIFIER`, a `HostnameVerifier` returning true, an `X509TrustManager` with empty checks,
  `SSLContext.init` with null or trust-all managers, and Netty `InsecureTrustManagerFactory`. Check
  `RestTemplate`, `WebClient`, Feign, Apache and OkHttp client beans, and which profile picks which bean.
- Lombok `@Data`/`@ToString` on DTOs with sensitive fields need `@ToString.Exclude` or a redacting `toString`.
- Money in `BigDecimal` with explicit scale and `RoundingMode`.

## Configuration and tooling
- springdoc/springfox: `/swagger-ui/**`, `/v3/api-docs/**`, `/v2/api-docs`, `/swagger-resources/**` in unsecured
  lists; `springdoc.api-docs.enabled`, `springdoc.swagger-ui.enabled`, `springfox.documentation.enabled` not
  `false` outside dev profiles.
- Actuator: `management.endpoints.web.exposure.include=*`, exposed `env`, `heapdump`, `threaddump`, `loggers`,
  `refresh`, `shutdown`, `trace`, `mappings`, `health` with `show-details: always`; custom `@Endpoint` or
  `@WriteOperation` beans that change security behaviour.
- `spring-boot-devtools` not `optional` or packaged in the WAR/JAR; `spring.devtools.*` outside dev.
- `server.error.include-stacktrace`, `include-message`, `include-exception`; `spring.jpa.show-sql`; DEBUG logging
  of web or HTTP client packages in production profiles.
- Profiles: check which profile production really runs (`spring.profiles.active`, deployment descriptors) before
  trusting profile-guarded controls (`@Profile`, `Environment.acceptsProfiles`).
- `server.forward-headers-strategy` and trusted proxies before using `X-Forwarded-For`.
- CORS: `@CrossOrigin` without origins, `allowedOrigins("*")` or `allowedOriginPatterns("*")` with credentials.
  CSRF: `csrf().disable()` / `csrf(AbstractHttpConfigurer::disable)` with cookie sessions.
- HTTP clients (`RestTemplate`, `WebClient`, Feign, Apache, OkHttp) need connect and read timeouts. Flag blocking
  I/O on the common fork-join pool or in WebFlux handlers.

## Dependencies
- Spring Boot 2.x below 2.6.6 or Spring Framework below 5.3.18 (Spring4Shell on WAR deployments), any Spring Boot
  line past its support end, Log4j 2 below 2.17.1, Jackson databind with gadget CVEs, SnakeYAML below 2.0,
  commons-text below 1.10, commons-collections 3.x below 3.2.2, third-party `SNAPSHOT` versions.

## Web protocol and identity
- Forwarded headers: `server.forward-headers-strategy` (`native` or `framework`) or `ForwardedHeaderFilter` makes
  `X-Forwarded-*` change the host, scheme and client address. Flag it without Tomcat's `RemoteIpValve`
  `internal-proxies` (`server.tomcat.remoteip.internal-proxies`) limited to the real proxies, and links built with
  `ServletUriComponentsBuilder.fromCurrentRequest()` for reset or email links.
- SAML: Spring Security `saml2Login()` with `OpenSaml4AuthenticationProvider`/`OpenSaml5AuthenticationProvider`.
  Flag custom response validators that skip the default signature, audience or `InResponseTo` checks, and
  relying-party registrations that load verification certificates from the assertion.
- WebAuthn: Spring Security `webAuthn()`, WebAuthn4J `WebAuthnManager`, or Yubico `RelyingParty`. Check the
  expected origins, RP ID, user verification and the challenge store per session.
- Caching: `@Cacheable` keys on per-user data that omit the principal or tenant; `CacheControl.maxAge(...)`
  without `cachePrivate()` on authenticated responses.

## Logging and errors
- Request/response logging aspects, `CommonsRequestLoggingFilter` with payloads, and Feign `Logger.Level.FULL`.
- `HttpClientErrorException`/`WebClientResponseException` messages carry the downstream body.
- `catch (Exception)`/`catch (Throwable)` that hides security failures; MDC and `ThreadLocal` cleared in
  `finally`; streams in try-with-resources.
- `@ControllerAdvice` must map exceptions to fixed codes, including those thrown in filters (which bypass it).
- Endpoint documentation: springdoc `@Operation` with auth, roles and error codes.
