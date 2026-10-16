---
paths:
  - "**/*.{java,kt,scala,groovy,ts,tsx,js,jsx,mjs,cjs,vue,svelte,py,go,cs,rb,php,rs,dart,swift}"
  - "**/*.{html,sql,graphql,gql}"
---

# Injection, input validation and unsafe parsing

OWASP A05:2025, API8/API10:2023, ASVS V1/V2/V5, WSTG-INPV, PCI DSS 6.2.4. CWE-89, CWE-943, CWE-78, CWE-90, CWE-643,
CWE-917, CWE-94, CWE-1336, CWE-1321, CWE-611, CWE-502, CWE-22, CWE-434, CWE-117, CWE-113, CWE-79, CWE-20, CWE-155.

The stack file for the repository (`rules/stacks/`) names the framework's validation, query and parsing APIs.
Client-side XSS and DOM sinks are in `client-side.md`.

## Input validation
- Validate every path, query, header and body field at the boundary: type, length, format, range and allow-listed
  values, with the framework's validation (annotations, decorators and pipes, schemas, form or model validators).
  Flag new request fields with no validation, and validation that is declared but not switched on for the route.
  (CWE-20)
- Validate on the server even when the client validates. Reject unknown enum values and negative or zero amounts,
  and don't silently coerce bad input. Reject unknown properties where the framework allows it.
- Ids the client picks from a list (product, package, plan, fee or limit) must be checked against the server-side
  list available to that user, so hidden or disabled options can't be selected.

## Injection sinks
- SQL and ORM query languages: flag string concatenation, interpolation or formatting into raw queries, native
  queries, query-builder raw fragments, `ORDER BY` and column or table names. Use bind parameters, or allow-lists
  for identifiers. (CWE-89)
- NoSQL: flag request objects passed straight into query filters, so operators such as `$ne`, `$gt`, `$regex` or
  `$where` from JSON reach the database; cast to the expected scalar type first. (CWE-943)
- `LIKE` and pattern search: flag user input put into `LIKE`, contains or regex patterns without escaping the
  wildcard and escape characters, or without a minimum length. These allow data extraction by pattern probing and
  full-table scans. (CWE-155)
- OS commands: flag request data reaching a shell or process call (`Runtime.exec`, `child_process.exec`,
  `subprocess` with `shell=True`, `os/exec` running `sh -c`, `Process.Start`). Pass arguments as a list with no
  shell. (CWE-78)
- Code and expressions: flag request data in `eval`, `new Function`, string `setTimeout`, `vm` modules, expression
  languages (SpEL, OGNL, MVEL), dynamic imports or requires, and reflection that picks a class or method by name.
  (CWE-94, CWE-917)
- LDAP, XPath and templates: flag request data in LDAP filters, XPath expressions, or used as a template rather than
  as template data (server-side template injection). (CWE-90, CWE-643, CWE-1336)
- HTTP headers: flag CR/LF or request data in response headers, `Location` or cookies. Incoming header values such
  as trace or request ids must be checked against a strict format (e.g. `^[A-Za-z0-9-]{1,64}$`) before going into
  logging context, logs or response headers. (CWE-113, CWE-117)
- Server-rendered XSS: flag HTML or JS built by string concatenation from request or downstream data, templates
  with auto-escaping switched off or bypassed, and JSON served as `text/html`. (CWE-79)

## Unsafe parsing and deserialization
- XML parsers must disable DTDs and external entities. (CWE-611)
- Flag native or polymorphic deserialization of untrusted data: Java `ObjectInputStream`, Jackson default typing,
  XStream without an allow-list, Python `pickle`, `yaml.load` without a safe loader, PHP `unserialize`, .NET
  `BinaryFormatter` or `TypeNameHandling` other than `None`, and Node packages that revive functions. (A08:2025,
  CWE-502)
- JavaScript prototype pollution: flag deep merge, `set`-by-path or clone helpers applied to request JSON without
  blocking `__proto__`, `constructor` and `prototype` keys. (CWE-1321)
- Treat third-party and downstream responses as untrusted: validate schema, sizes and values before use, and don't
  follow redirects or URLs they return without an allow-list. (API10)

## GraphQL
- Flag schemas without query depth, complexity or alias limits, batching without limits, and resolvers that skip
  the object-level checks in `access-control.md`. Introspection belongs to `configuration-supply-chain.md`.

## Files and paths
- Flag request data in file paths, names or archive entries without normalising the path and checking it stays
  under an allowed base directory. (CWE-22)
- Uploads: allow-listed types checked by content, not by name or extension; size limits; storage outside the web
  root under generated names. (CWE-434)

## Logs
- Flag request data written to logs without neutralising CR/LF (log forging), and user data used as a log format
  pattern. (CWE-117)
