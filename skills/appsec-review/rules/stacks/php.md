---
detect:
  - "composer.json with laravel/framework, symfony/framework-bundle, symfony/http-kernel, slim/slim, codeigniter4/framework, cakephp/cakephp, laminas/laminas-mvc or livewire/livewire"
  - "wp-config.php, or a PHP file with a 'Plugin Name:' or 'Theme Name:' header (WordPress)"
---

# Stack: PHP back ends (Laravel, Symfony, WordPress, Slim, CodeIgniter, CakePHP, Laminas)

Use with the category files.

## Entry points
- Laravel `routes/web.php`, `routes/api.php`, `routes/channels.php` and `routes/console.php`, controllers, route
  groups and their middleware, Livewire components (every public property and public method is callable from the
  browser), Filament resources and actions, queued jobs, listeners, scheduled commands, broadcast channels.
- Symfony `#[Route]` attributes and `config/routes/*.yaml`, controllers, event subscribers on `kernel.request`,
  Messenger handlers (`#[AsMessageHandler]`), console commands, API Platform resources and operations.
- WordPress `add_action('wp_ajax_*')` and `wp_ajax_nopriv_*` (callable without login), `admin_post_*`,
  `register_rest_route`, shortcodes, `init`/`template_redirect` hooks reading request input, XML-RPC.
- Slim, CodeIgniter 4 (`app/Config/Routes.php`, auto-routing), CakePHP and Laminas routes, and plain `.php`
  files under the web root that read `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_FILES` or `php://input`.

## Access control and authentication
- Laravel: `auth` or `auth:sanctum` middleware on every protected group, not only some routes; policies and
  `Gate::authorize`/`$this->authorize` before reading or changing a record; route model binding (`{card}`) does not
  check ownership, scope the query by the user or use `->can('view', 'card')`. Livewire: `#[Locked]` on IDs and
  other properties the client must not change, authorization inside each public action, not only in `mount`.
- Mass assignment: `$guarded = []` or `Model::unguard()`, `fill($request->all())`, `create($request->all())`,
  `update($request->input())`; use `$request->validated()` or `only([...])` with an explicit `$fillable`.
  Symfony forms with `allow_extra_fields`, API Platform resources without serialization groups on writes.
- Symfony: `access_control` in `security.yaml` matched in order (a broad early rule wins), `#[IsGranted]` and
  voters on each controller, firewalls with `security: false`, `PUBLIC_ACCESS` on sensitive paths.
- WordPress: every `wp_ajax_*`, `admin_post_*` and REST handler checks `current_user_can()` for the action, and a
  nonce (`check_ajax_referer`, `wp_verify_nonce`) for CSRF; `is_admin()` only says the request targets an admin
  page, it is not an authorization check; `register_rest_route` without `permission_callback`, or with
  `__return_true` on a write.
- JWT (`firebase/php-jwt`, `lcobucci/jwt`, `tymon/jwt-auth`): `JWT::decode` with a fixed `Key` and algorithm,
  `lcobucci` with `SignedWith` and `StrictValidAt` constraints, not `Parser::parse` alone.
- Loose comparison: `==` or `in_array`/`array_search` without `true` on tokens, hashes, roles or IDs
  (`"0e123" == "0e456"`, `0 == "abc"` before PHP 8), `strcmp` on arrays returning `null`; use `hash_equals` and
  `===`. `switch` uses loose comparison too.

## Validation and injection
- SQL: Laravel `DB::raw`, `DB::select`/`statement` with interpolation, `whereRaw`, `selectRaw`, `orderByRaw`,
  `havingRaw`, `orderBy($request->input('sort'))` without an allow-list (column names are not bound). Doctrine
  `createQuery`/`executeQuery` with concatenated DQL or SQL. WordPress `$wpdb->query/get_results/get_var` without
  `$wpdb->prepare`, and `prepare` with input in the query string itself. PDO/mysqli `query` with concatenation.
- Commands and code: `exec`, `shell_exec`, `system`, `passthru`, `proc_open`, `popen`, backticks, `mail()` with a
  user-controlled fifth argument; `eval`, `assert` with a string, `create_function`, `preg_replace` with `/e`,
  `call_user_func`/`$fn()` or `new $class` with names from input. `escapeshellarg` per argument, never
  `escapeshellcmd` on a whole command.
- Deserialization: `unserialize` on cookies, request data, cache or queue payloads (use `json_decode`, or
  `allowed_classes => false`); `phar://` paths reaching `file_exists`, `is_file`, `getimagesize` or `fopen` trigger
  phar deserialization on PHP below 8.0. Laravel with a leaked `APP_KEY` makes encrypted cookies, signed
  payloads and Livewire snapshots an RCE path (CVE-2018-15133, CVE-2025-54068 in Livewire 3 below 3.6.4).
- File inclusion and paths: `include`/`require` with input (LFI, `php://filter`, `data://`), `file_get_contents`,
  `fopen`, `readfile`, `Storage::get`/`download` with request paths; `basename` or a `realpath` prefix check.
- Uploads: `move_uploaded_file` or `$file->move()`/`store()` keeping the client name or extension into the web
  root (a `.php`, `.phtml` or `.phar` file runs); validate with `mimes:` and store outside `public/`.
- Templates: Blade `{!! !!}`, Twig `|raw` and `autoescape false`, `Twig\Environment::createTemplate` or
  `Blade::render` with user input (SSTI), WordPress output without `esc_html`, `esc_attr`, `esc_url` or
  `wp_kses`. `htmlspecialchars` without `ENT_QUOTES` in attributes on PHP below 8.1.
- XML: `simplexml_load_string`, `DOMDocument::loadXML` with `LIBXML_NOENT` or `LIBXML_DTDLOAD` (XXE).
- Other: `extract($_POST)`, `parse_str` without a result array and `$$name` overwrite variables; `header()` with
  input; `filter_var(FILTER_VALIDATE_URL)` accepts `javascript:` and any host, so it is not an SSRF or redirect
  check; `redirect()->to($request->input('next'))` and `wp_redirect` instead of `wp_safe_redirect`.
- Validation: Laravel Form Requests or `$request->validate()`, Symfony Validator constraints on DTOs; reject
  unknown fields.

## Cryptography and transport
- `rand`, `mt_rand`, `uniqid`, `lcg_value`, `str_shuffle` for tokens (use `random_bytes`, `random_int`,
  `Str::random`); `md5`/`sha1`/`crypt` for passwords (use `password_hash` and `password_verify`, Laravel `Hash`,
  Symfony password hashers); `openssl_encrypt` with ECB or a fixed IV, `mcrypt`.
- cURL `CURLOPT_SSL_VERIFYPEER => false` or `CURLOPT_SSL_VERIFYHOST => 0`, Guzzle and Laravel `Http`
  `verify => false` or `withoutVerifying()`, no timeout; `allow_url_fopen` and `file_get_contents($url)` used as
  an HTTP client with input URLs (SSRF, also `gopher://` and `file://` through cURL without
  `CURLOPT_PROTOCOLS`).
- Money in integers or `brick/money`/`bcmath`, not floats.

## Configuration and tooling
- Laravel: `APP_DEBUG=true` in production (Ignition error pages leak env and, on old versions, give RCE),
  `APP_KEY` committed or shared between environments, `.env` reachable over HTTP, Telescope, Horizon, Debugbar,
  Pulse or `/_ignition` exposed without a gate, `config/cors.php` with `allowed_origins => ['*']` and
  `supports_credentials => true`, `TrustProxies` with `$proxies = '*'`, session cookie `secure` and `same_site`.
- Symfony: `APP_ENV=dev` or `APP_DEBUG=1` in production, the profiler and `/_profiler`/`_fragment` routes
  enabled, `APP_SECRET` committed (it signs `_fragment` URLs and remember-me cookies), `framework.trusted_proxies`
  and `trusted_hosts` unset behind a proxy.
- WordPress: `WP_DEBUG_DISPLAY`, `DISALLOW_FILE_EDIT` unset, `wp-config.php` salts committed, `xmlrpc.php` open,
  user enumeration through `/wp-json/wp/v2/users` and `?author=`.
- PHP: `display_errors=On`, `expose_php`, `allow_url_include`, `phpinfo()` pages, `session.cookie_secure`,
  `session.cookie_httponly`, `session.use_strict_mode`; Composer `vendor/` or `composer.json` served from the
  web root.

## Dependencies
- PHP past support (8.1 and older ended 31 December 2025, 8.2 ends 31 December 2026), Laravel majors past
  security support (11 and older), Symfony branches past maintenance (8.0, 7.3 and older; 7.4 is the LTS),
  WordPress core, plugins and themes behind their latest release, `composer audit` results, `composer.lock` not
  committed for applications, plugins pulled from outside Packagist or wordpress.org.

## Web protocol and identity
- Forwarded headers: Laravel `TrustProxies`/`trustProxies(at: '*')` and `TrustHosts`, Symfony `trusted_proxies`
  and `trusted_hosts`; `$request->getHost()`, `url()` or `$_SERVER['HTTP_HOST']` in reset or email links when the
  host is not allow-listed (password reset poisoning).
- SAML: `onelogin/php-saml` needs `strict => true` and `wantAssertionsSigned`; `simplesamlphp` with signed
  assertions required. WebAuthn: `web-auth/webauthn-lib` or `lbuchs/WebAuthn` with the challenge from the server
  session and a fixed origin and RP ID.

## Logging and errors
- `Log::info($request->all())`, logging of `Authorization` headers, passwords or card data; `dd()`, `dump()`,
  `var_dump`, `print_r` left in code; exception handlers returning `$e->getMessage()` or traces; Sentry
  `send_default_pii`.
