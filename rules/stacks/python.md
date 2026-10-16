---
detect:
  - "pyproject.toml, requirements*.txt, Pipfile or setup.py with django, djangorestframework, fastapi, flask, starlette, aiohttp or litestar"
---

# Stack: Python back ends (Django, Django REST Framework, FastAPI, Flask, Starlette)

Use with the category files.

## Entry points
- Django `urls.py` and views (function views, class-based views, DRF `ViewSet`s and routers), middleware in
  `settings.MIDDLEWARE`, signals, management commands, Celery tasks. FastAPI and Starlette routers, `Depends`
  dependencies, middleware. Flask blueprints, `before_request` hooks.

## Access control and authentication
- DRF: `permission_classes` on every view (and `DEFAULT_PERMISSION_CLASSES` not `AllowAny`),
  `get_queryset` filtered by `request.user`, `get_object` with object permissions. Django: `@login_required`,
  `@permission_required`, `LoginRequiredMixin`; `@csrf_exempt` on cookie-authenticated views.
- FastAPI: security dependencies on every router (`Depends(get_current_user)`), not only some routes. Flask:
  decorators applied in the right order (`@app.route` outermost).
- Mass assignment: DRF serializers with `fields = '__all__'` or writable sensitive fields without `read_only`;
  `Model(**request.data)`, `setattr` loops over request keys; Pydantic models used both for input and ORM writes.
- PyJWT: `jwt.decode(..., options={"verify_signature": False})`, missing `algorithms=[...]`, `audience`,
  `issuer`. `python-jose` with `alg` from the header.

## Validation and injection
- SQL: f-strings or `%` formatting in `cursor.execute`, Django `raw()`, `extra()`, `RawSQL`, SQLAlchemy `text()`
  with interpolation; `order_by` from input without an allow-list.
- Commands and code: `os.system`, `subprocess` with `shell=True`, `eval`, `exec`, `pickle.loads`, `yaml.load`
  without `SafeLoader`, `marshal`, `shelve` on untrusted data.
- Templates: Jinja2 with `autoescape=False`, `Markup()`/`|safe`/`mark_safe` on user data,
  `render_template_string` with user input (SSTI).
- XML: `xml.etree`/`lxml` on untrusted input without `defusedxml`.
- Paths: `send_file`/`open` with input without `safe_join` or a base-directory check.
- Validation: DRF serializers, Pydantic models with constrained types, Flask forms; reject extra fields
  (`model_config = ConfigDict(extra="forbid")`).

## Cryptography and transport
- `random` for tokens (use `secrets`), `hashlib.md5/sha1` for passwords (use Django hashers, argon2-cffi or
  bcrypt), `hmac.compare_digest` for comparisons, `cryptography` AEAD rather than PyCrypto.
- `requests`/`httpx` with `verify=False`, no `timeout` (requests waits forever by default).
- Money in `decimal.Decimal`, not `float`.

## Configuration and tooling
- Django: `DEBUG = True`, `ALLOWED_HOSTS = ['*']`, `SECRET_KEY` committed, `SESSION_COOKIE_SECURE`,
  `CSRF_COOKIE_SECURE`, `SECURE_HSTS_SECONDS`, `SECURE_PROXY_SSL_HEADER` without a proxy that sets it,
  `django-cors-headers` with `CORS_ALLOW_ALL_ORIGINS` and credentials, admin at `/admin/` without extra
  protection, Django Debug Toolbar in production.
- FastAPI: `/docs`, `/redoc`, `/openapi.json` enabled in production; `CORSMiddleware` with `allow_origins=["*"]`
  and `allow_credentials=True`. Flask: `app.run(debug=True)`, Werkzeug debugger (remote code execution),
  `SECRET_KEY` committed.

## Dependencies
- Python past end of life, Django and Flask lines past support, `PyYAML` below 5.4, `Jinja2` below 3.1.6,
  `urllib3`/`requests` advisories, unpinned requirements without hashes (`--require-hashes`).

## Web protocol and identity
- Forwarded headers: Django `USE_X_FORWARDED_HOST`, `SECURE_PROXY_SSL_HEADER` and `ALLOWED_HOSTS = ['*']`;
  Werkzeug/Flask `ProxyFix(x_for=..., x_host=...)` counts higher than the real number of proxies; Starlette and
  Uvicorn `--forwarded-allow-ips='*'`. Flag `request.get_host()`/`request.host_url` in reset or email links when
  the host isn't allow-listed.
- SAML: `python3-saml` (OneLogin) needs `strict: True` and `security.wantAssertionsSigned`; `pysaml2` needs
  `want_assertions_signed` or `want_response_signed`. Parse XML with `defusedxml` or `lxml` with
  `resolve_entities=False`.
- WebAuthn: `webauthn` (py_webauthn) `verify_registration_response`/`verify_authentication_response` with
  `expected_challenge` from the server session, fixed `expected_origin` and `expected_rp_id`, and
  `require_user_verification` where the policy needs it.

## Logging and errors
- `logging` of `request.data`, `request.headers`, tokens; Sentry `send_default_pii=True`; Django `DEBUG` error
  pages; FastAPI exception handlers returning `str(exc)`.
