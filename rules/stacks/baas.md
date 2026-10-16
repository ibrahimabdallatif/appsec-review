---
detect:
  - "package.json with @supabase/supabase-js, @supabase/ssr, firebase, firebase-admin or firebase-functions"
  - "supabase/ folder (config.toml, migrations, functions), or SQL using auth.uid(), auth.jwt() or row level security"
  - "firebase.json, firestore.rules, storage.rules or database.rules.json"
  - "pubspec.yaml with supabase_flutter, cloud_firestore or another firebase_ package"
---

# Stack: backend-as-a-service (Supabase, Firebase)

Use with the category files and the stack file of the client (`web-frontend.md`, `mobile.md`) or server
(`node-backend.md`) that calls the service.

The client talks to the database directly. The Supabase anon (publishable) key and the Firebase web `apiKey` are
public by design, so anyone can call the API the app calls, with any query. Authorization lives in RLS policies
and security rules, not in the app code: a check done only in the app is no check. Review the policies and rules
as the API's access control, one table or collection at a time.

## Entry points
- Supabase: every table, view and function in an exposed schema (`public` and `graphql_public` by default; see
  `[api] schemas` in `supabase/config.toml`) is reachable through the Data API and GraphQL. Treat each one as an
  endpoint. Also Edge Functions (`supabase/functions/*/index.ts`), Storage buckets and Realtime channels.
- Firebase: each `match` block in `firestore.rules` and `storage.rules`, each path in `database.rules.json`, and
  each exported Cloud Function (`onCall`, `onRequest`, Firestore, Storage and Auth triggers).
- Policies and rules live in `supabase/migrations/*.sql`, `supabase/schemas/`, the rules files, or the hosted
  console. If they are not in the repository, report each table's access as "needs confirmation" and name the
  policy to check.

## Supabase: row level security
- Every table in an exposed schema needs `alter table … enable row level security`. Without it, anyone with the
  anon key can read and write every row. RLS on with no policy denies everything (safe; check the feature works
  another way, such as through the service role). (CWE-284, API1)
- Policies without a `to` clause apply to `public`, including `anon`. `to authenticated` means anyone who can
  sign up; check `enable_signup` and anonymous sign-ins in `config.toml` before treating it as a restriction.
- `using (true)` or `with check (true)` on a table holding user data is public access. Each policy must tie the
  row to the caller: `(select auth.uid()) = user_id`, or membership through a join on a table the caller can't
  write.
- INSERT policies use only `with check`: check that it pins the owner column to `auth.uid()`, or users create
  rows owned by others. UPDATE reuses `using` as `with check` when there is none; an explicit, weaker
  `with check` lets a user move a row to another owner or tenant.
- RLS is per row, not per column: a user who can update their own `profiles` row can also set `role`,
  `is_admin`, `plan`, `credits` or `tenant_id` on it. Look for column-level `grant update (…)`, a trigger that
  rejects changes, or sensitive columns kept in a separate table. (CWE-915)
- `auth.jwt() -> 'user_metadata'` (`raw_user_meta_data`) is editable by the user through `auth.updateUser()`.
  Never authorize on it; `app_metadata` is set only by the server. (CWE-639)
- Policies that read another RLS table can recurse or leak; helper functions used in policies must be
  `security definer` with `set search_path = ''`, kept in a schema that is not exposed, and not reveal rows to the
  caller.

## Supabase: views, functions and grants
- Views run with the owner's rights and ignore the caller's RLS unless created `with (security_invoker = true)`
  (Postgres 15+). A plain view over a protected table in an exposed schema exposes the whole table.
- Functions in an exposed schema can be called through `/rest/v1/rpc/<name>` by any role holding `EXECUTE`, which
  Postgres grants to `PUBLIC` by default. `security definer` functions bypass RLS: each needs its own
  `auth.uid()` check, `set search_path = ''`, and `revoke execute … from public, anon` when it is not meant to be
  public. (CWE-862)
- `grant all … to anon` or `to authenticated` on tables, sequences or functions widens what the policies must
  hold back. `bypassrls` roles and `disable row level security` in a later migration undo earlier protection;
  read migrations in order.

## Supabase: keys, auth and server code
- The `service_role` key (and `sb_secret_…` secret keys) bypasses RLS. It must never reach a browser or app bundle
  (`NEXT_PUBLIC_*`, `VITE_*`, `EXPO_PUBLIC_*`, mobile resources). Server code that uses it acts as admin and must
  authorize the user it acts for itself; flag service-role clients created from request data. (CWE-798, CWE-269)
- On the server, `supabase.auth.getSession()` reads the session from the cookie without verifying it. Authorize on
  `auth.getUser()` or `auth.getClaims()`, which verify the token. (CWE-345)
- Edge Functions: `verify_jwt = false` in `config.toml` makes the function public; check that it authenticates
  callers itself (webhook signature, `getUser()`), and that it uses the caller's JWT rather than the service role
  for user data.
- Storage: policies on `storage.objects` must check `bucket_id` and the owner, for example
  `(storage.foldername(name))[1] = (select auth.uid())::text`. Public buckets serve every object to anyone who
  has or guesses the path; signed URLs need short expiry.
- Realtime: `postgres_changes` follows RLS, but Broadcast and Presence need private channels with policies on
  `realtime.messages`; public channels let anyone join any topic.

## Firebase: security rules
- `allow read, write: if true`, rules left in test mode (`request.time < timestamp.date(…)`), and Realtime
  Database `".read": true` or `".write": true` are public access. (CWE-284)
- `if request.auth != null` lets any signed-in user, including anonymous auth and self sign-up, read or change
  every document under the match. Tie access to the document: `resource.data.ownerId == request.auth.uid` for
  read, update and delete, and `request.resource.data.ownerId == request.auth.uid` for create.
- Updates must limit which fields change: `request.resource.data.diff(resource.data).affectedKeys().hasOnly([…])`.
  Without it, a user sets their own `role`, `balance` or `verified` fields. (CWE-915)
- Rules combine with OR: a broad `match /{document=**}` or a parent match with `allow` overrides stricter rules
  below it. Rules are not filters: `list` access is decided per query, so check `allow list` separately from
  `allow get`.
- Custom claims (`request.auth.token.admin`) are safe only when set by the Admin SDK; check
  `request.auth.token.email_verified` where email ownership matters.

## Firebase: Admin SDK and Cloud Functions
- The Admin SDK bypasses security rules. `onCall` functions must check `request.auth` (`context.auth` in v1) and
  then authorize the action; `onRequest` functions are public HTTP endpoints and must verify the ID token with
  `verifyIdToken`. App Check proves the app, not the user, and is no substitute. (CWE-306, API5)
- Service-account JSON (`"private_key"`, `"client_email"`) in the repository or the app is a leaked admin
  credential. (CWE-798)
- Firestore and Storage triggers run with admin rights on data a user wrote: validate it before acting on it, and
  guard against loops and unbounded fan-out.

## Mapping
OWASP API1 (object-level authorization) and API3 (property-level authorization) for policy and rule gaps, API5
for admin functions, A01:2025, ASVS V8 (Authorization). Sources: Supabase docs on Row Level Security, database
functions, API keys and server-side auth; Firebase docs on security rules and Cloud Functions.
