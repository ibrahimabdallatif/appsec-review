---
parent: access-control
when: "any handler, resolver, consumer or job that reads or changes a record selected by an id, key, slug, filename or reference the client can supply"
---

# Deep: object-level authorization (BOLA / IDOR)

`deep` mode only. Extends `access-control.md` "Object level". API1:2023, A01:2025, CWE-639, CWE-862, CWE-863.

## Method
1. **List every client-supplied reference.** For each entry point, note every value that selects an object:
   path segment, query parameter, body field, an id nested in a JSON object or array, each item of a batch, a value
   carried in a token or cookie, a filename. Nested and batch ids are where the unbound access usually hides.
2. **Follow each reference to the data access.** Trace it to the exact query filter, key lookup, file open,
   mutation or downstream API call that selects the object. That access is the sink.
3. **Find what binds the object to the caller, at the sink.** A predicate in the same query or call that ties the
   object to the authenticated principal: owner id, tenant, membership, or an explicit policy check on the loaded
   object before use. A lookup keyed only by the client's id (`findById(id)`, `get(key)`) is unbound unless a
   mandatory scope (global ORM filter, row-level security, a repository method that always scopes) covers it.
   Establish which enforcement model the codebase uses before flagging.
4. **Check every sibling and the write side.** For each object type, list every access: read, update, delete,
   list, count, search, export, batch, admin, legacy, background job, webhook and event consumer. One protected
   `GET` means nothing if `PUT`, `DELETE`, bulk or export reaches the same object without the binding.
5. **Check second-order references.** An id validated on the way in, stored, then used later by another path is
   only as safe as that later access.
6. **Confirm or rule out from source.** Confirm with the entry point, the reference field, the unbound access
   line, and the missing predicate. Rule out only by citing the line that binds every access path, including
   writes, batches, exports and second-order uses.

## Where it leaks
- Ownership checked on read, missing on write, bulk or export.
- An id three levels into a body, or one item in an array, reaches an unscoped lookup.
- The tenant or owner taken from the URL or body instead of the verified session.
- Background jobs and consumers running with system scope on an id that came from a user.
- The check runs after the side effect, or only on some branches.

## Rationalizations to reject
- "The id is a random UUID." Unguessable is not bound; one leaked or shared id fires the access.
- "The route requires authentication." Authentication says who the caller is, not that the object is theirs.
- "The read path checks ownership." Audit every verb and every sibling path to the same object.
- "The id is validated on input." Validated for shape, or for ownership? A well-formed foreign id passes.
- "It is an internal endpoint." If an authenticated user or another tenant can reach it, the binding must hold.

Adapted from `hunting-broken-object-level-authorization` and `auditing-multi-tenant-isolation` in
UnboundCompute/security-agent-skills (MIT License, copyright 2026 Riyan Dhiman).
