# @vantageos/cloud-identity

Building blocks for multi-tenant authorization: decide which tenant a caller
belongs to, and keep every other tenant's rows out of the response.

If your service holds data for several customers behind one deployment, you
answer the same four questions on every request — who is calling, which tenant
they belong to, which rows they may see, and whether their token is genuine.
This package answers them once, in plain functions with no framework attached,
so each service does not re-implement (and re-misimplement) its own version.

It depends on no web framework, router or database, and runs anywhere
JavaScript runs.

## Install

```bash
npm install @vantageos/cloud-identity
```

Node 18 or later. ESM only.

## Quick start

```js
import { requireTenantId, scopeFilterList } from "@vantageos/cloud-identity";

// 1. Which tenant is this caller in? Throws if the answer is "none".
const tenantId = requireTenantId({
  kind: "session",
  identity: { userId: "user_123", orgId: "org_abc" },
});

// 2. Which of these rows may they see?
const ctx = {
  fromAllowList: ["reports"],
  namespaceReadPrefixes: ["team/finance"],
  namespaceWritePrefixes: [],
};

const rows = [
  { createdBy: "reports", namespace: "team/finance" },    // kept
  { createdBy: "someone-else", namespace: "team/legal" }, // dropped
];

console.log(tenantId);                    // "org_abc"
console.log(scopeFilterList(ctx, rows));  // only the first row
```

Every symbol is available from the package root. Subpath imports
(`@vantageos/cloud-identity/scope-filter` and friends) also work if you prefer
to be explicit about where something comes from.

## What each function does

**Tenant resolution and membership**

- `requireTenantId(source)` — returns the caller's tenant id, or throws if
  there is none. It accepts both entry paths behind one contract:
  `{ kind: "session", identity }` for a signed-in human, and
  `{ kind: "bearer", context }` for a machine caller. A missing session, a
  missing organization and an empty organization id are all refusals, never a
  default.
- `getEffectiveTenantId(ctx, args)` — resolves which tenant a request should
  act on when a caller may legitimately act on more than one.

**Row filtering**

- `passesScopeFilter(ctx, row)` — true when this row is visible to this
  caller.
- `scopeFilterList(ctx, rows)` — the subset of rows the caller may see.
- `scopeFilterGet(ctx, row)` — the row, or `null` if the caller may not see it.
- `isMasterScope(ctx)` / `isWildcardScope(ctx)` — true when the caller holds
  unrestricted access. Useful for skipping filtering you know is pointless;
  never as a substitute for it.

Visibility is granted two ways: the row's `createdBy` appears in the caller's
`fromAllowList`, or the row's `namespace` sits under one of the caller's
`namespaceReadPrefixes`. Prefixes match on a path boundary, so a caller allowed
`team/finance` does not thereby see `team/finance-archive`.

**Token validation**

- `validateMasterBearer(header, secret)` — compares an `Authorization: Bearer`
  header against a shared secret in constant time, and reports *why* it failed:
  header absent, header malformed, or value mismatched.
- `timingSafeEqual(a, b)` — constant-time byte comparison, if you need to build
  your own check.

**Shapes**

Zod schemas and TypeScript types for workspaces, members, roles and tenant
context: `workspaceSchema`, `workspaceMemberSchema`, `workspaceRoleSchema`,
`tenantContextSchema` — plus `ScopeViolationError`, for refusals you want to
catch by type.

## What this package does not do

Worth reading before you rely on it.

- **`decodeUnverifiedBearer` decodes a token. It does not verify one.** The
  name is literal. It reads the payload out of a bearer token and checks its
  shape; it does not check a signature, so the contents are whatever the caller
  chose to put there. Treating its output as trusted is a vulnerability, not a
  shortcut. Verify the token — a signed JWT, or a lookup against your own store
  — before you believe any field in it.
- **This is not an authentication system.** There is no user store, no login,
  no session issuance. It takes an identity you have already established and
  tells you what that identity may reach.
- **It does not talk to your database.** `scopeFilterList` filters rows you
  have already fetched. If fetching them was itself expensive or unsafe, filter
  earlier, in your query.

## Upgrading to 0.3.0

**This release changes a default, and it breaks compilation on purpose.**

Before 0.3.0, calling a scope-filter function without an authorization context
returned `true` — no context meant full access. A caller who simply forgot to
pass the context received every row, and no warning. From 0.3.0 the context is
required: omitting it is a type error, and passing `null` or `undefined`
throws.

The breakage is deliberate, and it is the point. A caller that stops compiling
is a caller that has been told. A caller that still compiles and quietly
returns different rows is an incident nobody attributes to the upgrade.

What to do:

- If the call site has a real authorization context, pass it. This is almost
  always the right fix, and the context is usually already in scope.
- If the call site genuinely means "unrestricted", pass the exported constant
  `LEGACY_WILDCARD_CTX` by name. It reproduces the old behaviour exactly. It
  has to be written out, because an intentional bypass belongs in a code review
  and an accidental one should not be possible.

```js
import { scopeFilterList, LEGACY_WILDCARD_CTX } from "@vantageos/cloud-identity";

scopeFilterList(LEGACY_WILDCARD_CTX, rows); // explicit, unrestricted
```

`requireTenantId` is also new in 0.3.0. Nothing existing calls it, so it breaks
nothing.

Version history is in [CHANGELOG.md](./CHANGELOG.md).

## License

FSL-1.1-Apache-2.0. See [LICENSE](./LICENSE).

## Issues

https://github.com/vantageos-agency/cloud-identity/issues
