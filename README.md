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

**In a bundle (a Convex function, an edge worker), import by subpath.** The
root re-exports `clerk-handshake`, which pulls `@clerk/backend`: importing even
`requireTenantId` from the root bundles 33 Clerk modules. The subpath does not:

```js
import { requireTenantId } from "@vantageos/cloud-identity/org-guard"; // 0 Clerk modules
```

Measured with esbuild on 0.23.3: the root import of `requireTenantId` is
599,033 bytes (33 `@clerk` modules), the `./org-guard` import 1,065 bytes
(none). `test/org-guard-subpath.test.ts` re-measures it on every run.

## Documentation

The long-form guides live in `docs/`, one page per topic:

- [Caller paths: a person, a service, a Convex consumer](https://github.com/vantageos-agency/cloud-identity/blob/main/docs/caller-paths.md): how a host-verified identity, a machine credential and a Convex consumer each reach the tenant, under one contract.
- [Authorizing a person and wiring sign-in](https://github.com/vantageos-agency/cloud-identity/blob/main/docs/authorize.md): the authorize flow that binds an organisation, person sign-in in an MCP server, and the `/authorize-runtime` wiring.
- [Role policy, membership, namespace writes and secrets](https://github.com/vantageos-agency/cloud-identity/blob/main/docs/role-policy.md): a minimum role over an order you supply, role-claim mapping, membership, namespace writes and secrets (0.10.0).
- [The acting principal and the target, by ID](https://github.com/vantageos-agency/cloud-identity/blob/main/docs/principal-by-id.md): resolving the acting principal and checking the target by permanent ID, and a caller's standing (0.11.0, 0.14.0).
- [Protecting an MCP server as an OAuth resource](https://github.com/vantageos-agency/cloud-identity/blob/main/docs/resource-server.md): `/resource-server`, Clerk handshake, token to tenant, member scope, scope standing, caller from claims, agent writer, personal agent and person scope.
- [An organisation is its permanent ID](https://github.com/vantageos-agency/cloud-identity/blob/main/docs/organisation-id.md): why an organisation is addressed by its permanent ID, never a slug or label (0.16.0).
- [Reaching across organisations: support access and agent links](https://github.com/vantageos-agency/cloud-identity/blob/main/docs/cross-org-access.md): time-bounded audited support access, and one agent of an organisation reaching one agent of another (0.23.0).
- [Clerk membership sync](https://github.com/vantageos-agency/cloud-identity/blob/main/docs/membership-sync.md): syncing Clerk memberships (0.21.6), HMAC-signed bodies (`/hmac-signature`, 0.28.0) and the no-organisation refusal (`/identity-refusal`, 0.32.0).
- [Agents: acting claims and tool roles](https://github.com/vantageos-agency/cloud-identity/blob/main/docs/agent-tools.md): whether a typed name may act as the agent (`/acting-claim`, 0.22.0), and which tools an agent may see and call (`/tool-role`, 0.33.0).
- [Upgrading](https://github.com/vantageos-agency/cloud-identity/blob/main/docs/upgrading.md): upgrade guides for 0.3.0 (breaking: the scope context is required) and 0.4.0 (additive).

## What each function does

**Tenant resolution and membership**

- `requireTenantId(source)` — returns the caller's tenant id, or throws if
  there is none. It accepts both entry paths behind one contract:
  `{ kind: "session", identity }` for a signed-in human, and
  `{ kind: "bearer", context }` for a machine caller. A missing session, a
  missing organization and an empty organization id are all refusals, never a
  default.
- `resolveTenantIdOrAbsent(source)` — the NON-throwing sibling of
  `requireTenantId`, for a public READ. Same `TenantSource` union, same
  refusal conditions; instead of throwing it returns
  `{ present: true, tenantId }` or
  `{ present: false, absence: { code: "TENANT_ABSENT", reason } }`
  (`TenantAbsence`, `TenantAbsenceReason`, `TenantResolution`). The absence
  is a non-empty object: it is never `[]`, `{}`, `null` or a zeroed count, so
  "no organization" and "an organization with nothing in it" cannot collapse
  into one value. Use `requireTenantId` at a WRITE boundary and
  `resolveTenantIdOrAbsent` where a throw would crash a mounted render. The
  tenant id is OPAQUE — returned byte-for-byte, never a slug or display name.
- `requireHumanRole(session, required)` — asserts the VERIFIED session
  carries `required` (a `HumanAccountRole` or a list of them, exact match, no
  hierarchy) and returns the resolved identity; throws otherwise. The role is
  read from `session.orgRole`, never from an argument. `RequiredHumanRole`
  is its `required` type.
- `resolveHumanRoleOrRefusal(session, required)` — the non-throwing form:
  `{ admitted: true, identity }` or
  `{ admitted: false, refusal: { code: "ROLE_REFUSED", reason } }`
  (`RoleResolution`, `RoleRefusal`, `RoleRefusalReason`). `reason` is
  `role-not-held` for a verified member lacking the role.
- `getEffectiveTenantId(ctx, args)` — resolves which tenant a request should
  act on when a caller may legitimately act on more than one.

**Resolving a presented bearer token**

- `validatePresentedBearer(authHeader, deps)` — takes the raw
  `Authorization` header a non-master caller presented, and returns either a
  resolved identity or a coarse refusal. It hashes the token, asks your
  `deps.lookupBySecretHash` callback for the row carrying that digest,
  re-compares the stored digest in constant time, and then checks revocation
  and expiry. Your callback does one indexed read; every decision stays in the
  package, so two consumers cannot drift into two different answers to "who is
  calling".
  - **Your callback receives the digest, never the token.** A raw secret
    therefore never reaches your query, your query log or your slow-query log.
    Use `sha256Hex` to produce the same digest when you WRITE a token row, so
    the two sides agree.
  - **An unknown token, a revoked token and an expired token return one
    identical value** (`{ ok: false, error: "mismatch" }`). Someone probing
    your endpoint cannot learn from the reply whether a token was ever real.
    Pass `deps.onRefusal` to receive the distinction
    (`PresentedBearerInternalReason`) in your own logs, where it belongs.
  - **A failing lookup refuses.** If your callback throws, the result is
    `{ ok: false, error: "unavailable" }` — a refusal you can answer with 503
    instead of 401. There is no branch that grants anything when the lookup
    fails.
  - `deps.now` is an injectable clock, so expiry is testable without waiting.
  - Types: `PresentedBearerDeps`, `StoredBearerRow` (validated at runtime by
    `storedBearerRowSchema`), `ResolvedBearerIdentity`,
    `ValidatePresentedBearerResult`.
- `requireAgentScopedIdentity(identity)` — narrows a resolved identity to a
  surface that acts as ONE agent, and refuses when the token has no agent.
  A token can be organization-wide: it names a tenant and no agent. That is a
  legitimate credential, and it must never be silently widened into whichever
  agent the surface happened to be about. So the agent is not a nullable field
  you have to remember to check — `ResolvedBearerIdentity.agent` is an
  `AgentPresence`, a union you must narrow, and the per-agent form
  (`AgentScopedIdentity`, with a plain `agentId: string`) can only be obtained
  from this function. Returns `RequireAgentScopedResult`; its refusal is
  distinct from a bad credential, because the right answer there is 403, not
  401.
- `sha256Hex(input)` — the lower-case hex SHA-256 digest of a string. Exported
  so that the code storing a token row hashes it exactly the way the resolver
  will recompute it. Hash once, store the digest, discard the token.

**Row filtering**

- `passesScopeFilter(ctx, row)` — true when this row is visible to this
  caller. **Deprecated since 0.11.0** (see below).
- `scopeFilterList(ctx, rows)` — the subset of rows the caller may see.
  **Deprecated since 0.11.0** (see below).
- `scopeFilterGet(ctx, row)` — the row, or `null` if the caller may not see it.
  **Deprecated since 0.11.0** (see below).
- `isMasterScope(ctx)` / `isWildcardScope(ctx)` — true when the caller holds
  unrestricted access. Useful for skipping filtering you know is pointless;
  never as a substitute for it. Decided on `scope === "master"`. A `"*"`
  entry in `fromAllowList` still counts as master, **deprecated since
  0.24.0**: declare `scope: "master"` instead. It is removed in a major
  release.

**Deprecated since 0.11.0 (pointing to `filterTargetsBelongingTo` since 0.14.0): `passesScopeFilter`, `scopeFilterGet` and
`scopeFilterList`.** All three (the last two through the first) admit a row
when its `createdBy` NAME appears in the caller's `fromAllowList`, so a name
selects the row, which backend standard R-53 clause 1 forbids. For a target
that carries an organisation or owner ID, use `resolveActingPrincipal` and
`assertTargetBelongsTo`, which compare stored IDs (see "The acting principal
by ID, and the target checked by ID"). Their behaviour is unchanged; they stay
exported until consumers migrate off them, and are removed in a major release.

Visibility is granted two ways: the row's `createdBy` appears in the caller's
`fromAllowList`, or the row's `namespace` sits under one of the caller's
`namespaceReadPrefixes`. Prefixes match on a path boundary, so a caller allowed
`team/finance` does not thereby see `team/finance-archive`.

`fromAllowList` is optional since 0.24.0. An absent list, or a value that is
not an array, names nobody: no row is visible through `createdBy` or a grant
field, and the caller is not master through it. Namespace prefixes work as
before.

A third way is opt-in per call. All three functions take an optional last
argument, `grantFields` (type `GrantFieldDeclaration`, a list of property
names). It names the row properties that carry per-row grants, such as a
mission's `agents`. A row is then also visible when one of those properties
names an identity in the caller's `fromAllowList`. The property can hold a
single string or an array of strings; a value of any other shape is skipped,
not matched. The list is data supplied by your call site; the package
hardcodes no field names. Omitting it, or passing `[]`, adds nothing.

**Token validation**

- `validateMasterBearer(header, secret)` — compares an `Authorization: Bearer`
  header against a shared secret in constant time, and reports *why* it failed:
  header absent, header malformed, or value mismatched.
- `timingSafeEqual(a, b)` — constant-time byte comparison, if you need to build
  your own check.

**Shapes**

Zod schemas and their inferred TypeScript types for workspaces, members,
roles and tenant context: `workspaceSchema` (type `Workspace`),
`workspaceMemberSchema` (type `WorkspaceMember`), `workspaceRoleSchema`
(type `WorkspaceRole`), `tenantContextSchema` (type `TenantContext`) — plus
`ScopeViolationError` (payload type `ScopeViolationPayload`), for refusals you
want to catch by type, and `BearerPayload`, the type returned by
`decodeUnverifiedBearer`.

**Supporting types** (no runtime code — import with `import type`)

- `OAuthCtx` — the context object every scope-filter function above requires:
  `{ fromAllowList?, namespaceReadPrefixes, namespaceWritePrefixes, scope? }`
  (`fromAllowList` optional since 0.24.0).
- `ScopeProfile`, `NamespacePrefix`, `FromAllowListEntry` — the field types
  that make up `OAuthCtx`.
- `ValidateMasterBearerResult` — the return type of `validateMasterBearer`.
- `ScopeFilterable` — the minimal row shape (`{ createdBy?, namespace? }`)
  accepted by `passesScopeFilter` / `scopeFilterList` / `scopeFilterGet`.
- `GrantFieldDeclaration` — `readonly string[]`, the optional `grantFields`
  argument of those three functions.
- `SessionIdentity` — the human-path shape `requireTenantId` accepts under
  `{ kind: "session", identity }` (see "Both caller paths, one contract").
- `TenantSource` — the discriminated union `requireTenantId` accepts:
  `{ kind: "session", identity }`, `{ kind: "bearer", context }`, or
  `{ kind: "self-host", tenantId }`.
- `DeploymentMode` — the named `"cloud" | "self-host"` literal union (0.4.0).

**Deployment mode and the human path (0.4.0, additive)**

- `DeploymentMode` (`"cloud" | "self-host"`) names the two ways this package
  can be run. `cloud` keeps `requireTenantId`'s existing session/bearer
  behaviour exactly as-is — organization/workspace REQUIRED, fail-closed.
  `self-host` is single-tenant: pass `{ kind: "self-host", tenantId }` to
  `requireTenantId`, and it returns `tenantId` when it is a non-empty string.
  The self-host tenant id must be DECLARED via configuration — if you select
  self-host mode without configuring a tenant id, `requireTenantId` throws
  rather than returning a default. A right is never granted by absence,
  whichever mode you are in.

  ```ts
  import { requireTenantId } from "@vantageos/cloud-identity";

  // self-host: the tenant id is configured explicitly, once, at startup.
  requireTenantId({ kind: "self-host", tenantId: "the-one-tenant" });
  // -> "the-one-tenant"

  requireTenantId({ kind: "self-host", tenantId: undefined });
  // -> throws: "No tenant id configured for self-host mode..."
  ```

- `normalizeVerifiedHumanSession(session)` — **normalizes, does not
  authenticate.** Maps an already-*verified* (not merely well-shaped),
  framework-agnostic Clerk session object (`{ orgId, userId, orgRole }`) to
  `{ tenant, subject, role }`. This package never imports a Clerk SDK; the
  caller MUST verify the session upstream (e.g. Clerk's server-side `auth()`)
  and pass in the already-verified object — never an unverified,
  client-supplied object such as `req.body`, which would make the caller's
  input the trusted source of tenant/subject/role. Refuses (throws) when the
  session has no organization, no user id, or an org role this package does
  not recognize — never defaults silently; these are shape checks, not a
  verification step.
- `humanAccountRoleSchema` (type `HumanAccountRole`) — the new
  `"owner" | "admin" | "member" | "client"` role union returned by
  `normalizeVerifiedHumanSession`. Distinct from `workspaceRoleSchema`
  (`Admin | Editor | Viewer`) — one is an organization-account role, the
  other is workspace membership; they are never conflated.
- `ClerkSessionLike` — the minimal input shape `normalizeVerifiedHumanSession` accepts:
  `{ orgId?, userId?, orgRole? }`.
- `ResolvedHumanIdentity` — the `{ tenant, subject, role }` return type of
  `normalizeVerifiedHumanSession`.

  ```ts
  import { normalizeVerifiedHumanSession } from "@vantageos/cloud-identity";

  normalizeVerifiedHumanSession({
    orgId: "org_abc",
    userId: "user_123",
    orgRole: "org:admin",
  });
  // -> { tenant: "org_abc", subject: "user_123", role: "admin" }
  ```

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
- **It does not issue, rotate or revoke tokens.** `validatePresentedBearer`
  reads a row you already store and decides whether it may be believed. Minting
  a token, writing its row, marking it revoked and expiring it are yours; the
  package only insists that a row it is handed be believed in constant time,
  and refused identically however it fails.
- **It does not verify an arbitrary signed JWT.** The presented-bearer path is
  for an OPAQUE token — one whose only meaning is the row it matches. The one
  signed token it verifies is a Clerk session token (`verifyClerkSessionToken`,
  RS256 only). For any other signed credential, verify the signature with a
  JWT library first.

## Versioning

This package follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
While it is 0.x, a breaking change bumps the MINOR version. Every release, and
every migration a release requires, is in
[CHANGELOG.md](https://github.com/vantageos-agency/cloud-identity/blob/main/CHANGELOG.md). The 0.3.0 and 0.4.0 upgrade guides are in
[docs/upgrading.md](https://github.com/vantageos-agency/cloud-identity/blob/main/docs/upgrading.md).

## License

FSL-1.1-Apache-2.0. See [LICENSE](https://github.com/vantageos-agency/cloud-identity/blob/main/LICENSE).

## Issues

https://github.com/vantageos-agency/cloud-identity/issues
