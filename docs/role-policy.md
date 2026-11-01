# Role policy, membership, namespace writes and secrets

Part of the `@vantageos/cloud-identity` documentation. Start at the [README](../README.md).

## Role policy, membership, namespace writes and secrets (0.10.0)

Seven primitives that consumers used to copy. Each is pure, takes its policy as
DATA from the call site, and refuses on every absence: no role, no claim, no
list, no prefix, no secret and a failing lookup are all refusals, never a
default grant. Refusals share one shape, `IdentityRefusal` (`code`, `reason`,
`door`, `detail`), thrown inside an `IdentityRefusalError` by the asserting
forms. `IdentityRefusalCode` is `RBAC_DENIED` or `CREDENTIAL_REFUSED`;
`IdentityRefusalReason` is the closed list of reasons. Every function that
refuses accepts an optional `door` so the refusal names your own entry point.

**Minimum role over an order you supply** (`./role-policy`)

- `resolveMinRole({ role, minimum, order, door? })` — `order` is your ordered
  list, MOST privileged first (for example `["admin", "editor", "viewer"]`).
  Returns `{ ok: true, role }` or `{ ok: false, refusal }` (`MinRoleInput`,
  `MinRoleResult`). Refuses an empty or duplicated order, a `minimum` outside
  the order, an absent or unknown role, and a role below the minimum. Matching
  is exact.
- `assertMinRole(input)` — the throwing form; returns the role or throws
  `IdentityRefusalError`.

**Role-claim mapping with an explicit fallback** (`./role-policy`)

- `mapRoleClaim({ claim, mapping, fallback?, door? })` — maps a verified claim
  (for example `"org:admin"`) to your role through `mapping`, your data
  (`MapRoleClaimInput`, `MapRoleClaimResult`). The package never picks a
  default: an absent or unmapped claim is served only when YOU pass `fallback`
  (use your least-privileged role), and is refused otherwise. A claim that is
  not a string counts as absent; prototype keys are never mapped. The result
  says whether the role was `mapped` or came from the `fallback`.

**Membership and tenant visibility** (`./tenant-membership`)

- `resolveMembership({ subject, orgId, lookup, door? })` — async. `lookup` is
  your read of one membership (`MembershipRecord`: `active`, optional `role`,
  optional `orgId`). A throwing lookup, a miss, an inactive row, a malformed
  row and a row naming another organisation are all refusals; the lookup's own
  error text is not surfaced. Served result: `{ ok: true, membership }`
  (`ResolvedMembership`, `ResolveMembershipInput`, `ResolveMembershipResult`).
  `membershipRecordSchema` is the zod schema of the record.
- `isRowInTenant({ rowOrgId, callerOrgId })` — `true` only on strict equality
  of two non-empty ids. An unstamped row is never visible, not even to a caller
  with no organisation.
- `requireOrgAdmin({ verifiedOrgId, targetOrgId, role, adminRoles, door? })` —
  the organisation-admin proof, bound to the caller's VERIFIED organisation:
  the target must equal it, and the role must be one of `adminRoles` (your
  data; an empty list admits nobody). Throws `IdentityRefusalError`
  (`RequireOrgAdminInput`).

**Namespace writes** (`./namespace-write`, `./scope-filter`)

- `assertNamespaceWrite(oauthCtx, namespace, door?)` — throws unless the
  caller's `namespaceWritePrefixes` admit the namespace. Master scope passes;
  a non-master with no write prefix is refused; read prefixes never grant a
  write; an empty-string prefix grants nothing.
- `namespaceMatchesPrefix(namespace, prefix)` — the one path-boundary rule:
  equality, or the prefix followed by `/`. `team/finance-archive` is not inside
  `team/finance`. The read filter and `assertNamespaceWrite` both use it.

**Synchronous constant-time comparison** (`./secret-compare-sync`)

- `timingSafeEqualSync(a, b)` — strings (UTF-8) or `Uint8Array`, pure
  JavaScript, no early exit on content. It walks the longer length and folds a
  length difference into the result. Any other input type is `false`. The async
  `timingSafeEqual` is unchanged.
- `assertSecretSync(presented, expected, door?)` — throws `IdentityRefusalError`
  (`CREDENTIAL_REFUSED`) on mismatch. An unset `expected` (undefined, null or
  empty) matches nothing, so a missing configuration never opens a door. The
  refusal carries neither value.
