# Changelog

All notable changes to `@vantageos/cloud-identity` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0]

**Additive — typed refusal for reads, and a role assertion.**

### Added

- `resolveTenantIdOrAbsent(source)` (`src/org-guard.ts`): non-throwing sibling
  of `requireTenantId`. Returns `{ present: true, tenantId }` or a typed
  `{ present: false, absence: { code: "TENANT_ABSENT", reason } }`. A read that
  throws crashes a mounted render; a read that returns a bare empty value is
  byte-identical to "there is nothing". This returns neither.
- `requireHumanRole(session, required)` and
  `resolveHumanRoleOrRefusal(session, required)` (`src/human-path.ts`): role
  assertion on the verified session's `orgRole`, throwing and non-throwing
  forms. Exact match, no hierarchy; an empty required list admits nobody.
- Types: `TenantAbsence`, `TenantAbsenceReason`, `TenantResolution`,
  `RequiredHumanRole`, `RoleRefusal`, `RoleRefusalReason`, `RoleResolution`.

### Fixed

- The Clerk org-role map is now prototype-less (`Object.create(null)`). As a
  plain object literal it inherited `Object.prototype`, so a presented
  `orgRole` of `toString`, `constructor`, `valueOf` or `__proto__` did not
  MISS the lookup — it returned an inherited value, which is truthy, and the
  resolver handed back a FUNCTION as the role instead of refusing. Any key
  that is not one of the eight own keys is now `undefined`, so the existing
  refusal path rejects it. Fixed at the data; no lookup expression and no
  function body changed, and no list of forbidden names was introduced.

### Unchanged

- `requireTenantId` and `normalizeVerifiedHumanSession` are byte-for-byte
  unchanged and still throw on every refusal.
- The tenant key stays opaque: no export takes or returns a slug. That
  opacity is now pinned on all four served paths (session, bearer,
  self-host, `role.identity.tenant`), through BOTH the throwing and the
  non-throwing sibling, with a fixture carrying edge whitespace so that
  splicing a `.trim()` onto a served id goes RED instead of passing.

### Removed

- `bun.lock`, committed by accident in 0.5.0. `package-lock.json` is the
  lockfile of record; two lockfiles for two package managers guarantee a
  silent divergence.

## [0.5.0]

**Additive — grant-aware scope filter.** Closes the other pole of the
fail-closed defect class: 0.3.0/0.4.0 closed "a right granted by ABSENCE"
(missing `oauthCtx` silently passing everything); this closes "a right
REFUSED by absence" — a per-row grant (a named mission agent/pilot, a
mandate's `fulfilledBy`) that IS present on the row but that
`passesScopeFilter`/`scopeFilterList`/`scopeFilterGet` were structurally
blind to, because they only ever consulted `createdBy`/`namespace`.

### Added

- `passesScopeFilter`, `scopeFilterList`, `scopeFilterGet` (`src/scope-filter.ts`)
  now accept an optional `grantFields: readonly string[]` parameter, defaulting
  to `[]`. Each entry names a property on the row that the CALLER declares as
  a per-row grant — the field's runtime value is treated as a single identity
  (`string`, equality match) or multiple identities (`string[]`, any-element
  match) against `oauthCtx.fromAllowList`. The package never hardcodes which
  fields are grants for which table; that declaration is caller-supplied data.
- **Fail-closed regression preserved byte-for-byte:** omitting `grantFields`
  (or passing `[]`) reproduces 0.4.0 behaviour exactly — this is a pure
  widening, no existing caller's behaviour changes without an explicit
  opt-in declaration at its own call site.

## [0.4.0]

**Additive.** Two new primitives so one identity layer covers both deployment
shapes and the human sign-in path — no separate self-host layer, no change to
the Cloud/machine path. Serves Tau's `vantage-starter` self-host install and
the Hephaistos human-path onboarding, both stalled on this surface.

### Added

- **Named deployment mode** — `DeploymentMode` (`"cloud" | "self-host"`) and a
  `{ kind: "self-host"; tenantId }` branch on `TenantSource` / `requireTenantId`
  (`src/org-guard.ts`). `cloud` keeps the existing fail-closed behaviour
  unchanged (org/workspace required on every request — invariant #1123 holds,
  0.4.0 reopens nothing). `self-host` is single-tenant: `requireTenantId`
  returns the configured `tenantId` only when it is a non-empty string, and
  **throws** otherwise — the tenant is presented explicitly by configuration,
  never inferred from the absence of an organization.
- **Human-path resolver** — `normalizeVerifiedHumanSession()` (`src/human-path.ts`,
  new `./human-path` subpath export) maps an already-*verified*, framework-agnostic
  Clerk-shaped session (`{ orgId, userId, orgRole }`) to
  `{ tenant, subject, role }`. `role` is a new union `HumanAccountRole`
  (`owner | admin | member | client`), distinct from `workspaceRoleSchema`
  (`Admin | Editor | Viewer`) and never conflated. No Clerk SDK is imported.
  Refuses (throws) on no session, no org, no user id, or an unrecognized/absent
  org role — presented, never inferred. **Naming fix, still pre-publish:** this
  function was originally named `resolveHumanIdentity`, which invited passing
  in an unverified, client-supplied object (e.g. `req.body`) and would make
  that object the trusted source of tenant/subject/role — a
  privilege-escalation risk. Renamed to `normalizeVerifiedHumanSession` before
  0.4.0 reaches npm (current published latest is 0.3.0) to make the
  already-verified precondition explicit at the call-site, mirroring
  `decodeUnverifiedBearer`'s rename from `resolveBearer` in 0.2.0. Not a
  breaking change — 0.4.0 has no npm consumer yet.

### Notes

- Purely additive: every 0.3.0 export (`passesScopeFilter`, `scopeFilterList`,
  `scopeFilterGet`, `validateMasterBearer`, `getEffectiveTenantId`,
  `decodeUnverifiedBearer`, `requireTenantId`'s `session`/`bearer` branches, …)
  is behaviorally unchanged. Full suite 87/87, `tsc --noEmit` 0.

## [Unreleased] - 0.3.0

**BREAKING.** Closes two measured 0.2.0 defects — a right must never be
granted by absence.

### Changed (breaking)

- `passesScopeFilter`, `scopeFilterList`, `scopeFilterGet`, `isMasterScope`,
  `isWildcardScope`: `oauthCtx` is now **mandatory** (`OAuthCtx`, no longer
  `OAuthCtx | undefined`). The 0.2.0 behaviour of an omitted `oauthCtx`
  silently passing every row (wildcard, as if master-scoped) is removed.
  Omitting the argument now breaks the caller's build; at runtime (for
  callers that bypass TypeScript) it throws instead of granting access.
  Callers that deliberately want the old legacy-bearer wildcard behaviour
  must import and pass the new `LEGACY_WILDCARD_CTX` sentinel explicitly.

### Added

- `LEGACY_WILDCARD_CTX` — explicit, by-name opt-in for the pre-0.3.0
  legacy-bearer wildcard behaviour (`src/scope-filter.ts`).
- `requireTenantId(source: TenantSource): string` — organization/workspace
  membership guard, unifying the human (session) and machine (bearer) entry
  paths behind one contract. Refuses on missing session, missing/empty `orgId`, and
  missing/empty bearer-resolved `workspaceId` (`src/org-guard.ts`).
- `SessionIdentity`, `TenantSource` types.

### Scope note

The package now exposes, behind one contract, all four primitives an
application needs and should never reimplement: tenant resolution
(`getEffectiveTenantId`), membership requirement (`requireTenantId`), row
filtering (`passesScopeFilter` / `scopeFilterList` / `scopeFilterGet`), and
identifier validation (`validateMasterBearer`). Framework adapters (Convex,
Hono, etc.) wrap these; they must not reimplement the checks.

## [0.2.0] - 2026-06-13

Additive release — domain-tenancy layer. No breaking changes. All 0.1.0 exports unchanged.

### Added

- `WorkspaceRole` literal union `"Admin" | "Editor" | "Viewer"` + `workspaceRoleSchema` (Zod).
- `Workspace` type + `workspaceSchema` (Zod) — `{ id, name, createdAt, metadata? }`.
- `WorkspaceMember` type + `workspaceMemberSchema` (Zod) — `{ userId, workspaceId, role, joinedAt }`.
- `TenantContext` type + `tenantContextSchema` (Zod) — `{ workspaceId, userId, roles[] }`.
- `ScopeViolationError` class — `code: "SCOPE_VIOLATION"`, payload `{ requestedTenantId, contextTenantId, reason }`. Canonical cross-tenant isolation signal — translate to 403 or MCP permission-denied.
- `getEffectiveTenantId(ctx, args)` — multi-tenant isolation guard. Throws `ScopeViolationError` when `args.workspaceId !== ctx.workspaceId`; returns `ctx.workspaceId` on match.
- `decodeUnverifiedBearer(token)` — async DECODER for `base64(JSON({ userId, workspaceId, roles[] }))` into `BearerPayload`. Validates SHAPE via Zod and throws on shape or decode failure. **⚠️ NOT authentication. NOT a trust boundary.** Performs NO signature verification, NO issuer check, NO expiry check. The decoded payload is attacker-controlled — see the "Security: bearer decoding" section of README. Use as a test fixture or as a decoder for a bearer already verified by an upstream signed-JWT / opaque-token middleware. The production trust boundary (signed JWT + verification) is planned for 0.3.0. Renamed from the original `resolveBearer` (0.2.0 pre-release) per Eta security review — the new name makes the lack of verification impossible to miss at the call-site.
- `BearerPayload` type (inferred from Zod schema).
- `ScopeViolationPayload` interface.
- New subpath export: `@vantageos/cloud-identity/tenancy-domain`.
- `zod` added as a production dependency (schema validation for domain types).

### Notes

- All new symbols are also re-exported from the main `@vantageos/cloud-identity` entry point.
- `decodeUnverifiedBearer` uses base64-JSON as a lightweight format and is intentionally NOT an authentication primitive. Production callers MUST run a SIGNATURE-VERIFYING middleware (signed JWT / Clerk session / opaque-token lookup) before constructing the `TenantContext` passed to `getEffectiveTenantId`.
- `getEffectiveTenantId` expects a `TenantContext` whose `workspaceId` came from a signature-verified source. Feeding it the output of `decodeUnverifiedBearer` directly is a security bug — see README "Security: bearer decoding".

## [0.1.0] - 2026-06-04

Initial release.

### Added
- `crypto.timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean` — constant-time byte comparison with branch-timing-leak mitigation on length mismatch.
- `scope-filter.passesScopeFilter / scopeFilterList / scopeFilterGet` — row-level visibility filter honouring `fromAllowList` + `namespaceReadPrefixes` with master pass-through and legacy-bearer back-compat.
- `bearer-validation.validateMasterBearer` — `Authorization: Bearer <token>` parsing + sha256 constant-time match against a master secret.
- Public type surface: `OAuthCtx`, `ScopeProfile`, `NamespacePrefix`, `FromAllowListEntry`, `ValidateMasterBearerResult`.

### Notes
- `getEffectiveWorkspaceId` deferred to 0.2.0.
- No `provenance: true` in `publishConfig` — provenance only from CI per fleet friction lesson `npm-publish-provenance-only-from-ci-not-local-host`.
