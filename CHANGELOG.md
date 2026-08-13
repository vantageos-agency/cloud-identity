# Changelog

All notable changes to `@vantageos/cloud-identity` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
- **Human-path resolver** — `resolveHumanIdentity()` (`src/human-path.ts`,
  new `./human-path` subpath export) maps an already-resolved, framework-agnostic
  Clerk-shaped session (`{ orgId, userId, orgRole }`) to
  `{ tenant, subject, role }`. `role` is a new union `HumanAccountRole`
  (`owner | admin | member | client`), distinct from `workspaceRoleSchema`
  (`Admin | Editor | Viewer`) and never conflated. No Clerk SDK is imported.
  Refuses (throws) on no session, no org, no user id, or an unrecognized/absent
  org role — presented, never inferred.

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
