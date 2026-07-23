# Changelog

All notable changes to `@vantageos/cloud-identity` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
  paths behind one contract. Hoisted from evevantage's
  `convex/lib/auth.ts::requireOrgId`
  (commit `1c102132ac5832573e58145de43b7338ba5d0b00`), adapted to be
  framework-agnostic. Refuses on missing session, missing/empty `orgId`, and
  missing/empty bearer-resolved `workspaceId` (`src/org-guard.ts`).
- `SessionIdentity`, `TenantSource` types.

### Scope note (2026-07-23 avenant)

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
- `getEffectiveWorkspaceId` deferred to 0.2.0 (depends on `vantageos-crm` workspace helper, owned by Theta).
- No `provenance: true` in `publishConfig` — provenance only from CI per fleet friction lesson `npm-publish-provenance-only-from-ci-not-local-host`.
