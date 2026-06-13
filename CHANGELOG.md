# Changelog

All notable changes to `@vantageos/cloud-identity` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-06-13

Additive release — domain-tenancy layer. No breaking changes. All 0.1.0 exports unchanged.

### Added

- `WorkspaceRole` literal union `"Admin" | "Editor" | "Viewer"` + `workspaceRoleSchema` (Zod).
- `Workspace` type + `workspaceSchema` (Zod) — `{ id, name, createdAt, metadata? }`.
- `WorkspaceMember` type + `workspaceMemberSchema` (Zod) — `{ userId, workspaceId, role, joinedAt }`.
- `TenantContext` type + `tenantContextSchema` (Zod) — `{ workspaceId, userId, roles[] }`.
- `ScopeViolationError` class — `code: "SCOPE_VIOLATION"`, payload `{ requestedTenantId, contextTenantId, reason }`. Canonical cross-tenant isolation signal — translate to 403 or MCP permission-denied.
- `getEffectiveTenantId(ctx, args)` — multi-tenant isolation guard. Throws `ScopeViolationError` when `args.workspaceId !== ctx.workspaceId`; returns `ctx.workspaceId` on match.
- `resolveBearer(token)` — async decode of `base64(JSON({ userId, workspaceId, roles[] }))` into `BearerPayload`. Validates via Zod; throws on any shape or decode failure. Consistent error-throw contract with `validateMasterBearer`.
- `BearerPayload` type (inferred from Zod schema).
- `ScopeViolationPayload` interface.
- New subpath export: `@vantageos/cloud-identity/tenancy-domain`.
- `zod` added as a production dependency (schema validation for domain types).

### Notes

- All new symbols are also re-exported from the main `@vantageos/cloud-identity` entry point.
- `resolveBearer` uses base64-JSON as a lightweight default token format. Production callers can replace the decode mechanism without changing the API surface (same `BearerPayload` return type).
- `getEffectiveTenantId` reuses `TenantContext` (sourced from `resolveBearer`) as the trusted bearer-derived identity — mirrors `validateMasterBearer` semantics for master scope.

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
