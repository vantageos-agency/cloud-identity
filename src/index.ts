/**
 * @vantageos/cloud-identity — public surface.
 *
 * Framework-agnostic identity + scope-filter primitives for VantagePeers Cloud
 * (multi-tenant MCP). Consumed by `vantage-peers-mcp` and
 * `@vantageos/vantage-crm-mcp`.
 */

export { timingSafeEqual } from "./crypto.js";
export {
  passesScopeFilter,
  scopeFilterList,
  scopeFilterGet,
  isMasterScope,
  isWildcardScope,
  LEGACY_WILDCARD_CTX,
  type ScopeFilterable,
} from "./scope-filter.js";
export { validateMasterBearer } from "./bearer-validation.js";
export type {
  OAuthCtx,
  ScopeProfile,
  NamespacePrefix,
  FromAllowListEntry,
  ValidateMasterBearerResult,
} from "./types.js";

// 0.2.0 — Domain-tenancy layer (additive)
export {
  workspaceSchema,
  workspaceMemberSchema,
  workspaceRoleSchema,
  tenantContextSchema,
  ScopeViolationError,
  getEffectiveTenantId,
  decodeUnverifiedBearer,
} from "./tenancy-domain.js";
export type {
  Workspace,
  WorkspaceMember,
  WorkspaceRole,
  TenantContext,
  ScopeViolationPayload,
  BearerPayload,
} from "./tenancy-domain.js";

// 0.3.0 — Organization-membership guard (unified session + bearer contract)
export { requireTenantId } from "./org-guard.js";
export type { SessionIdentity, TenantSource } from "./org-guard.js";
