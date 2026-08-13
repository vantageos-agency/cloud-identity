/**
 * @vantageos/cloud-identity — public surface.
 *
 * Framework-agnostic building blocks for multi-tenant authorization:
 * tenant resolution, membership requirement, row filtering and bearer
 * validation.
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

// Organization-membership guard (unified session + bearer + self-host contract)
export { requireTenantId } from "./org-guard.js";
export type {
  SessionIdentity,
  TenantSource,
  DeploymentMode,
} from "./org-guard.js";

// 0.4.0 — Human-path resolver (Clerk-shaped session -> { tenant, subject, role })
export { humanAccountRoleSchema, resolveHumanIdentity } from "./human-path.js";
export type {
  HumanAccountRole,
  ClerkSessionLike,
  ResolvedHumanIdentity,
} from "./human-path.js";
