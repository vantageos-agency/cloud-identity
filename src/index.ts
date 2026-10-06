/**
 * @vantageos/cloud-identity — public surface.
 *
 * Framework-agnostic building blocks for multi-tenant authorization:
 * tenant resolution, membership requirement, row filtering and bearer
 * validation.
 */

export { timingSafeEqual, sha256Hex } from "./crypto.js";
export {
  passesScopeFilter,
  scopeFilterList,
  scopeFilterGet,
  isMasterScope,
  isWildcardScope,
  namespaceMatchesPrefix,
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
export { requireTenantId, resolveTenantIdOrAbsent } from "./org-guard.js";
export type {
  TenantAbsence,
  TenantAbsenceReason,
  TenantResolution,
  SessionIdentity,
  TenantSource,
  DeploymentMode,
} from "./org-guard.js";

// 0.4.0 — Human-path resolver (Clerk-shaped session -> { tenant, subject, role })
export {
  humanAccountRoleSchema,
  normalizeVerifiedHumanSession,
  requireHumanRole,
  resolveHumanRoleOrRefusal,
} from "./human-path.js";
export type {
  RequiredHumanRole,
  RoleRefusal,
  RoleRefusalReason,
  RoleResolution,
  HumanAccountRole,
  ClerkSessionLike,
  ResolvedHumanIdentity,
} from "./human-path.js";

// Presented-bearer resolution — the opaque-token trust boundary for a
// NON-MASTER credential. The package's single answer to "who is calling"
// for a presented bearer; consumers must not keep a local variant.
export {
  validatePresentedBearer,
  requireAgentScopedIdentity,
  storedBearerRowSchema,
} from "./presented-bearer.js";
export type {
  StoredBearerRow,
  AgentPresence,
  ResolvedBearerIdentity,
  AgentScopedIdentity,
  ValidatePresentedBearerResult,
  RequireAgentScopedResult,
  PresentedBearerDeps,
  PresentedBearerInternalReason,
} from "./presented-bearer.js";

// 0.8.0 — Authorize a PERSON: Clerk session -> verified organisation -> a code
// bound to both; the exchange that redeems it; the OIDC documents.
export {
  startAuthorize,
  resumeAuthorize,
} from "./authorize-flow.js";
export type {
  AuthorizeClient,
  ClerkOrgMembership,
  AuthorizationCodeRecord,
  AuthorizationCodeStore,
  ConsumeCodeResult,
  AuthorizeConfig,
  AuthorizeDeps,
  AuthorizeOutcome,
  OrgPickerModel,
  ResumeInput,
} from "./authorize-flow.js";
export { exchangeAuthorizationCode } from "./token-exchange.js";
export type {
  AuthorizedTokenClaims,
  ExchangeInput,
  ExchangeDeps,
  ExchangeResult,
} from "./token-exchange.js";
export { verifyClerkSessionToken } from "./clerk-session.js";
export type {
  ClerkJwk,
  ClerkJwks,
  ClerkSessionVerifierConfig,
  VerifiedClerkSession,
  VerifyClerkSessionResult,
} from "./clerk-session.js";
export { buildDiscoveryDocument, buildUserInfo } from "./oidc.js";
export type {
  DiscoveryConfig,
  DiscoveryDocument,
  DiscoveryResult,
  ClerkUserLike,
  UserInfo,
  UserInfoResult,
} from "./oidc.js";
export { oauthErrorFor, pkceChallengeFromVerifier } from "./authorize-shared.js";
export type {
  AuthorizeRefusal,
  AuthorizeRefusalReason,
} from "./authorize-shared.js";

// 0.9.0 — The person principal: a verified sign-in (person + organisation) as
// pure data, the own-name actor rule, the tenant compare and the writer-role
// assertion. Every consumer wires a person the same way.
export {
  PERSON_ACTOR_PREFIX,
  PersonRefusalError,
  personActorName,
  isPersonActorName,
  personTokenRecordSchema,
  resolvePersonPrincipal,
  resolvePersonActingName,
  checkPersonCallShape,
  resolvePersonTenantAccess,
  resolveWriterRole,
  requireWriterRole,
} from "./person-principal.js";
export type {
  PersonRefusal,
  PersonRefusalCode,
  PersonRefusalReason,
  PersonTokenRecord,
  PersonPrincipal,
  OrganisationState,
  PersonPrincipalDeps,
  PersonPrincipalResult,
  PersonActingNameResult,
  PersonAccessResult,
} from "./person-principal.js";

// 0.10.0 — Identity gaps closed in the package so consumers adapt, never copy.
export { IdentityRefusalError } from "./identity-refusal.js";
export type {
  IdentityRefusal,
  IdentityRefusalCode,
  IdentityRefusalReason,
} from "./identity-refusal.js";
export { resolveMinRole, assertMinRole, mapRoleClaim } from "./role-policy.js";
export type {
  MinRoleInput,
  MinRoleResult,
  MapRoleClaimInput,
  MapRoleClaimResult,
} from "./role-policy.js";
export {
  isRowInTenant,
  resolveMembership,
  requireOrgAdmin,
  membershipRecordSchema,
} from "./tenant-membership.js";
export type {
  MembershipRecord,
  ResolvedMembership,
  ResolveMembershipInput,
  ResolveMembershipResult,
  RequireOrgAdminInput,
} from "./tenant-membership.js";
export { assertNamespaceWrite } from "./namespace-write.js";
export { timingSafeEqualSync, assertSecretSync } from "./secret-compare-sync.js";

// 0.11.0 — The acting principal by ID and the target checked by ID. A name is
// a display label: it never selects a row and never authorises one.
export {
  actingCredentialSchema,
  principalRowSchema,
  organisationRowSchema,
  resolveActingPrincipal,
  assertTargetBelongsTo,
} from "./principal-by-id.js";
export type {
  ActingCredential,
  PrincipalRow,
  OrganisationRow,
  PrincipalLookups,
  OrgKind,
  OrgKindLookups,
  ActingPrincipalKind,
  ActingPrincipal,
  ResolveActingPrincipalResult,
  TargetIds,
  AssertTargetOptions,
  AssertTargetResult,
} from "./principal-by-id.js";
