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
// A host-verified identity (e.g. Convex `ctx.auth.getUserIdentity()`) -> its tenant
export { requireTenantFromIdentity } from "./tenant-from-identity.js";
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
export {
  resolveClerkSessionFromRequest,
  resumeAuthorizeFromRequest,
} from "./clerk-handshake.js";
export type {
  ClerkSessionFromRequest,
  ClerkSessionFromRequestOptions,
  ResumeFromRequestOutcome,
} from "./clerk-handshake.js";

// 0.20.0 — the standing of a resolved org scope: one reading of "isMaster".
export {
  scopeStanding,
  hasFleetRead,
  requireStanding,
  requireFleetStanding,
  // 0.20.1 — the service account apart from the internal opt-in; a verified bearer context.
  isServiceAccountScope,
  requireServiceAccountStanding,
  bearerStanding,
} from "./scope-standing.js";
export type {
  ScopeStanding,
  StandingScope,
  BearerStanding,
  StandingBearer,
} from "./scope-standing.js";

// 0.20.0 — one entry from verified claims to org + person + role + admin.
export {
  resolveCallerFromClaims,
  readOrgRoleClaim,
  claimsAnOrganisation,
} from "./caller-from-claims.js";
export type {
  CallerFromClaimsDeps,
  CallerFromClaimsOptions,
  CallerFromClaimsResult,
} from "./caller-from-claims.js";
// An agent bound by ID to its human owner: the agent twin of the entry above.
export { resolveCallerFromAgentCredential } from "./agent-caller.js";
export type {
  AgentCallerCredential,
  AgentCallerDeps,
  AgentCallerOptions,
  AgentCallerResult,
} from "./agent-caller.js";
// Person scope inside an organisation: after organisation isolation
// (`filterTargetsBelongingTo`), keep the rows whose scope key is in the scope
// the person presents. Who sees which keys is the consumer's data.
export { filterTargetsInPersonScope } from "./person-scope.js";
export type {
  PersonScope,
  PersonScopeDeps,
  PersonScopeOptions,
  PersonScopeResult,
} from "./person-scope.js";
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
// 0.12.0 — assertOrgAdmin: the org-admin proof on a principal resolved by ID.
export {
  actingCredentialSchema,
  principalRowSchema,
  organisationRowSchema,
  resolveActingPrincipal,
  assertTargetBelongsTo,
  filterTargetsBelongingTo,
  assertOrgAdmin,
  assertPrincipalListed,
  assertAgentOwnedBy,
  assertRecipientAddressable,
  resolveCallerStanding,
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
  FilterTargetsResult,
  AssertOrgAdminOptions,
  AssertOrgAdminResult,
  PrincipalIdList,
  AssertPrincipalListedOptions,
  AssertPrincipalListedResult,
  AssertAgentOwnedByOptions,
  AssertAgentOwnedByResult,
  RecipientIds,
  RecipientLookups,
  AssertRecipientAddressableOptions,
  AssertRecipientAddressableResult,
  CallerCredential,
  AssertCallerStandingOptions,
  CallerStanding,
} from "./principal-by-id.js";

// 0.15.0 — Resource-server primitives: RFC 9728 protected resource metadata,
// the RFC 6750 401 challenge, issuer discovery URLs and MCP access-token
// verification bound to this resource. Replaces the standalone resource-server
// package; one identity layer.
export {
  buildProtectedResourceMetadata,
  unauthorizedChallenge,
  deriveClerkDiscoveryUrls,
  verifyMcpAccessToken,
} from "./resource-server.js";
export type {
  ProtectedResourceMetadataConfig,
  ProtectedResourceMetadata,
  UnauthorizedChallengeConfig,
  UnauthorizedChallenge,
  ClerkDiscoveryUrls,
  McpResourceServerConfig,
  VerifyMcpAccessTokenResult,
} from "./resource-server.js";

// 0.16.0 — An organisation is its permanent ID: the credential's org_id claim to
// the org's mapping row, the ID comparisons and the operator org. Labels
// (slugs) never select or prove an org; no option turns that on. The
// label-to-ID derivation is exported only as
// `resolveOrgIdForLabelBackfillOnly`, for a one-off backfill, and as
// `resolveProvisioningLabel` (0.20.0), the one boundary where an operator's
// provisioning input names an organisation by label.
export {
  sameOrg,
  isFleetStamp,
  sameTenantStamp,
  resolveOrgFromClaim,
  resolveOrgIdForLabelBackfillOnly,
  resolveProvisioningLabel,
  findOperatorOrg,
  orgMappingRowSchema,
} from "./org-by-id.js";
export type {
  OrgRef,
  OrgMappingRow,
  OrgMappingLookups,
  ResolvedOrg,
  ResolveOrgFromClaimOptions,
  ResolveOrgFromClaimResult,
  OrgIdAbsence,
  OrgIdAbsenceReason,
  OrgIdResolution,
  ProvisioningLabelResult,
  OperatorOrgLookups,
  FindOperatorOrgOptions,
  OperatorOrgResult,
} from "./org-by-id.js";

// 0.18.0 — Session to tenant: `{ principal, orgId }` from a verified access token,
// built on `verifyMcpAccessToken`, or a typed refusal. A downstream server never
// reads a raw claim.
export { resolveTenantFromAccessToken } from "./tenant-from-token.js";
export type {
  TokenPrincipal,
  ResolveTenantFromAccessTokenResult,
} from "./tenant-from-token.js";
