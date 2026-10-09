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

## Both caller paths, one contract

A right is never granted by an absent argument. `requireTenantId` refuses by
default — a missing session, a missing organization, or a missing
bearer-resolved workspace all throw; there is no branch that falls through to
"full access" when tenant information is absent. The same function resolves
both entry paths a VantagePeers Cloud request can arrive on:

```ts
import {
  requireTenantId,
  decodeUnverifiedBearer,
  type TenantSource,
} from "@vantageos/cloud-identity";

async function resolveTenant(req: {
  session?: { orgId?: string | null } | null;
  bearerToken?: string;
}): Promise<string> {
  const source: TenantSource = req.session
    ? { kind: "session", identity: req.session }
    : {
        // decodeUnverifiedBearer only decodes the shape — verify the token's
        // signature (or look it up against your own store) before trusting
        // any field on the payload. See "What this package does not do".
        kind: "bearer",
        context: await decodeUnverifiedBearer(req.bearerToken!),
      };

  // Throws for BOTH paths if no tenant is attached — never returns a
  // "default" tenant id when one is missing.
  return requireTenantId(source);
}

// Human path: a signed-in user with an active organization.
await resolveTenant({ session: { orgId: "org_abc" } }); // -> "org_abc"

// Machine path: a caller presenting an already-resolved bearer token.
await resolveTenant({ bearerToken: someBase64Token }); // -> the token's workspaceId

// Either path with nothing attached throws instead of granting access.
await resolveTenant({ session: null }); // throws Error("Unauthenticated: no session.")
```

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
  never as a substitute for it.

**Deprecated since 0.11.0 (pointing to `filterTargetsBelongingTo` since 0.13.0): `passesScopeFilter`, `scopeFilterGet` and
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
  `{ fromAllowList, namespaceReadPrefixes, namespaceWritePrefixes, scope? }`.
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

## Authorize a person and bind an organisation

A connector that signs in a PERSON (a Claude or ChatGPT user) must end up with
a token naming that person and one organisation they belong to, never an
anonymous app. Clerk is the identity provider; this package holds the
decisions and takes every collaborator as a parameter.

```ts
// GET /authorize
const out = await startAuthorize(query, clerkSessionToken, cfg, deps);
// GET /authorize/callback (the return from Clerk) and the picker's POST
const out2 = await resumeAuthorize({ state, sessionToken, orgId, approved, consentToken }, cfg, deps);
// POST /token (authorization_code grant)
const res = await exchangeAuthorizationCode(
  { code, codeVerifier, redirectUri, clientId, resource },
  { codeStore },
);
```

- `startAuthorize(params, sessionToken, config, deps)` validates the request
  (registered client, exact `redirect_uri`, a PKCE challenge using the SHA-256
  method, an allowed RFC 8707 `resource`, supported scopes). With no valid Clerk
  session it returns `{ kind: "redirect-to-sign-in", url }` and issues nothing;
  the return URL carries a state blob signed with HMAC (`AuthorizeConfig.stateSecret`,
  at least 32 characters) and valid for 600 seconds by default.
- `resumeAuthorize(input, config, deps)` rebuilds the request ONLY from that
  signed state (a tampered or expired blob is refused), verifies the Clerk
  session token (`verifyClerkSessionToken`: RS256 against the key set the
  consumer supplies, issuer, expiry, optional audience and authorized parties),
  lists the user's organisations through `deps.listMemberships`, and answers
  with an `AuthorizeOutcome`:
  `redirect-to-sign-in`, `org-picker` (an `OrgPickerModel` the consumer renders;
  it lists only the user's own organisations), `redirect-to-client` (the URL
  carrying the code and the client's `state`) or `refused`.
  A posted `orgId` is honoured only if the verified user's own membership list
  contains it.
  Consent is ON by default (`requireConsent` defaults to true). What it
  protects: a code is issued only after the person was SHOWN the picker and
  approved it. The picker's `OrgPickerModel` carries a `consentToken`:
  `HMAC(stateSecret, "consent-v1" NUL state NUL clerkUserId NUL sorted
  organisation ids)`. It is bound to the exact signed state (useless for any
  other request), to the verified user (useless under another session) and to
  the organisation set that user was shown. `resumeAuthorize` with
  `approved: true` refuses with `consent-required` unless the presented
  `consentToken` verifies, compared in constant time, for that state AND the
  session's user. Without this, a client could mint its own state (the sign-in
  redirect hands it one), replay it with a victim's session and
  `approved: true`, and receive a code the victim never saw a screen for.
  The consumer renders `consentToken` as a hidden field of the picker's POST
  form and posts it back as `consentToken`. The token IS the CSRF protection
  for that POST, because a cross-site form cannot know it; do not add a weaker
  substitute and do not accept the POST without it. Also set
  `session.authorizedParties` to your own origin(s) so a Clerk session token
  minted for another application (`azp`) is not accepted here.
  Set `requireConsent: false` explicitly ONLY for first-party clients whose
  redirect URIs you control; exactly one organisation is then auto-picked and
  no token is involved.
- The code is bound to `{ clerkUserId, orgId, orgSlug, orgRole, clientId,
  redirectUri, codeChallenge, resource }`, stored as a digest through the
  consumer's `AuthorizationCodeStore` (`put`, and an ATOMIC `consume`), single
  use, 60 seconds by default. Records are `AuthorizationCodeRecord`; a consume
  answers `ConsumeCodeResult`. `AuthorizeClient`, `ClerkOrgMembership`,
  `AuthorizeDeps`, `ResumeInput` and `ClerkJwk` / `ClerkJwks` /
  `VerifiedClerkSession` / `VerifyClerkSessionResult` /
  `ClerkSessionVerifierConfig` are the shapes the consumer supplies or reads.
- `exchangeAuthorizationCode(input, deps)` consumes the code FIRST (every
  attempt burns it), then checks expiry, client, `redirect_uri`, resource and
  the PKCE verifier (`pkceChallengeFromVerifier` derives a challenge). It
  returns `AuthorizedTokenClaims`:
  `{ sub, org_id, org_slug, org_role, aud, client_id, scope }` (`ExchangeInput`,
  `ExchangeDeps`, `ExchangeResult`). No field comes from a client-registration
  profile.
- `buildDiscoveryDocument(config)` builds the discovery document
  (`DiscoveryConfig`, `DiscoveryDocument`, `DiscoveryResult`); the issuer must
  be https with no query. It advertises only what is implemented: the code
  flow, PKCE, the `authorization_code` grant and UserInfo. It omits
  `id_token_signing_alg_values_supported` (OIDC Discovery lists it as required
  for a provider that issues id_tokens; this package issues none, so that is a
  documented deviation), refresh tokens and client-authentication methods. A
  consumer that implements any of them adds those keys itself. `buildUserInfo(claims, user)` returns `sub`, and
  `email` / `email_verified` when the token carries `email`
  (`ClerkUserLike`, `UserInfo`, `UserInfoResult`).
- Every refusal is `{ code: "AUTHORIZE_REFUSED", reason }`
  (`AuthorizeRefusal`, `AuthorizeRefusalReason`), the same shape as
  `RoleRefusal`. `oauthErrorFor(refusal)` maps it to an OAuth error code and an
  HTTP status (503 for a collaborator that failed, so an outage is not reported
  as a bad credential). A collaborator that throws is always a refusal.

Also exported as subpaths: `/authorize`, `/token-exchange`, `/clerk-session`,
`/oidc`.

Limits, stated: `redirect_uri` matching is exact (no loopback port variation);
the package signs no access token and no id token and issues no refresh token (the consumer mints the token
from the claims); it fetches no key set and calls no Clerk API itself.

## Wiring person sign-in in an MCP server

A person signed in through an OAuth connector reaches your MCP server holding a
bearer you minted for them (see "Authorize a person and bind an organisation").
`@vantageos/cloud-identity/person-principal` turns that bearer's token record
into the person's principal and answers the three questions every write needs.
It is pure: you do the lookups, it decides. A server that serves people (a PDF
inspector, a registry, a CRM) wires it the same way:

```ts
import {
  resolvePersonPrincipal,
  resolvePersonActingName,
  resolvePersonTenantAccess,
  resolveWriterRole,
  type PersonPrincipal,
  type PersonRefusal,
} from "@vantageos/cloud-identity/person-principal";

// 1. Who is calling: the token row you looked up by the bearer's digest.
const who = await resolvePersonPrincipal(
  { principal: row.principal, subject: row.userId, orgSlug: row.orgSlug,
    orgRole: row.orgRole, revokedAt: row.revokedAt, expiresAt: row.expiresAt },
  { now: Date.now(), lookupOrganisation: (slug) => orgTable.get(slug) },
  "my-tool",
);
if (!who.ok) return deny(who.refusal);

// 2. Under what name: the token's, never the argument's.
//    Deprecated since 0.11.0: a new door uses resolveActingPrincipal instead.
const name = resolvePersonActingName({
  principal: who.principal, claimedName: args.createdBy,
  agentCredential: presentedAgent, door: "my-tool",
});
if (!name.ok) return deny(name.refusal);

// 3. Which rows, and may they write.
const inOrg = resolvePersonTenantAccess({
  principal: who.principal, rowOrgId: record.orgId, door: "my-tool" });
const mayWrite = resolveWriterRole({
  role: who.principal.orgRole, writerRoles: writerRolesOfOrg, door: "my-tool",
  orgSlug: who.principal.orgSlug });
```

- `resolvePersonPrincipal(token, deps, door)` refuses a token that is expired,
  revoked, not a person's, bound to no organisation, or bound to an inactive or
  unmapped one. It looks up only the token's own organisation.
- **Deprecated since 0.11.0:** `resolvePersonActingName`. It takes names
  (`claimedName`, `agentCredential.agentName`) as identity input, which backend
  standard R-53 clause 4 makes non-conforming for any new door. Use
  `resolveActingPrincipal` and `assertTargetBelongsTo` (see "The acting
  principal by ID, and the target checked by ID"). Its behaviour is unchanged;
  it will be removed in a major release once consumers have migrated off it.
- `resolvePersonActingName` returns `{ ok: true, actingAs: "person", actor }`
  for no name or the person's own (`user:<subject>`), and refuses another
  user's name (`PERSON_ACTS_AS_ITSELF`) and an agent's name without that
  agent's own credential (`AGENT_CREDENTIAL_REQUIRED`, or
  `AGENT_IDENTITY_MISMATCH` when the credential belongs to another agent).
  `checkPersonCallShape` is the same rule for a backend door that receives a
  person's call already stripped of its name. `PERSON_ACTOR_PREFIX`,
  `personActorName` and `isPersonActorName` spell and reserve the actor name:
  refuse it when someone registers an agent.
- `resolvePersonTenantAccess` is a strict equality on the organisation; an
  unstamped row is refused.
- `resolveWriterRole` / `requireWriterRole` check the verified role against a
  writer allowlist you hold as data. A missing role, a missing list and an
  empty list all refuse. `requireWriterRole` throws `PersonRefusalError`.
- Every refusal is a `PersonRefusal` (`PersonRefusalCode`, `PersonRefusalReason`,
  `door`, `detail`); you choose the transport shape. `personTokenRecordSchema`,
  `PersonTokenRecord`, `PersonPrincipal`, `OrganisationState`,
  `PersonPrincipalDeps`, `PersonPrincipalResult`, `PersonActingNameResult` and
  `PersonAccessResult` are the input and result types.

The module verifies no credential. The token record must come from your own
lookup of the bearer the person presented, never from a request body.

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

## The acting principal by ID, and the target checked by ID (0.11.0)

**Why this exists.** Two organisations each had an agent displayed as `eta`.
An organisation A agent, calling through the shared service account and naming
itself `eta`, completed, updated and deleted organisation B's `eta` task at ten
different task doors. Every door admitted the call by comparing the typed name
with a name stored on the task. The names were equal; the two agents were not.
Nothing compared an ID.

The rule this module carries: **an actor and a target are identified by their
stored IDs. A name is a display label; it never selects a row and never
authorises one.** Resolving the principal and checking the target both happen
here, so a product never writes its own identity layer.

```js
import {
  resolveActingPrincipal,
  assertTargetBelongsTo,
} from "@vantageos/cloud-identity";

// The operator org is DATA: the org whose mapping row says orgKind "operator".
const orgKindOf = async (id) => (await db.orgs.get(id))?.orgKind ?? null;

// 1. Who is acting? IDs from the VERIFIED credential, rows read by ID.
const who = await resolveActingPrincipal(
  { kind: "service", serviceAccountId: "svc_a", actingForAgentId: "agent_a_eta" },
  {
    agentById: (id) => db.agents.get(id),          // -> { id, orgId, active }
    serviceAccountById: (id) => db.services.get(id),
    organisationById: (id) => db.orgs.get(id),     // -> { id, active }
    orgKindOf,                                     // -> "operator" | "client" | null
  },
  "tasks:complete",
);
if (!who.ok) throw toHttpError(who.refusal);       // RBAC_DENIED, typed reason

// 2. Does the target belong to them? Stored IDs against resolved IDs.
const task = await db.tasks.get(taskId);
const may = await assertTargetBelongsTo(
  who.principal,
  { orgId: task.orgId, ownerId: task.ownerId },
  { orgKindOf },
  { ownerOnly: true, door: "tasks:complete" },
);
if (!may.ok) throw toHttpError(may.refusal);
```

Organisation B's `eta` task carries `orgId: "org_b"`; the principal above
resolved to `orgId: "org_a"`. The target check refuses it with
`target-other-organisation`, whatever either agent is called.

**`resolveActingPrincipal(credential, lookups, door?)`** (`./principal-by-id`)

Async. Returns `{ ok: true, principal }` or `{ ok: false, refusal }`
(`ResolveActingPrincipalResult`). The `principal` (`ActingPrincipal`) is
`{ principalId, orgId, kind, viaServiceAccountId?, orgRole? }`, where `kind` is
`"agent" | "person" | "service" | "fleet"` (`ActingPrincipalKind`).

`credential` (`ActingCredential`, validated by `actingCredentialSchema`) is one
of three shapes, every identity field an ID:

- `{ kind: "agent", agentId, verifiedOrgId }` — the machine path: an agent's
  own bearer, already verified by you (for example with
  `validatePresentedBearer`). The agent row's stored `orgId` must equal
  `verifiedOrgId`.
- `{ kind: "person", personId, verifiedOrgId, verifiedOrgRole? }` — the human
  path: a person's token, already verified by you. The person's row in that
  organisation is read by `(personId, verifiedOrgId)`. `verifiedOrgRole`
  (0.12.0, optional) is the role the SAME verified token carries in that
  organisation (Clerk: `org_role`); it is copied onto the principal as
  `orgRole` and read only by `assertOrgAdmin`.
- `{ kind: "service", serviceAccountId, actingForAgentId? }` — the service
  account. Alone it acts as itself (`kind: "service"`, or `kind: "fleet"` if
  `orgKindOf` reports its organisation as `"operator"`). With `actingForAgentId` it acts for that
  agent, named BY ID and resolved within the service account's OWN
  organisation; the principal is the agent, and `viaServiceAccountId` records
  the carrier.

The schemas are strict: a credential carrying any other key (`agentName`,
`callerOrchestrator`, `name`, `assignedTo`) is refused whole with
`credential-invalid`, before any lookup runs.

`lookups` (`PrincipalLookups`) are your indexed reads by ID: `agentById(id)`,
`personById(id, orgId)`, `serviceAccountById(id)` returning a `PrincipalRow`
(`{ id, orgId?, active }`, schema `principalRowSchema`), and
`organisationById(id)` returning an `OrganisationRow` (`{ id, active }`, schema
`organisationRowSchema`), and `orgKindOf(orgId)` returning an `OrgKind`
(`"operator" | "client"`) or `null`. Only the lookups of the presented path
are called; `orgKindOf` is called on every path.
Each row must repeat the ID that was asked for, and `active` is required and
must be `true`.

Refused, each with a typed `IdentityRefusal` reason: a credential that does not
parse; a missing or throwing lookup (its error text is never surfaced); a miss;
a malformed, inactive or unstamped row; a row of another organisation than its
credential; an unmapped or inactive organisation; a service account acting for
an agent of another organisation. Nothing falls back to a default or master
principal.

**`assertTargetBelongsTo(principal, target, lookups, opts?)`** (`./principal-by-id`)

Async. Returns `{ ok: true }` or `{ ok: false, refusal }`
(`AssertTargetResult`). `target` (`TargetIds`) is `{ orgId?, ownerId? }` read
from the STORED row; `lookups` (`OrgKindLookups`) is `{ orgKindOf }`, the same
adapter as above, and is required (a missing or throwing adapter refuses with
`principal-lookup-failed`); `opts` (`AssertTargetOptions`) is
`{ door?, ownerOnly?, fleetCrossOrg? }`. IDs are compared byte for byte.

- The target's `orgId` must equal the principal's `orgId`
  (`target-other-organisation` otherwise).
- `ownerOnly: true` also requires `ownerId` to equal `principalId`; a target
  with no owner is refused (`target-owner-mismatch`).
- A target with no `orgId` is refused (`target-unstamped`) to EVERY
  principal, the fleet principal included, with or without `fleetCrossOrg`.
  No right is inferred from an absence: a row with no organisation is never
  treated as a master row.
- An absent principal, or one with an empty ID, is refused
  (`credential-invalid`).

**`assertOrgAdmin(principal, targetOrgId, opts)`** (`./principal-by-id`, 0.12.0)

Synchronous. Returns `{ ok: true }` or `{ ok: false, refusal }`
(`AssertOrgAdminResult`). `opts` (`AssertOrgAdminOptions`) is
`{ adminRoles, door? }`: `adminRoles` is your list of admin role values exactly
as the verified claim spells them (Clerk: `["org:admin"]`). Decided by ID, no
lookup:

- only a `kind: "person"` principal can be an organisation admin; an agent, a
  service account and the fleet principal are refused
  (`principal-not-a-person`);
- `targetOrgId` must be present (`target-unstamped`) and byte-equal to the
  principal's `orgId` (`target-other-organisation`): an admin of A is not an
  admin of B;
- the principal's `orgRole` must be byte-equal to an entry of `adminRoles`
  (`role-not-admin`): an absent role, a member role, an empty or malformed
  `adminRoles` all refuse. No case folding, no default role;
- an absent principal, or one with an empty ID, is refused
  (`credential-invalid`).

```js
const who = await resolveActingPrincipal(
  { kind: "person", personId: claims.sub, verifiedOrgId: claims.org_id, verifiedOrgRole: claims.org_role },
  lookups,
  "owners:startBinding",
);
if (!who.ok) throw toHttpError(who.refusal);
const admin = assertOrgAdmin(who.principal, who.principal.orgId, {
  adminRoles: ["org:admin"],
  door: "owners:startBinding",
});
if (!admin.ok) throw toHttpError(admin.refusal);
```

**`assertPrincipalListed(principal, list, opts)`** (`./principal-by-id`, 0.13.0)

Synchronous. Returns `{ ok: true }` or `{ ok: false, refusal }`
(`AssertPrincipalListedResult`). `list` is a `PrincipalIdList`,
`{ orgId, principalIds }`, the stored roster of agent IDs; `opts`
(`AssertPrincipalListedOptions`) is `{ door? }`. The single admission check
for "is this caller on that stored list", decided by agent ID only, no lookup:

- the principal's `principalId` must be byte-equal to an entry of
  `principalIds` (`principal-not-listed`). No case folding, no trimming, no
  prefix match, and no name matching anywhere: a name in the list never
  matches, and a principal carrying only a name has no ID
  (`credential-invalid`);
- only a `kind: "agent"` principal is admitted (`principal-not-an-agent`),
  an agent acting through a service account included, judged by its own ID;
- `list.orgId` must be present (`target-unstamped`) and equal the principal's
  `orgId` (`target-other-organisation`);
- an absent list (`list-absent`) and an empty or malformed `principalIds`
  (`list-empty`) refuse;
- there is no wildcard: `"*"` is an ordinary string and admits nobody.

```js
const listed = assertPrincipalListed(who.principal, { orgId: row.orgId, principalIds: row.allowedAgentIds }, {
  door: "tasks:complete",
});
if (!listed.ok) throw toHttpError(listed.refusal);
```

**`assertRecipientAddressable(sender, recipient, lookups, opts)`** (`./principal-by-id`, 0.13.0)

Async. Returns `{ ok: true }` or `{ ok: false, refusal }`. `recipient` is
`{ agentId, orgId }`; `lookups` is `{ orgKindOf, rosterOf }` where
`rosterOf(orgId)` returns the stored `{ orgId, principalIds }` roster of that
client organisation; `opts` is `{ door? }`. Decided by agent ID only:

- same organisation: admitted;
- client sender to operator recipient: the recipient's ID must be on the
  SENDER organisation's roster;
- operator sender to client recipient: the sender's ID must be on the
  RECIPIENT organisation's roster;
- client to client across organisations, a missing sender or recipient, a
  sender that is not an agent, an unknown organisation kind and an
  unresolvable roster all refuse. A name never matches. Types: `RecipientIds`,
`RecipientLookups`, `AssertRecipientAddressableOptions`,
`AssertRecipientAddressableResult`.

```js
const may = await assertRecipientAddressable(who.principal, { agentId: to.id, orgId: to.orgId }, {
  orgKindOf, rosterOf,
}, { door: "send_message" });
if (!may.ok) throw toHttpError(may.refusal);
```

**`filterTargetsBelongingTo(principal, rows, lookups, opts)`** (`./principal-by-id`, 0.13.0)

Async. The ID-keyed replacement for `scopeFilterList`. Returns
`{ ok: true, rows }` (the rows `assertTargetBelongsTo` admits, in input order)
or `{ ok: false, refusal }`. `lookups` and `opts` are those of
`assertTargetBelongsTo`. Type: `FilterTargetsResult`.

- an absent or unresolved principal is a refusal naming the door, even for an
  empty list; it is never `{ ok: true, rows: [] }`;
- a resolved principal whose rows all belong elsewhere gets
  `{ ok: true, rows: [] }`, so a refusal is distinguishable from an absence;
- rows of other organisations, unstamped rows and a same-NAME row of another
  organisation are dropped; a name never decides;
- a lookup failure is a refusal of the whole call, never a silent drop.

```js
const out = await filterTargetsBelongingTo(who.principal, rows, { orgKindOf }, { door: "tasks:list" });
if (!out.ok) throw toHttpError(out.refusal);
return out.rows;
```

**The fleet is the operator organisation.** The fleet is not a reserved ID: it
is the organisation your `orgKindOf` adapter reports as `"operator"` (for
example the organisation whose mapping row carries `orgKind: "operator"`),
read from your data at run time. The package spells no organisation ID. An
adapter answering `null`, a miss, or anything other than exactly
`"operator"` means "not the fleet"; a missing or throwing adapter refuses.

**RULING 5: membership of the operator organisation is ordinary membership.**
Its agents and persons resolve as `kind: "agent"` / `"person"` of that
organisation and reach its rows only; cross-organisation reach (`kind: "fleet"`
with `fleetCrossOrg`) belongs to the operator organisation's service account
alone, and `reserved-fleet-scope` refuses a CLAIM of that scope, never plain
membership:

- an agent or person credential verified for the operator organisation
  resolves as an ordinary principal of it, with no cross-organisation reach;
  only a service account stamped with it resolves to `kind: "fleet"`;
- a credential carrying `kind: "fleet"` is refused (`reserved-fleet-scope`),
  whoever presents it;
- any non-fleet principal reaching another organisation's row under
  `fleetCrossOrg: true` is refused (`reserved-fleet-scope`); without it,
  `target-other-organisation`;
- an operator-organisation row is refused to every client principal, with or
  without `fleetCrossOrg` (`reserved-fleet-scope`);
- a `kind: "fleet"` principal whose organisation the adapter does not report
  as `"operator"` is refused, and so is a `kind: "service"` principal in the
  operator organisation (its service account is the fleet);
- the fleet principal reaches a CLIENT organisation's row only when the door
  passes `fleetCrossOrg: true` (a master export) AND the adapter reports that
  organisation as `"client"`. An unknown organisation is refused;
- the operator organisation is an ordinary stored organisation:
  `organisationById` must return it mapped and active, like any other;
- a fleet row is a row stamped with the operator organisation's ID explicitly.
  A row with no `orgId` is not a fleet row and is refused to the fleet
  principal too.

**Migration (required consumer step).** Before a product switches any door to
`assertTargetBelongsTo`, it must stamp every existing row that has no `orgId`:
with its real organisation ID, or with the operator organisation's ID if it
belongs to the operator's own scope. An unstamped row is refused to every caller,
including the fleet principal, so a door switched before the backfill stops
serving those rows. Run the backfill first, confirm that no unstamped row is
left in the tables the door reads, then switch the door.

`viaServiceAccountId` and `door` are not identity; no function in this module
takes a name as an identity input, and a test reads the exported signatures to
keep it that way.

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

## Upgrading to 0.4.0

**This release is purely additive — nothing you already call changes.** Every
0.3.0 export keeps its exact behaviour; 0.4.0 only adds two primitives, so an
upgrade from 0.3.0 compiles and runs unchanged until you choose to adopt them.

What is new:

- **A named deployment mode.** `requireTenantId` gains a `self-host` source
  alongside `session` and `bearer`. `cloud` is unchanged — an org-less
  identity is still refused. `self-host` is single-tenant and returns the
  tenant you **declare**; it throws when none is configured, never inferring
  one from absence.

  ```js
  import { requireTenantId } from "@vantageos/cloud-identity";

  // cloud (unchanged): refuses when the session has no org
  requireTenantId({ kind: "session", identity });
  // self-host: returns the DECLARED tenant, throws if it is empty
  requireTenantId({ kind: "self-host", tenantId: process.env.TENANT_ID });
  ```

- **A human-path normalizer.** `normalizeVerifiedHumanSession` maps an
  **already-verified** Clerk-shaped session into `{ tenant, subject, role }`
  (`role` ∈ `owner | admin | member | client`).

  ```js
  import { normalizeVerifiedHumanSession } from "@vantageos/cloud-identity";

  // session MUST already be verified upstream, e.g. Clerk auth() server-side:
  const { tenant, subject, role } = normalizeVerifiedHumanSession(session);
  ```

  ⚠️ It **normalizes, it does not authenticate.** Passing an unverified,
  client-controlled object (a `req.body`, a query payload) makes that object
  the trusted source of tenant, subject and role — a privilege escalation.
  Verify the session upstream first; only pass the object your provider
  already verified. (Same discipline as `decodeUnverifiedBearer`.)

Nothing to change on upgrade, nothing removed. Adopt the new primitives when
you need them.

## Upgrading to 0.3.0

**This release changes a default, and it breaks compilation on purpose.**

Before 0.3.0, calling a scope-filter function without an authorization context
returned `true` — no context meant full access. A caller who simply forgot to
pass the context received every row, and no warning. From 0.3.0 the context is
required: omitting it is a type error, and passing `null` or `undefined`
throws.

The breakage is deliberate, and it is the point. A caller that stops compiling
is a caller that has been told. A caller that still compiles and quietly
returns different rows is an incident nobody attributes to the upgrade.

What to do:

- If the call site has a real authorization context, pass it. This is almost
  always the right fix, and the context is usually already in scope.
- If the call site genuinely means "unrestricted", pass the exported constant
  `LEGACY_WILDCARD_CTX` by name. It reproduces the old behaviour exactly. It
  has to be written out, because an intentional bypass belongs in a code review
  and an accidental one should not be possible.

```js
import { scopeFilterList, LEGACY_WILDCARD_CTX } from "@vantageos/cloud-identity";

scopeFilterList(LEGACY_WILDCARD_CTX, rows); // explicit, unrestricted
```

`requireTenantId` is also new in 0.3.0. Nothing existing calls it, so it breaks
nothing.

Version history is in [CHANGELOG.md](./CHANGELOG.md).

## License

FSL-1.1-Apache-2.0. See [LICENSE](./LICENSE).

## Issues

https://github.com/vantageos-agency/cloud-identity/issues
