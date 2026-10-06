# Changelog

All notable changes to `@vantageos/cloud-identity` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.11.0]

**Additive — the acting principal by ID, and the target checked by ID
(`./principal-by-id`).** An actor and a target are identified by their stored
IDs; a name is a display label and never selects or authorises a row. Motivating
incident: an agent of one organisation, calling by name through the service
account, landed on another organisation's same-named agent's task at ten task
doors, because admission compared names. No existing function changes behaviour.

### Added

- `resolveActingPrincipal(credential, lookups, door?)`: a verified credential
  (agent bearer, person token, or the service account acting as itself or for
  an agent named BY ID within its own organisation) to `{ principalId, orgId,
  kind, viaServiceAccountId? }` read from stored rows, or a typed refusal.
  Strict credential schemas: a credential carrying a name field is refused
  whole. Missing or throwing lookups, misses, malformed, inactive, unstamped
  and wrong-organisation rows, and inactive organisations all refuse.
- `assertTargetBelongsTo(principal, target, lookups, opts?)` (async):
  compares the target's stored `orgId` (and `ownerId` with `ownerOnly`) with
  the resolved IDs. An unstamped target is refused to every principal, the
  fleet principal included: no right is inferred from an absence, and a fleet
  row carries the operator organisation's ID explicitly.
- The fleet is the OPERATOR ORGANISATION, decided from data by the adapter
  method `orgKindOf(orgId) => "operator" | "client" | null` on
  `PrincipalLookups` (and `OrgKindLookups` for `assertTargetBelongsTo`). `null`,
  a miss or any other answer is not the fleet; a missing or throwing adapter
  refuses. An operator-organisation row is refused to every client; the
  fleet principal reaches a client organisation's row only with
  `fleetCrossOrg: true` and only when the adapter reports it as `"client"`.
- RULING 5: membership of the operator organisation is ordinary membership.
  Its agents and persons resolve as `kind: "agent"` / `"person"` of that
  organisation and reach its rows only; cross-organisation reach (`kind:
  "fleet"` + `fleetCrossOrg`) belongs to its service account alone, and
  `reserved-fleet-scope` refuses a claim of that scope (a `kind: "fleet"`
  credential, or `fleetCrossOrg` used by any other principal), never plain
  membership.
  The operator organisation is checked by `organisationById` like any other.
- `FLEET_SCOPE_ORG_ID` (a reserved `"vantageos:fleet"` constant, merged on
  `main` but never published) is REMOVED before release, with no alias (RULING
  4). A row stamped with that literal is an unknown organisation and is refused
  to every caller.
- `actingCredentialSchema`, `principalRowSchema`, `organisationRowSchema` and
  the types `ActingCredential`, `PrincipalRow`, `OrganisationRow`,
  `PrincipalLookups`, `OrgKind`, `OrgKindLookups`, `ActingPrincipalKind`,
  `ActingPrincipal`,
  `ResolveActingPrincipalResult`, `TargetIds`, `AssertTargetOptions`,
  `AssertTargetResult`.
- New `IdentityRefusalReason` values: `credential-invalid`,
  `principal-lookup-failed`, `principal-not-found`, `principal-record-invalid`,
  `principal-inactive`, `organisation-not-active`, `reserved-fleet-scope`,
  `acting-agent-other-organisation`, `target-unstamped`,
  `target-other-organisation`, `target-owner-mismatch`.
- New subpath export `./principal-by-id`.
- A test that reads the exported signatures with the TypeScript checker and
  fails if any identity input of this module is spelled like a name.

### Deprecated

- `resolvePersonActingName` (0.9.0). It takes names (`claimedName`,
  `agentCredential.agentName`) as identity input; backend standard R-53
  clause 4 makes it non-conforming for any new door. Use
  `resolveActingPrincipal` and `assertTargetBelongsTo`. Behaviour unchanged;
  removal is a major change, made only after consumers migrate off it.
- `passesScopeFilter`, `scopeFilterGet` and `scopeFilterList` (the last two
  through the first). A `createdBy` name matched against `fromAllowList`
  selects the row; backend standard R-53 clause 1 forbids it. Use
  `resolveActingPrincipal` and `assertTargetBelongsTo`. Behaviour unchanged;
  they stay exported until consumers migrate off them.
- The name-input test now covers every callable export of the package root: a
  new export taking a name-like identity input fails. The deprecated legacy
  exceptions are exactly `resolvePersonActingName`, `passesScopeFilter`,
  `scopeFilterGet` and `scopeFilterList`, and the test fails if any of them
  loses its `@deprecated Since 0.11.0` tag. The scan reads a generic input
  through its constraint, so a name field behind `T extends ScopeFilterable`
  is seen. Two 0.10.0 exports that carry a name-like field without selecting a
  row by it (`isPersonActorName`: `name`; `checkPersonCallShape`:
  `actingName`, accepted only to be refused) are pinned in a frozen map that
  can only shrink.

### Migration (required consumer step)

- Before switching a door to `assertTargetBelongsTo`, stamp every existing row
  that has no `orgId` with its real organisation ID or with the operator
  organisation's ID, and supply `orgKindOf` reading the stored `orgKind`. Unstamped rows are refused to every caller, so a door
  switched before the backfill stops serving them.

## [0.10.0]

**Additive — identity gaps a consumer had are now in the package.** Every
consumer adapts these; none copies them. No existing function changes behaviour.

### Added

- `resolveMinRole` / `assertMinRole`: minimum-role check over an order the
  caller supplies as data. Unknown role, unknown minimum, invalid order refuse.
- `mapRoleClaim`: claim to role through caller data, with a fallback that must
  be explicit. Absent or unmapped claim without a fallback refuses.
- `resolveMembership` (injected async lookup; error, miss, inactive, malformed
  and other-organisation all refuse), `isRowInTenant` (strict equality,
  unstamped row refused), `membershipRecordSchema`.
- `requireOrgAdmin`: the proof is bound to the caller's verified organisation.
- `assertNamespaceWrite` and the shared boundary rule `namespaceMatchesPrefix`
  (now also used by the read filter, same behaviour).
- `timingSafeEqualSync` / `assertSecretSync`: synchronous constant-time
  comparison; an unset expected secret matches nothing.
- `IdentityRefusalError` and the `IdentityRefusal` types.
- New subpath exports `./identity-refusal`, `./role-policy`,
  `./tenant-membership`, `./namespace-write`, `./secret-compare-sync`.

## [0.9.1]

### Fixed

- `resolveWriterRole` / `requireWriterRole`: an absent `writerRoles` list (a
  consumer that failed to load it) now returns the typed `role-not-writer`
  refusal instead of throwing a `TypeError`. It already granted nothing; the
  refusal now carries its code, as the JSDoc and test promised. Found by the
  reviewer of #15.

## [0.9.0]

**Additive — the person principal (`./person-principal`).** The decisions a
server needs to serve a signed-in person in its own name, extracted from the
first consumer so that every other one wires them the same way.

### Added

- `resolvePersonPrincipal`: a presented token's record -> `{ subject, orgSlug,
  orgRole?, actor }`, or a typed refusal (not live, not a person's, no
  organisation, organisation inactive or unmapped). Only the token's own
  organisation is ever looked up.
- `resolvePersonActingName` / `checkPersonCallShape`: the own-name rule. The
  acting identity comes from the principal; another user's name and an agent's
  name without that agent's credential are refused.
- `resolvePersonTenantAccess`: strict organisation equality; unstamped refused.
- `resolveWriterRole` / `requireWriterRole`: writer-role assertion, fail closed.
- `PERSON_ACTOR_PREFIX`, `personActorName`, `isPersonActorName`,
  `personTokenRecordSchema`, `PersonRefusalError` and the refusal types.
- New subpath export `./person-principal`.

## [0.8.0]

**Additive — authorize a PERSON and bind an organisation (0.8.0).**
A connector's `/authorize` that auto-approves with no user authentication, and
derives the code's user from a client-registration profile, makes every client
an anonymous app. This release is the flow that replaces it: Clerk session,
verified organisation membership, a code bound to both, and an exchange that
re-derives nothing from the client's profile.

### Added

- `startAuthorize` / `resumeAuthorize` (`src/authorize-flow.ts`): request
  validation (exact `redirect_uri`, PKCE challenge required, allowed `resource`,
  supported scopes); no Clerk session -> redirect to sign-in with an
  HMAC-signed, short-lived state blob and no code; verified session -> one
  organisation auto-picked, several -> an `OrgPickerModel`, a posted `orgId`
  honoured only if it is in the user's own membership list; `requireConsent`
  (default ON; opt out explicitly for first-party clients only). The code is single-use, short-lived and stored as a digest
  through a consumer-supplied `AuthorizationCodeStore` whose `consume` must be
  atomic.
- `exchangeAuthorizationCode` (`src/token-exchange.ts`): consumes the code
  first, then checks expiry, client, `redirect_uri`, `resource` and the PKCE
  verifier; returns `{ sub, org_id, org_slug, org_role, aud, client_id, scope }`.
- `verifyClerkSessionToken` (`src/clerk-session.ts`): RS256 against a
  consumer-supplied key set; issuer, expiry, `nbf`, optional audience and
  authorized parties.
- `buildDiscoveryDocument`, `buildUserInfo` (`src/oidc.ts`). The document
  advertises only what is implemented (no id_token alg, no refresh grant, no
  client-auth methods).
- `AuthorizeRefusal` / `AuthorizeRefusalReason` (`{ code: "AUTHORIZE_REFUSED",
  reason }`), `oauthErrorFor`, `pkceChallengeFromVerifier`, and the types listed
  in the README section "Authorize a person and bind an organisation".
- Subpath exports `/authorize`, `/token-exchange`, `/clerk-session`, `/oidc`.

### Security

- Consent is bound to a server-issued `consentToken` (HMAC over state, user and
  organisation set). `approved: true` without a token valid for that state and
  that session's user is refused with `consent-required`; a client can no
  longer mint its own state and approve on a victim's behalf.

### Changed

- README: the "does not verify a signed JWT" limit now names the one exception.
- `package.json` version set to 0.8.0 (proposed; not published).

### Unchanged

- Every existing export keeps its behaviour and signature; no existing test
  was edited. No new runtime dependency (Web Crypto only).

## [0.7.0]

**Additive — resolution of a PRESENTED, non-master bearer.** The published
0.5.0 surface covered the master credential (`validateMasterBearer`) and a
decoder that verifies nothing and says so (`decodeUnverifiedBearer`). Between
them there was no function taking a presented non-master bearer, hashing it,
looking the row up and returning a resolved identity or a typed refusal — so a
consuming product wrote that primitive locally, against an untyped client, with
the lookup failure swallowed into `null`. That is a second authority answering
"who is calling". This release is the single one, so the local variant can be
deleted rather than duplicated.

**Version number.** This entry takes `0.7.0`, not `0.6.0`. An unmerged branch
already claims `0.6.0` for `resolveTenantIdOrAbsent` (the non-throwing sibling
of `requireTenantId`); leaving `0.6.0` to it means these two can land in either
order without either having to be renumbered after review.

### Added

- `validatePresentedBearer(authHeader, deps)` (`src/presented-bearer.ts`) —
  parses the header, hashes the token to a SHA-256 hex digest, obtains the row
  through the caller-supplied `deps.lookupBySecretHash(digest)`, re-compares the
  row's stored digest with `timingSafeEqual`, then honours row shape, revocation
  and expiry. The package cannot query a datastore, so the read is injected; every
  decision stays in the package. `deps.now` is an injectable clock.
  - **The callback receives the DIGEST, never the token**, keeping a usable
    secret out of a consumer's query and out of its query logs.
  - **An unknown digest, a revoked row, an expired row, a row of invalid shape
    and a row whose stored digest does not match all return ONE shared frozen
    value**, `{ ok: false, error: "mismatch" }` — one object rather than five
    equal literals, so the branches cannot drift apart by an added field. A
    prober cannot learn whether a token was ever real. `deps.onRefusal` reports
    the internal distinction (`PresentedBearerInternalReason`) to the consumer's
    own logs; a throwing sink cannot change the outcome.
  - **A lookup that throws is a REFUSAL** (`error: "unavailable"`), deliberately
    outside the collapsed bucket so a datastore outage can be answered 503
    rather than reported to every caller as a bad credential. No branch grants
    anything on a lookup failure.
  - Header vocabulary is `validateMasterBearer`'s, unchanged: `"missing"`,
    `"malformed"`, `"mismatch"`. A malformed header costs no datastore read.
- `requireAgentScopedIdentity(identity)` — the second, mandatory call for a
  per-agent surface. An organization-wide token (a row with no agent identity)
  resolves successfully and carries its agent as an EXPLICIT absence
  (`AgentPresence`, a union that must be narrowed — not a nullable field a
  caller can fail to check). The per-agent form `AgentScopedIdentity` carries a
  module-private type brand, so it cannot be constructed outside the package: a
  handler typed against it is reachable only through this function. Its refusal
  is distinguishable from a bad credential on purpose — 403, not 401.
- `sha256Hex(input)` (`src/crypto.ts`) — lower-case hex SHA-256 of a string,
  exported so the code WRITING a token row derives the digest exactly as the
  resolver recomputes it.
- `storedBearerRowSchema` + `StoredBearerRow`, `AgentPresence`,
  `ResolvedBearerIdentity`, `AgentScopedIdentity`,
  `ValidatePresentedBearerResult`, `RequireAgentScopedResult`,
  `PresentedBearerDeps`, `PresentedBearerInternalReason`.
- Subpath export `@vantageos/cloud-identity/presented-bearer`.

### Changed

- Documentation only: `decodeUnverifiedBearer`'s security banner said the
  production trust boundary was "not yet exported by this package". For an
  opaque token it now is, and the banner names it. No behaviour change.

### Unchanged

- **Every existing export keeps its exact behaviour and signature.** The new
  module is a new file; the only edits to existing sources are one appended
  function in `src/crypto.ts`, new export lines in `src/index.ts`, and the
  docstring above. No existing test was edited.

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
