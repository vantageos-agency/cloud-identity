# Changelog

All notable changes to `@vantageos/cloud-identity` are documented here.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.27.0] - 2026-10-28

Additive: one resolver for the agent a person acts as.

### Added
- `resolvePersonalAgent({ personId, orgId }, { designatedAgents, principalLookups }, { door? })`, tagged `@callerResolver`, and the `./personal-agent` subpath. A verified person acts as the agent that designates them when EXACTLY ONE active agent of the person's organisation does (the agent row stores the person's ID; the consumer injects the by-ID read of those rows). Zero or only inactive designations (`reason` `none` / `inactive`) and more than one active (`ambiguous`) leave the person as the person: `{ ok: true, actingAs: "person", reason }`. An agent of another organisation, or one designating someone else, is neither selected nor counted. The one selected agent is re-read by ID through `resolveActingPrincipal` and returned as `{ ok: true, actingAs: "agent", principal }`. An absent or throwing lookup, a malformed row or an empty ID is a typed refusal (`{ ok: false, refusal }`, never "the person", its text never surfaced). No new refusal reason. `test/personal-agent.test.ts` pins 18 outcomes.

## [0.26.0] - 2026-10-27

Additive: one resolver for an agent write made by the fleet service account.

### Added
- `resolveAgentWriter({ scope, verifiedActor, targetOrgId? }, { principalLookups }, { door? })`, tagged `@callerResolver`, and the `./agent-writer` subpath. It requires the service-account standing (`requireServiceAccountStanding`), a `verifiedActor` of exactly `{ agentId, orgId }`, a claim for the call's target organisation when one is named, and then resolves the agent by ID through `resolveActingPrincipal`. It returns `{ principalId, orgId, kind: "agent" }` or throws `IdentityRefusalError`. It only resolves; the door still writes and compares stored IDs with the resolved IDs. No name takes part, and no new refusal reason is added. `test/agentWrite.test.ts` pins 20 outcomes, including each refusal without a lookup where none is needed.

## [0.25.0] - 2026-10-25

Additive: digest entry points for Convex consumers, and the `./machine-caller` subpath. The raw-token functions are unchanged and keep passing their tests.

### Security
- A raw bearer passed as a Convex function argument leaks: on any argument-validation failure Convex echoes the whole argument object, valid fields included, into the caller's error, and the error is persisted in the deployment log. The docstrings of `resolvePresentedToken`, `resolveConvexMachineCaller` and `ConvexMachineCallerInput` now document the raw-token argument transport as unsafe. Hash at the HTTP boundary with `sha256Hex` and pass the digest.

### Added
- `resolvePresentedDigest(digestHex, deps)`: resolves the SHA-256 hex digest of a presented token. Same result type as `validatePresentedBearer`.
- `resolveConvexMachineCallerFromDigest({ credentialDigest, claimedOrgId }, deps)` and `ConvexMachineCallerDigestInput`. Tagged `@callerResolver`.
- One decision path: the raw-token functions hash and call the same digest decision (lookup, constant-time re-compare, row shape, revocation, expiry). `test/presented-digest.test.ts` pins identical results, refusal reasons and lookup arguments for both paths across nine outcomes.
- Only a 64-character lowercase hex digest is accepted. Anything else returns the same collapsed refusal as a digest matching no row (`mismatch` / `CREDENTIAL_REFUSED` `credential-invalid`), without a lookup. New internal reason `malformed-digest` for `onRefusal` (type-level note: an exhaustive `switch` over `PresentedBearerInternalReason` gains one case).
- `./machine-caller` subpath export. Measured with esbuild, importing `resolveConvexMachineCallerFromDigest`: root 816,088 bytes / 33 `@clerk` modules; `./machine-caller` 760,183 bytes / 0 (`test/machine-caller-subpath.test.ts`). Most of the remaining weight is `zod`, which `storedBearerRowSchema` needs.

## [0.24.0] - 2026-10-25

Additive optionality: neither name list is required any more, so a consumer can remove them and keep only IDs. Every existing test passes unchanged (936/936); 17 new tests pin the new behaviour.

### Changed
- `OAuthCtx.fromAllowList` is optional. An absent list, `null`, or a value that is not an array names nobody: `passesScopeFilter` / `scopeFilterList` / `scopeFilterGet` select no row by `createdBy` or by a declared grant field, and `isMasterScope` / `isWildcardScope` / `assertNamespaceWrite` do not treat the caller as master through it. Before, an absent list threw a `TypeError` inside `isMasterScope`. Namespace read and write prefixes decide exactly as before.
- Master is decided on the declared `scope === "master"`. The `"*"` entry in `fromAllowList` still makes a caller master, now **deprecated**: a consumer can attach a context whose `scope` is a non-master profile and whose list is a stored org roster that holds `"*"`, and dropping the signal would withhold master from it. Declare `scope: "master"` instead; the `"*"` signal is removed in a major release. `isMasterScope({ scope: "tenant", fromAllowList: ["*"] })` stays `true`.
- `orgMappingRowSchema.allowedOrchestrators` is optional. A mapping row without it resolves through `resolveOrgFromClaim` (and parses in `findOperatorOrg`, `resolveOrgIdForLabelBackfillOnly`, `resolveProvisioningLabel`) instead of being refused as `org-mapping-record-invalid`. A present but malformed list still refuses the row.
- `ResolvedOrg.allowedOrchestrators` is optional and deprecated: it is on the resolved org when the row has it, with the same value as before, and absent otherwise. Type-level note for readers: a consumer that assigns it to a required `string[]` needs `?? []` when it upgrades. Runtime output for a row that carries the list is unchanged.

### Added
- `orgMappingRowSchema.allowedAgentIds` (optional, non-empty strings) and `ResolvedOrg.allowedAgentIds`: the mapping row's roster by agent ID, exposed when the row has it (an empty list stays empty). Before, the field was stripped by the schema, so a consumer had to read the row a second time to get it. A present but malformed ID roster refuses the row (`org-mapping-record-invalid`).

### Fixed
- A `fromAllowList` that is a string instead of an array (an untyped caller) is no longer read as names. Before, `"alice".includes("ali")` selected a row whose `createdBy` was `"ali"`, and `"*"` as a string made the caller master. Typed callers cannot produce this shape.

## [0.23.3] - 2026-10-25

Packaging fix. No function changes.

### Added
- `./org-guard` subpath export (`requireTenantId`). Before, `requireTenantId` was reachable only through the root index, which re-exports `clerk-handshake` and so pulls `@clerk/backend` into every bundle that imports it. vantageos-crm measured a Convex bundle growing 724,158 -> 813,936 bytes (33 Clerk modules) from that one import after upgrading from 0.7.0, when the root depended on zod alone. Measured here with esbuild: root import 599,033 bytes / 33 `@clerk` modules; `./org-guard` import 1,065 bytes / 0. The root import is unchanged and keeps working; both paths hand out the same function (`test/org-guard-subpath.test.ts`).

### Changed
- Dev toolchain only: `esbuild` `^0.28.0` declared as a devDependency (it was already present through vite 8; the new test imports it directly). OSV: 0 advisories on 0.28.2.

## [0.23.2] - 2026-10-24

Security patch. One runtime change: the `zod` floor. Nothing else in the published surface changes.

### Security
- Runtime: `zod` floor raised `^4.4.3` → `^4.6.7` (GHSA-mrhx-c7xc-m3w5, memory exhaustion while validating oversized constrained collections; fixed in 4.6.6). A consumer installing the next release can no longer resolve a vulnerable zod through this package.
- Dev toolchain only, nothing published changes: `vitest` `^1.6.0` → `^5.0.5`, `vite` `^8.3.5` added (vitest 5's peer), `@types/node` `^20.11.0` → `^24.19.2` (vitest 5's peer range). This clears tinypool (GHSA-5gmw-xhrv-c9v3, GHSA-85c8-ppgw-ccpr, CRITICAL), vite (GHSA-587h-7wmj-h5pm and 7 others), esbuild, postcss, nanoid and source-map-js from the lockfile.

## [0.23.1]

Additive patch: `membershipPersonLookups` also returns the stored membership role. Existing callers are unaffected: `personById` answers exactly what it did, and the new `lookupMembership` key is extra on the returned object.

### Added
- `membershipPersonLookups(readMembership)` now returns `{ personById, lookupMembership }`. `lookupMembership(personId, orgId)` answers `{ active: true, role, orgId? }` for a live row (the role exactly as stored, `null` when absent from the row), `{ active: false, role: null }` for a tombstoned row, and `null` for an absent one; a throwing read propagates. It has the shape of `AgentLinkLookups["lookupMembership"]`, so a consumer builds the agent link deps from ONE package call, with no membership read of its own: `{ lookupAgent, ...membershipPersonLookups(read), adminRoles }`. Types `StoredMembershipRead`, `MembershipLookupResult`.
  - Why this and not a new function: the consumer already feeds `membershipPersonLookups` one positional closure; a sibling would make it wire the same read twice. The row type gains optional `role` and `orgId` (both optional, so every existing closure still type-checks).
  - A tombstoned row does not surface its stale role: a removed admin carries no role into the decision, and `resolveMembership` refuses an inactive record in any case.
  - `buildAgentLink` and `resolveAgentLink` are unchanged: they already take `lookupMembership`, so the deps this call produces are accepted as they are (spreading the extra `personById` is harmless).

### Fixed
- `IdentityRefusalReason` listed the nine agent-link reasons twice. A duplicate union member is harmless to the compiler; the repeated block is removed, the type is unchanged.

### Verified, no change needed
- The admin role is matched EXACTLY (`adminRoles.includes(role)`): a stored role that merely starts with an admin role string (`"admin-lite"` against `["admin"]`, `"org:adminx"`, `"org:admin "`, `"ORG:ADMIN"`) is refused at build and voids the link at resolve. Pinned by tests that passed on first run, so they guard the behaviour rather than fix it.

## [0.23.0]

Additive: two new functions, one new subpath, nine new refusal reasons. No existing export changes behaviour.

### Added
- Agent link: an explicit, revocable channel that lets ONE agent of an organisation message, or assign a task to, ONE agent of ANOTHER organisation, by ID only. A name stays refused across organisations: no path here accepts one.
  - `buildAgentLink({ fromAgentId, fromOrgId, toAgentId, toOrgId, grantedBy, reason, now }, { lookupAgent, lookupMembership, adminRoles })` (package root and `@vantageos/cloud-identity/agent-link`) validates an activation and returns the row to store, `{ ok: true, link }`, `revokedAt: null`, no expiry. It proves that `grantedBy` is an active member of `toOrgId` whose stored role is in `adminRoles`, that both agents exist, are active and belong to the organisations stated, that the two organisations differ, and that the reason has at least 10 characters.
  - `resolveAgentLink({ fromAgent: { agentId, orgId }, toAgentId, door }, { lookupAgentLink, lookupAgent, lookupMembership, adminRoles, now?, onAgentLink? })` (package root, tagged `@callerResolver`) decides per request. It admits only a stored, non-revoked row for exactly the (`fromAgentId`, `toAgentId`) pair and the caller's organisation, while the target agent is still active in `toOrgId` AND the grantor is still an active admin of `toOrgId`. A grantor who was removed, lost the admin role or whose membership went inactive voids the link, with no write to the row. Every attempt is reported to `onAgentLink`; a throwing sink never changes the outcome. Types `StoredAgentLink`, `AgentLinkLookups`, `BuildAgentLinkInput`, `BuildAgentLinkDeps`, `BuildAgentLinkResult`, `AgentLinkEvent`, `ResolveAgentLinkInput`, `ResolveAgentLinkDeps`, `ResolveAgentLinkResult`.
  - A link is DIRECTIONAL: pi -> victor says nothing about victor -> pi, and does not cover a third agent of the same two organisations.
- New `IdentityRefusalReason` members `agent-link-absent`, `agent-link-revoked`, `agent-link-mismatch`, `agent-link-invalid`, `agent-link-same-organisation`, `agent-link-grantor-not-admin`, `agent-link-grantor-void`, `agent-link-agent-unavailable`, `agent-link-lookup-failed` (all `RBAC_DENIED`).

### How a grant is made
- The grant is made by the TARGET side. The consumer calls `buildAgentLink` with `grantedBy` set to the stored person ID of an admin of the target agent's organisation (`toOrgId`), then stores `built.link`. An admin of the source organisation cannot grant it, and neither can a plain member of the target organisation.
- It takes ONE ROW PER DIRECTION. For two agents to reach each other, `buildAgentLink` is called twice: A -> B granted by an admin of B's organisation, and B -> A granted by an admin of A's organisation.
- Revoke by setting `revokedAt` on the stored row. Re-granting after the grantor left is a new `buildAgentLink` call by a current admin of `toOrgId`.
- Consumers that list resolvers from the `@callerResolver` tag now see `resolveAgentLink` as well.

## [0.22.0]

Additive: one new function and one new subpath. No existing export changes behaviour.

### Added
- `decideActingClaim({ claimed, caller, mode?, door? })` (package root and `@vantageos/cloud-identity/acting-claim`): whether a name a caller typed into a call may be treated as the acting agent, decided on the caller the consumer already resolved BY ID. Returns `{ ok: true, via }` or `{ ok: false, refusal }`. `caller` is one of `agent-credential` (`agentId`, `agentLabel`, `orgSlug`), `seat` (`agentId`, `agentLabel`, `orgId`), `seat-unresolved` (`allowlist`), `master-bearer`, `master-scope`, `org-member`, or `null`.
  - The claim must equal the resolved agent's label for `agent-credential` and `seat`, else `AGENT_IDENTITY_MISMATCH`, in every mode: a typed name never overrides a resolved identity. `master-bearer` is `AGENT_CREDENTIAL_REQUIRED` in every mode. `master-scope` passes. `org-member` and `seat-unresolved` pass only in explicit `"permissive"` mode (`via: "permissive-unattributed"`) or, for `seat-unresolved`, when the allowlist is exactly one real label (not `"*"`, not empty) and the claim equals it (`via: "seat-own-label"`); otherwise `AGENT_CREDENTIAL_REQUIRED`.
  - `mode` is an input. Absent, or any value other than the exact string `"permissive"`, is strict.
  - Refusal codes are the ones the consumer's local check already used: `AGENT_IDENTITY_MISMATCH`, `AGENT_CREDENTIAL_REQUIRED`. The local no-context refusal carried no code, only the text `Forbidden: no authorization context ...`; it is now `RBAC_DENIED` with reason `no-context`. Two further `RBAC_DENIED` refusals are new: `caller-invalid` (an unknown kind, or a resolved agent with an empty ID or label, which would otherwise let an empty claim equal an empty label) and `claim-invalid` (a claim that is not a string). The refusal is the package's `{ code, reason, door, detail }` shape plus `claimed` and `resolved`; the wording of `detail` differs from the consumer's old message strings.
  - The comparison is the package's own (NFC, lowercase, trim; accents are not folded). It was a private helper of the person-principal module and is now one internal module used by both; `resolvePersonActingName` behaves as before.
  - Types `ActingCaller`, `ActingClaimMode`, `ActingClaimInput`, `ActingClaimRefusal`, `ActingClaimRefusalCode`, `ActingClaimRefusalReason`, `ActingClaimResult`, `ActingClaimVia`.

## [0.21.7]

Additive: one new subpath, no change to any existing export.

### Added
- `@vantageos/cloud-identity/authorize-runtime` (subpath only, not re-exported from the root: `renderOrgPicker` takes display labels, which the root's no-name-input surface guard would otherwise count as identity inputs): the runtime glue around `startAuthorize`, `resumeAuthorize` and `exchangeAuthorizationCode`, so a server wiring person sign-in imports it instead of copying it. Every collaborator is injected; nothing reads `process.env`, opens a connection or logs a value.
- `readAuthorizeSettings(env, { requireClerkSecretKey? })`: typed settings from an env object, or `{ ok: false, missing, refusal }` with the NAMES of the absent or unusable variables (a state secret under 32 characters, a URL that does not parse) and a `server-misconfigured` refusal. `AUTHORIZE_ENV`, `DEFAULT_AUTHORIZE_SCOPE`. Types `AuthorizeEnv`, `AuthorizeSettings`, `AuthorizeSettingsResult`, `ReadAuthorizeSettingsOptions`.
- `createClerkJwksSource({ issuer, fetch?, now?, ttlMs? })`: the `session.jwks` function with a per-source cache (default 10 minutes), one shared in-flight fetch, and nothing cached on a failed or malformed answer. Types `JwksFetch`, `ClerkJwksSourceOptions`.
- `codeStoreFrom({ insert, takeOnce })`: adapts the host's storage to `AuthorizationCodeStore`; a consume answer that is not `ok` with a complete record, `unknown` or `already-used` throws (the exchange answers `code-store-unavailable`). `createInMemoryCodeStore()` for tests and a single-instance development server. Type `CodeStoreBackend`.
- `createClerkDirectory(clerk, { pageSize?, maxPages? })`: `listMemberships` (read in full, paged; a Clerk failure or a list that does not end within `maxPages` throws) and `getUser` over a Clerk Backend client the host created. Types `ClerkUsersApi`, `ClerkDirectoryOptions`, `ClerkDirectory`.
- `renderOrgPicker(model, { productName, formAction? })` and `pickerContentSecurityPolicy()`: the escaped, script-free organisation picker and consent page, and the CSP that admits only its one inline style by hash. Type `OrgPickerOptions`.
- `buildAuthorizeRuntime({ settings, lookupClient, listMemberships, codeStore, jwks?, now?, generateCode?, resourcePath?, defaultScope?, supportedScopes? })`: the `{ cfg, deps }` the flow functions take, consent left on. Types `AuthorizeRuntimeOptions`, `AuthorizeRuntime`.

## [0.21.6]

Publish order: 0.21.4, then the open PR #45 (0.21.5), then this one.

### Added
- `verifySvixWebhook({ id, timestamp, signature, rawBody }, { secret, now?, toleranceSeconds? })` (package root): Svix signature verification for Clerk webhooks, Web Crypto HMAC-SHA256 over `${id}.${timestamp}.${rawBody}`, every `v1,<base64>` candidate compared in constant time with no early exit. Returns `{ ok: true }` or `{ ok: false, refusal }`. Types `SvixDelivery`, `VerifySvixWebhookOptions`, `VerifySvixWebhookResult`.
- `clerkMembershipEvent(payload, { svixTimestampSeconds })` (package root): parses an `organizationMembership.created|updated|deleted` payload into `{ ok: true, kind: "upsert" | "delete", orgId, personId, orgSlug?, role, eventAt }`, `{ ok: true, kind: "ignore" }` for any other type, or a typed refusal. A delete is timed `max(data.updated_at, delivery time)`. Types `MembershipEvent`, `ClerkMembershipEventResult`.
- `decideMembershipEvent(existing, event)` (package root): `{ apply, revive }`. A delete is stale only when strictly older (removal wins a tie); an upsert is stale at or before `lastEventAt`; an upsert newer than a tombstone revives. Types `StoredMembershipState`, `DecideMembershipEventResult`.
- `membershipPersonLookups(readMembership)` (package root): the `personById` lookup for `resolveActingPrincipal`, answering `{ id, orgId, active: true }` for a live row and `null` for an absent or tombstoned one.
- `planMembershipReconcile(stored, fromClerk, { at, fullyReadOrgIds })` (package root): `{ upserts, tombstones }`, tombstoning only inside fully read organisations and never touching a row stamped after `at`. Types `MembershipRow`, `ClerkMembershipRow`, `PlanMembershipReconcileOptions`, `MembershipUpsert`, `MembershipTombstone`, `MembershipReconcilePlan`.
- New `IdentityRefusalReason` members `webhook-secret-invalid`, `webhook-headers-missing`, `webhook-timestamp-out-of-window`, `webhook-signature-mismatch`, `membership-event-invalid`.

## [0.21.5]

### Added
- Support access: a time-bounded, audited grant instead of membership. `buildSupportGrant({ personId, orgId, reason, grantedBy, now, durationMs }, { maxDurationMs })` validates an activation (reason of at least 10 characters, `0 < durationMs <= maxDurationMs`, non-empty IDs) and returns the row to store, `revokedAt: null`. `resolveSupportAccess(principal, targetOrgId, { lookupSupportGrant, now?, onSupportAccess? }, { door })` (package root, tagged `@callerResolver`) admits only a `person` principal holding a live, exact (person, organisation) grant; denied by default. Every granted access and every refusal is reported to `onSupportAccess`; a throwing sink never changes the outcome. Types `StoredSupportGrant`, `BuildSupportGrantInput`, `BuildSupportGrantPolicy`, `BuildSupportGrantResult`, `SupportAccessEvent`, `SupportAccessDeps`, `SupportAccessOptions`, `SupportAccessResult`.
- New `IdentityRefusalReason` members `support-grant-absent`, `support-grant-expired`, `support-grant-revoked`, `support-grant-mismatch`, `support-grant-own-organisation`, `support-grant-not-a-person`, `support-grant-invalid`, `support-grant-lookup-failed` (all `RBAC_DENIED`).

## [0.21.4]

### Added
- `resolveConvexMachineCaller({ credential, claimedOrgId }, { door, lookupBySecretHash, now?, onRefusal? })` (package root, tagged `@callerResolver`): resolves a machine credential that a service with no human behind it passes to a Convex function as an ARGUMENT (Convex functions receive no request headers). Returns `{ ok: true, tenantId, agent, scopes }` or `{ ok: false, refusal }`. Empty or non-string credential or claimed organisation refuses `CREDENTIAL_REFUSED` / `credential-invalid` without calling the lookup; unknown, revoked, expired, malformed row and stored-digest mismatch all refuse with the same `CREDENTIAL_REFUSED` / `credential-invalid`; a throwing lookup refuses `RBAC_DENIED` / `principal-lookup-failed`; a valid credential whose row tenant is not the claimed organisation refuses `RBAC_DENIED` / `other-organisation`. No refusal echoes the credential, its digest or the claimed organisation. Types `ConvexMachineCallerInput`, `ConvexMachineCallerDeps`, `ConvexMachineCallerResult`.
- `mintMachineCredential()` (package root): `{ credential, secretHash }`, the credential being `vpmc_` + 32 bytes of `crypto.getRandomValues`, base64url, and `secretHash` its `sha256Hex`. The consumer stores only `secretHash`. Type `MintedMachineCredential`.

### Changed
- `validatePresentedBearer` now delegates everything after the header parse to an internal `resolvePresentedToken(token, deps)` shared with `resolveConvexMachineCaller`. Behaviour unchanged.

## [0.21.3]

### Added
- `requireSubjectFromIdentity(identity, { door })` (package root, tagged `@callerResolver`): the subject of an identity the host has already verified (for a Convex function, `ctx.auth.getUserIdentity()`), for audit stamps such as `createdBy`, so a consumer no longer reads `identity.subject` itself. No identity, or a subject that is not a non-empty string, throws `IdentityRefusalError` `RBAC_DENIED` / `no-verified-subject`.
- New `IdentityRefusalReason` member `no-verified-subject`.

## [0.21.2]

### Added
- `resolveClerkSessionForFormPost(request, { secretKey, publishableKey, authorizedParties?, jwtKey?, expectedOrigin })` (`./clerk-handshake` and the package root; options type `ClerkSessionForFormPostOptions`): the session of a person posting a same-origin form, for the org picker's Approve / Deny. Refuses a request that is not a POST (`not-a-form-post`) or whose `Origin` is not `expectedOrigin` (`cross-origin-post`), then resolves the session with `authenticateRequest` as the GET that served the form, so a production instance's suffixed cookie (`__session_<suffix>`) is read and an expired session token is refreshed from `__refresh_<suffix>` (the returned `Set-Cookie` headers carry the new token). A post that would need a handshake is `signed-out` (`session-needs-handshake`). Measured on a production instance: the session cookie is never named a bare `__session`, and a session token presented after a 70-second wait is refused `session-invalid`; through this function the same post is signed-in.

## [0.21.1]

### Added
- `requireTenantFromIdentity(identity, { door })` (package root, tagged `@callerResolver`): the tenant ID of an identity the host has already verified (for a Convex function, the result of `ctx.auth.getUserIdentity()`, or `null`). The organisation ID claim is read by the package's own claim reader (`org_id`, `organizationId`, `orgId`, Clerk `org_` shape), so a consumer no longer reads `org_id` itself. No identity, no claim, or a claim that is not an organisation ID throws `IdentityRefusalError` `RBAC_DENIED` / `no-verified-organisation`; the refusal never echoes the claim value.

## [0.21.0]

### Added
- An agent bound by ID to its human owner. `ActingCredential` (`kind: "agent"`) gains an optional `ownerPersonId`, taken from the consumer's verified credential row; `PrincipalRow` and `ActingPrincipal` gain an optional `ownerPersonId`. When the credential presents one, `resolveActingPrincipal` requires the agent row's stored owner to be byte-equal (`agent-owner-mismatch`) and `personById(owner, orgId)` to return an active row of the same organisation (`agent-owner-not-member`); an owner lookup that throws or is not supplied refuses `principal-lookup-failed`. The principal carries `ownerPersonId` only when proven. Without `ownerPersonId` the result is unchanged.
- `resolveCallerFromAgentCredential({ agentId, verifiedOrgId, ownerPersonId? }, { orgLookups, principalLookups }, { door })` (package root): organisation by ID, then the agent, then the owner, returning `{ ok: true, org, principal, owner }` (`owner` is a person principal of the same organisation, or `null`) or `{ ok: false, refusal }`. Tagged `@callerResolver`. Types `AgentCallerCredential`, `AgentCallerDeps`, `AgentCallerOptions`, `AgentCallerResult`.
- `assertAgentOwnedBy(principal, personId, { door })` (`./principal-by-id`): admits only an agent principal whose proven owner equals `personId`; everything else refuses `agent-not-owned`. Types `AssertAgentOwnedByOptions`, `AssertAgentOwnedByResult`.
- New `IdentityRefusalReason` members `agent-owner-mismatch`, `agent-owner-not-member`, `agent-not-owned`.
- `./person-scope`: `filterTargetsInPersonScope(principal, rows, deps, opts)` keeps, within the caller's organisation, the rows whose scope key is in the scope the person presents. Organisation isolation is `filterTargetsBelongingTo`, called first; its refusal is returned unchanged. `deps.scopeOf(principal)` returns `{ kind: "keys", keys }` or `{ kind: "all", grantedBy }`; `deps.rowScopeKeys(row)` returns the row's key(s). Keys are compared as exact strings. A row with no key is dropped. Refusals (`RBAC_DENIED`): `person-scope-absent` (no scope presented), `person-scope-empty` (empty key set), `person-scope-grant-unreasoned` (`"all"` without a reason), `person-scope-malformed` (unknown scope form or unreadable row key), `person-scope-lookup-failed` (`scopeOf` or `rowScopeKeys` threw; the error kind is named, never its message). Types `PersonScope`, `PersonScopeDeps`, `PersonScopeOptions`, `PersonScopeResult`.

## [0.20.2]

### Changed
- `requireServiceAccountStanding(scope, door)` returns the literal `"fleet"` instead of `void`, like `requireFleetStanding`. An analyser that classifies a standing gate by its return can now credit a door that calls it. Callers that ignore the return are unaffected.

## [0.20.1]

### Added
- `isServiceAccountScope(scope)` and `requireServiceAccountStanding(scope, door)` (`./scope-standing`): the fleet service account apart from the internal opt-in, which `"fleet"` also covers. The require form throws `RBAC_DENIED` `scope-not-resolved` or `standing-not-allowed`.
- `bearerStanding(context)` (`./scope-standing`): `"service-bearer"`, `"local-trust"`, `"caller"` or `"refused"` for a verified bearer context (`isMaster`, `viaMasterBearer`). Fails closed. Types `BearerStanding`, `StandingBearer`.
- The `@standingGate` JSDoc tag on every standing gate, kept in `dist/*.d.ts`, so an analyser derives the gates from the package.
- `resolveCallerFromClaims` refusals carry `subject` when the claims had a verified one.

### Changed
- README: `requireFleetStanding`'s example no longer says "the fleet's own service only"; it admits the internal opt-in too.

## [0.20.0]

### Added

- `./scope-standing`: `scopeStanding(scope)` reads a RESOLVED org scope (the shape
  an org-scope resolver such as VantagePeers `withOrgScope` returns) as
  `"fleet" | "operator-admin" | "member" | "refused"`; `requireStanding(scope, door, allowed)`
  and `requireFleetStanding(scope, door)` throw `RBAC_DENIED` naming the door
  (`scope-not-resolved` / `standing-not-allowed`); `hasFleetRead(scope)` is the
  reading meaning of `isMaster`. Fail closed: `isMaster`, `fleetWide` and a known
  `masterSource` must agree, otherwise `"refused"`. Types `ScopeStanding`,
  `StandingScope`. New `IdentityRefusalReason` members `scope-not-resolved`,
  `standing-not-allowed`.
- `./caller-from-claims`: `resolveCallerFromClaims(claims, deps, { adminRoles, door })`,
  the one call from a verified claim record to `{ subject, actorName, org, principal,
  role, isOrgAdmin }` or a typed refusal with `claimsOrg`. It chains
  `resolveOrgFromClaim` -> `resolveActingPrincipal` (person) -> `assertOrgAdmin`
  and decides nothing new. Helpers `readOrgRoleClaim`, `claimsAnOrganisation`.
- `resolveProvisioningLabel(label, lookups)` (`./org-by-id`): the one boundary
  where a provisioning label is translated to the permanent org ID —
  `mapped` / `unmapped` / `mapped-without-id` / `unreadable`; an unreadable
  store is never `unmapped`.
- `@callerResolver` JSDoc tag, kept in the published declarations, on the
  caller resolvers (`resolveActingPrincipal`, `resolvePersonPrincipal`,
  `resolveCallerFromClaims`): an analyser derives its accepted sinks for a
  verified identity from the tag instead of a hand-typed list.

## [0.19.1]

### Fixed

- `resolveClerkSessionFromRequest`: a `__clerk_handshake` that does not verify (not a JWT, or
  signed by another key) resolves to `signed-out` with reason `handshake-invalid` and no headers.
  The SDK threw on these forms, so a consumer callback answered 500. Any other SDK error still
  propagates. Measured: a Clerk-signed handshake past its own `exp` is still answered by the SDK
  (its cookies are Clerk-signed; the `__session` among them is verified on its own).

## [0.19.0]

### Added

- `resolveClerkSessionFromRequest(request, { secretKey, publishableKey, authorizedParties?, jwtKey? })`
  (`./clerk-handshake`): resolves the person's Clerk session from the raw
  request with Clerk's own handshake, `@clerk/backend` `authenticateRequest()`
  (no hand-written handshake). Returns `signed-in` (`sessionToken`, `userId`,
  `sessionId`), `handshake` (`status` + the `Location` / `Set-Cookie` headers
  to return as they are) or `signed-out` (`reason`). The return from the
  handshake (`__clerk_handshake`) is also answered as `handshake`: the SDK
  hands back the `__session` cookies and a `Location` that strips the handshake
  parameters, and the next request is plain `signed-in`. On a development instance
  this is what carries the session from the hosted sign-in domain to the app
  host; a return with only `__clerk_db_jwt` used to end in `session-required`.
- `resumeAuthorizeFromRequest(request, input, clerk, cfg, deps)`: the resume
  path fed with the raw request; a `handshake` is returned untouched.
- Dependency: `@clerk/backend` `^3.23.2` (resolved 3.23.2).

### Unchanged

- `resumeAuthorize` / `startAuthorize` keep taking a `sessionToken` string; a
  Bearer or `__session` token remains the signed-in case.

## [0.18.0]

### Added

- `resolveTenantFromAccessToken(authorization, config, nowMs?)`
  (`./tenant-from-token`): the session-to-tenant helper. From an
  `Authorization` header it returns `{ ok: true, principal, orgId }` for a
  VERIFIED access token, or a typed refusal. Built on `verifyMcpAccessToken`
  (no second verifier): a forged, expired, wrong-audience or wrong-issuer
  token never yields a tenant (`401` with the challenge, `503` when the key set
  is unreachable). The org is the `org_id` claim of the verified token; a
  verified token without a usable one is refused `no-verified-organisation`
  (`403`). Lets a downstream server stop reading raw claims. New types
  `ResolveTenantFromAccessTokenResult`, `TokenPrincipal`.

### Security

- Denial path: `resumeAuthorize` with `denied: true` now verifies the
  `consentToken` exactly as the approve path does (same function, same
  `consent-required` refusal) when consent is on. Before, a forged or missing
  consent token on a denial was accepted. **Behaviour change for consumers:**
  the denial POST must carry the picker's `consentToken`, as the approval POST
  already must. With `requireConsent: false` nothing changes.

## [0.17.0]

### Added

- `OrgPickerModel.redirectOrigin`: the origin of the `redirect_uri` that was
  validated against the registered client, for the consent page to display
  (display-only).
- Person denial: `ResumeInput.denied: true`. After the signed state, the
  client and the Clerk session all verify, `resumeAuthorize` returns
  `redirect-to-client` with `error=access_denied` and the client's `state`
  (no `iss`: the consumer appends RFC 9207 `iss` to every `redirect-to-client`
  outcome, success and denial alike). A tampered or
  expired state, an unknown client or a failed session stays a refusal;
  `denied` together with `approved: true` is refused (`invalid-request`).

### Changed

- `prepublishOnly` now runs `npm run build` only; the test suite is not part
  of the publish step.

## [0.16.0]

**Additive: an organisation is its permanent ID (`./org-by-id`).** A consumer
used to keep its own copy of "which org is this credential", "are these two
rows one org", "which org is the operator" and "what is this slug's org ID".
Those decisions are now the package's, keyed on IDs, refusing by default. No
existing function changes behaviour for an existing input.

### Added

- `resolveOrgFromClaim(claims, lookups, { door? })`: a verified
  credential's `org_id` claim to the org's mapping row (roster, scopes, kind).
- `sameOrg`, `isFleetStamp`, `sameTenantStamp`: comparisons over `OrgRef`
  (`{ id?, label? }`). Unstamped is never a match.
- `findOperatorOrg(lookups, { cap? })`: `one | none | many | overCap | unreadable`.
- `resolveOrgIdForLabelBackfillOnly(label, lookups)`: label to permanent ID,
  or a typed `ORG_ID_ABSENT` absence. For the one-off backfill only; it must
  never be called on a request path, and the name says so. (Developed as
  `resolveOrgIdForLabel`; that name was never published.)
- `orgMappingRowSchema` and the types `OrgRef`, `OrgMappingRow`,
  `OrgMappingLookups`, `ResolvedOrg`, `ResolveOrgFromClaimOptions`,
  `ResolveOrgFromClaimResult`, `OrgIdAbsence`, `OrgIdAbsenceReason`,
  `OrgIdResolution`, `OperatorOrgLookups`, `FindOperatorOrgOptions`,
  `OperatorOrgResult`.
- New `IdentityRefusalReason` values: `org-mapping-lookup-failed`,
  `org-mapping-not-found`, `org-mapping-record-invalid`.

### No label resolution

An organisation is never resolved from its label on a request path, and no
option turns that on. A transitional `labelFallback` option was developed and
removed before publication: `sameOrg`, `isFleetStamp`, `sameTenantStamp` and
`resolveOrgFromClaim` compare and select by org ID only, a label-only input
refuses, and the `org-id-contradicts-label` reason and the `source` field of
`ResolvedOrg` went with it. The label adapter is read only by
`resolveOrgIdForLabelBackfillOnly`.

## [0.15.0]

**Additive: resource-server primitives (`./resource-server`).** No existing
function changes behaviour for an existing input. This is the identity layer an
MCP server needs as an OAuth 2.1 protected resource, so a separate
resource-server package is no longer needed.

### Added

- `buildProtectedResourceMetadata(config)`: the RFC 9728 document served at
  `/.well-known/oauth-protected-resource` (`resource`, `authorization_servers`,
  `bearer_methods_supported`, optional `scopes_supported`, `resource_name`,
  `resource_documentation`). Throws on a relative or fragment-bearing resource,
  an empty or relative authorization server list, or empty bearer methods.
- `unauthorizedChallenge(config)`: the `401` status and a `WWW-Authenticate:
  Bearer` value that always carries `resource_metadata` (RFC 9728 section 5.1),
  with optional `error`, `error_description` and `scope` (RFC 6750). Values are
  quoted and escaped; a line break throws.
- `deriveClerkDiscoveryUrls(issuer)`: the OIDC discovery and JWKS URLs of an
  `https` issuer.
- `verifyMcpAccessToken(authorization, config, nowMs?)`: reads the `Authorization`
  header and verifies the token for this resource by delegating to
  `verifyClerkSessionToken` (RS256 only; signature, `iss`, `aud`, `exp`, `nbf`),
  with the audience mandatory. Returns the verified session, or a typed
  `CREDENTIAL_REFUSED` refusal with the `401` envelope (`bearer-missing` and
  `bearer-malformed` answer `invalid_request`; `token-invalid` answers
  `invalid_token`), or `503` with no challenge when the key set is unreachable
  (`jwks-unavailable`). A missing issuer or audience throws.
- Types `ProtectedResourceMetadataConfig`, `ProtectedResourceMetadata`,
  `UnauthorizedChallengeConfig`, `UnauthorizedChallenge`, `ClerkDiscoveryUrls`,
  `McpResourceServerConfig`, `VerifyMcpAccessTokenResult`.
- `IdentityRefusalReason` gains `bearer-missing`, `bearer-malformed`,
  `token-invalid`, `jwks-unavailable`.

### Fixed

- `verifyMcpAccessToken` now validates `audience` as an absolute URL with no
  fragment (RFC 8707 section 2), with the same validator as the `resource` of
  `buildProtectedResourceMetadata`. A whitespace-only, non-URL or
  fragment-bearing audience throws the config error instead of being accepted.

## [0.14.0]

**Additive: who may address whom, which rows a caller may see, and a caller's
standing, decided by agent ID only (`./principal-by-id`).** No existing function changes behaviour for an existing
input.

### Added

- `assertRecipientAddressable(sender, recipient, lookups, { door? })` (CI-2):
  decides, by agent ID only, whether a sender may address a recipient,
  across organisations included. Admits same organisation; client to operator
  when the recipient's ID is on the sender organisation's roster; operator to
  client when the sender's ID is on the recipient organisation's roster.
  `lookups` is `{ orgKindOf, rosterOf }`. Everything else refuses with a typed
  `RBAC_DENIED` naming the door: client to client, a missing sender or
  recipient, a sender that is not an agent, an unresolvable roster. The roster
  check reuses `assertPrincipalListed`. Types `RecipientIds`,
  `RecipientLookups`, `AssertRecipientAddressableOptions`,
  `AssertRecipientAddressableResult`.
- `resolveCallerStanding(credential, lookups, { adminRoles, door? })` (CI-4):
  names a caller's standing as `anonymous` (with the typed refusal), `pre-org`
  (a verified session with no organisation, via the new
  `{ kind: "person-no-org", personId }` credential), `member`, `admin` or
  `fleet`. Built on `resolveActingPrincipal` and `assertOrgAdmin`; the only
  case the existing primitives could not say was `pre-org`, which they refuse
  like a garbled credential. Types `CallerCredential`,
  `AssertCallerStandingOptions`, `CallerStanding`.
- `filterTargetsBelongingTo(principal, rows, lookups, opts?)` (CI-3): the
  ID-keyed row filter that replaces the name-keyed `scopeFilterList`. Async;
  returns `{ ok: true, rows }` or `{ ok: false, refusal }`. Each row is kept
  exactly when `assertTargetBelongsTo` admits it (same `lookups` and options,
  including `door`, `ownerOnly`, `fleetCrossOrg`); that function is reused, not
  re-derived. The principal is proved first: an absent or unresolved principal
  is a refusal naming the door, even for an empty list, never an empty
  success. A resolved principal whose rows all belong elsewhere gets
  `{ ok: true, rows: [] }`. Rows of other organisations, unstamped rows and a
  same-NAME row of another organisation are dropped. A lookup failure on any
  row refuses the whole call, never a silent drop. `fleetCrossOrg: true` from a
  principal that is not `kind: "fleet"` is refused `reserved-fleet-scope` for
  any list. Input order is kept. Type
  `FilterTargetsResult`.

### Deprecated

- `scopeFilterList`, `scopeFilterGet`, `passesScopeFilter` and the name-keyed
  `OAuthCtx.fromAllowList` field now point to `filterTargetsBelongingTo` in
  their TSDoc. Behaviour is unchanged; they are removed when the consumer
  migrates.

## [0.13.0]

**Additive: admission by membership of a stored list, by agent ID only
(`./principal-by-id`).** A client roster used to be checked by comparing names.
`assertPrincipalListed` is the single primitive that replaces it: the caller's
agent ID must be byte-equal to an entry of a stored ID list. No existing
function changes behaviour for an existing input.

### Added

- `assertPrincipalListed(principal, list, { door? })`: synchronous, returns
  `{ ok: true }` or a typed `RBAC_DENIED` refusal naming the door. Refused by
  default: an absent principal or one without an ID, a principal that is not
  `kind: "agent"`, an absent list, a list without an organisation or stored
  under another organisation, an empty or malformed `principalIds`, and an ID
  not on the list. A name never matches and `"*"` is not a wildcard.
- Types `PrincipalIdList`, `AssertPrincipalListedOptions`,
  `AssertPrincipalListedResult`.
- New `IdentityRefusalReason` values: `list-absent`, `list-empty`,
  `principal-not-an-agent`, `principal-not-listed`.

## [0.12.0]

**Additive — the organisation-admin proof, decided by ID
(`./principal-by-id`).** A door that requires "the caller is an ADMIN of its
organisation" reads the verified role from the principal the package resolved,
instead of re-reading the session in a local helper. No existing function
changes behaviour for an existing input.

### Added

- `verifiedOrgRole` (optional, non-empty string) on the `kind: "person"`
  credential of `resolveActingPrincipal`: the role the same verified token
  carries in `verifiedOrgId` (Clerk: `org_role`). It is copied onto the
  resolved principal as `orgRole`; a person credential without it resolves
  exactly as in 0.11.0, with no `orgRole` key. The agent and service
  credentials stay strict: a role on them is refused whole
  (`credential-invalid`).
- `assertOrgAdmin(principal, targetOrgId, { adminRoles, door? })`:
  synchronous, returns `{ ok: true }` or a typed refusal. Only a person is an
  organisation admin (an agent, a service account and the fleet principal are
  refused); the target organisation must be present and byte-equal to the
  principal's stored organisation; the role must be byte-equal to an entry of
  the consumer's `adminRoles`. An absent role, an unknown role and an empty or
  malformed `adminRoles` refuse. No lookup, no case folding, no default role.
- Types `AssertOrgAdminOptions`, `AssertOrgAdminResult`; `orgRole?` on
  `ActingPrincipal`.
- New `IdentityRefusalReason` value: `principal-not-a-person`.

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

## [0.3.0] - 2026-07-23

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
