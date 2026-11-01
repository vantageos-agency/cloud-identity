# Authorizing a person and wiring sign-in

Part of the `@vantageos/cloud-identity` documentation. Start at the [README](../README.md).

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
  `OrgPickerModel.redirectOrigin` is the origin of the registered
  `redirect_uri` the person will be sent to, for the consent page to display
  (display-only; it grants nothing).
  Denial: post `denied: true` (an explicit flag, never inferred from a missing
  `approved`). Once the state, the client and the session verify,
  `resumeAuthorize` returns `redirect-to-client` carrying `error=access_denied`
  and the client's `state`. This package never adds `iss`: the RFC 9207 `iss`
  is appended by the consumer (the authorization server that owns the issuer)
  to every `redirect-to-client` outcome, success and denial alike. A tampered or expired state, an unknown client or a failed
  session is a refusal, never a redirect; `denied` with `approved: true` is
  refused as `invalid-request`. With consent on (the default), a denial must
  also post the picker's `consentToken`, verified by the same function as an
  approval (0.18.0): a missing, empty, forged or foreign token is refused as
  `consent-required`, the same outcome the approve path returns, and a valid
  one still redirects with `access_denied`. A denial is a claim in a POST body
  like an approval; without the token it could be posted for a victim's
  session. With `requireConsent: false` no token exists and none is required.
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
- **By ID (0.29.0).** A token record may carry `orgId` and the deps a
  `lookupOrganisationById(orgId)` (plus `organisationId(org)` to read an org
  row's ID). Then the ID path alone selects the organisation: a miss never
  falls back to the slug. A record with both `orgId` and `orgSlug` naming
  different organisations is refused (`other-organisation`). Without `orgId`
  (or without the ID lookup) the slug path runs as before; it is legacy, since a
  label is renamable.
- `orgMappingRowSchema` / `ResolvedOrg` also carry `addressableFleetCoordinatorIds`
  (0.29.0), the client organisation's roster of operator agent IDs; read it in
  your `RecipientLookups.rosterOf`.
- `resolvePersonTenantAccess` is a strict equality on the organisation: on
  `principal.orgId` when the principal carries one (0.29.0; pass the row's org ID
  as `rowOrgId`, a slug never matches), else on the slug (legacy). An
  unstamped row is refused.
- `resolveWriterRole` / `requireWriterRole` check the verified role against a
  writer allowlist you hold as data. A missing role, a missing list and an
  empty list all refuse. `requireWriterRole` throws `PersonRefusalError`.
- **A writer list per organisation, with a fleet default (0.30.0).** Your store
  holds an optional list per organisation and an optional fleet default. Read
  both (the package reads no store) and let the package choose:
  `selectWriterRoles(orgRoles, fleetDefaultRoles)` returns
  `{ source: "org" | "fleet-default" | "none", roles }`. A list for the
  organisation wins, even an empty one (an empty organisation list means nobody
  writes there, it never falls back); an absent one (`undefined` or `null`)
  falls back to the fleet default; no list anywhere is `"none"`. A list that is
  present but malformed selects itself with no roles, never the default.
  `resolveWriterRoleForOrg({ role, orgRoles, fleetDefaultRoles, door, orgSlug })`
  is `resolveWriterRole` over that choice: no list, an empty list or an absent
  role all refuse (`role-not-writer`), never "all roles". Types
  `WriterRoleListSource`, `SelectedWriterRoles`.
- Every refusal is a `PersonRefusal` (`PersonRefusalCode`, `PersonRefusalReason`,
  `door`, `detail`); you choose the transport shape. `personTokenRecordSchema`,
  `PersonTokenRecord`, `PersonPrincipal`, `OrganisationState`,
  `PersonPrincipalDeps`, `PersonPrincipalResult`, `PersonActingNameResult` and
  `PersonAccessResult` are the input and result types.

The module verifies no credential. The token record must come from your own
lookup of the bearer the person presented, never from a request body.

## Wiring the authorize runtime (`/authorize-runtime`, 0.21.7)

The decisions (`startAuthorize`, `resumeAuthorize`, `exchangeAuthorizationCode`,
`buildDiscoveryDocument`) take their collaborators as parameters.
`@vantageos/cloud-identity/authorize-runtime` is the glue that builds them, so an
MCP server does not copy it. It is store-agnostic and framework-agnostic: you
inject the client registry, the code storage and the membership lister; it reads
no `process.env`, opens no connection and logs no value.

```ts
import {
  buildAuthorizeRuntime,
  codeStoreFrom,
  createClerkDirectory,
  pickerContentSecurityPolicy,
  readAuthorizeSettings,
  renderOrgPicker,
} from "@vantageos/cloud-identity/authorize-runtime";
import { createClerkClient } from "@clerk/backend";

const read = readAuthorizeSettings(process.env);
if (!read.ok) return respond503(read.missing); // names only, never values

const clerk = createClerkDirectory(createClerkClient({ secretKey: process.env.CLERK_SECRET_KEY }));
const { cfg, deps } = buildAuthorizeRuntime({
  settings: read.settings,
  lookupClient: (clientId) => myRegistry.find(clientId),
  listMemberships: clerk.listMemberships, // filter it here to the orgs your server can serve
  codeStore: codeStoreFrom({ insert: db.putCode, takeOnce: db.consumeCode }),
});

// GET /authorize           -> startAuthorize(query, sessionToken, cfg, deps)
// GET /authorize/callback  -> resumeAuthorize({ state, sessionToken }, cfg, deps)
// POST /authorize/org      -> resumeAuthorize({ state, sessionToken, orgId, approved, consentToken }, cfg, deps)
// On kind "org-picker":
//   body    = renderOrgPicker(outcome.model, { productName: "My Server" })
//   header  = { "Content-Security-Policy": await pickerContentSecurityPolicy() }
// POST /token (authorization_code) -> exchangeAuthorizationCode(input, { codeStore: deps.codeStore })
```

**`readAuthorizeSettings(env, { requireClerkSecretKey? })`** reads
`AUTHORIZE_STATE_SECRET` (at least 32 characters), `CLERK_DOMAIN`,
`AUTHORIZE_SIGN_IN_URL`, `AUTHORIZE_CALLBACK_URL`, `PUBLIC_BASE_URL`,
`CLERK_SECRET_KEY` and the optional comma list `AUTHORIZE_AUTHORIZED_PARTIES`
from the object you pass. It returns `{ ok: true, settings }` or
`{ ok: false, missing, refusal }`, where `missing` holds the NAMES of every
absent or unusable variable and `refusal` is `server-misconfigured`. Pass
`requireClerkSecretKey: false` when you inject your own membership lister.
`AUTHORIZE_ENV` lists the names; `DEFAULT_AUTHORIZE_SCOPE` is `mcp:full openid`.
Types `AuthorizeEnv`, `AuthorizeSettings`, `AuthorizeSettingsResult`,
`ReadAuthorizeSettingsOptions`.

**`createClerkJwksSource({ issuer, fetch?, now?, ttlMs? })`** is the
`session.jwks` function: it serves the key set from its own cache for `ttlMs`
(default ten minutes) and refetches after. A failed or malformed answer throws
and is not cached; the flow then refuses `jwks-unavailable`. `buildAuthorizeRuntime`
creates one unless you pass `jwks`. Types `JwksFetch`, `ClerkJwksSourceOptions`.

**`codeStoreFrom({ insert, takeOnce })`** adapts your storage to
`AuthorizationCodeStore`. `takeOnce(codeHash)` must be atomic. Its answer is
checked: `ok` with a complete record, `unknown` and `already-used` pass; anything
else throws, and the exchange answers `code-store-unavailable`.
`createInMemoryCodeStore()` is a single-use store for tests and a one-instance
development server. Type `CodeStoreBackend`.

**`createClerkDirectory(clerk, { pageSize?, maxPages? })`** returns
`listMemberships` and `getUser` over a Clerk Backend client you created. The list
is read in full; a Clerk failure or a list that does not end within `maxPages`
throws, so a partial list is never offered. Types `ClerkUsersApi`,
`ClerkDirectoryOptions`, `ClerkDirectory`.

**`renderOrgPicker(model, { productName, formAction? })`** returns the consent
page (default action `/authorize/org`); every interpolated value is escaped and
the hidden `consentToken` is the CSRF protection of the post. Send
`await pickerContentSecurityPolicy()` as its `Content-Security-Policy`: no
scripts, no external assets, no framing, one inline style admitted by hash. Type
`OrgPickerOptions`.

**`buildAuthorizeRuntime({ settings, lookupClient, listMemberships, codeStore, jwks?, now?, generateCode?, resourcePath?, defaultScope?, supportedScopes? })`**
returns `{ cfg, deps }`. The only resource codes are issued for is
`<baseUrl><resourcePath>` (default `/mcp`). Consent stays on. Types
`AuthorizeRuntimeOptions`, `AuthorizeRuntime`.
