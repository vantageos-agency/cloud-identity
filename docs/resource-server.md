# Protecting an MCP server as an OAuth resource

Part of the `@vantageos/cloud-identity` documentation. Start at the [README](../README.md).

## Protecting an MCP server as an OAuth resource (`/resource-server`)

An MCP server that requires a bearer token is an OAuth 2.1 protected resource.
These primitives are the whole resource side; they fetch nothing and call no
network.

```ts
import {
  buildProtectedResourceMetadata,
  unauthorizedChallenge,
  deriveClerkDiscoveryUrls,
  verifyMcpAccessToken,
} from "@vantageos/cloud-identity/resource-server";

// GET /.well-known/oauth-protected-resource  (RFC 9728)
const metadata = buildProtectedResourceMetadata({
  resource: "https://mcp.example.com/mcp",
  authorizationServers: ["https://clerk.example.com"],
  scopesSupported: ["mcp:read", "mcp:write"],
});

// On every MCP request
const r = await verifyMcpAccessToken(req.headers.authorization, {
  realm: "mcp",
  resourceMetadataUrl: "https://mcp.example.com/.well-known/oauth-protected-resource",
  issuer: "https://clerk.example.com",
  audience: "https://mcp.example.com/mcp", // this resource: required
  jwks: () => fetchJwks(deriveClerkDiscoveryUrls("https://clerk.example.com").jwksUrl),
});
if (!r.ok) return respond(r.status, "headers" in r ? r.headers : {});
// r.session.userId, r.session.claims
```

- `buildProtectedResourceMetadata` returns the RFC 9728 document
  (`ProtectedResourceMetadataConfig` in, `ProtectedResourceMetadata` out).
- `unauthorizedChallenge` returns `{ status: 401, headers }` whose
  `WWW-Authenticate` always carries `resource_metadata`, plus `error`,
  `error_description` and `scope` when given (`UnauthorizedChallengeConfig`,
  `UnauthorizedChallenge`). Values are escaped; a line break throws.
- `deriveClerkDiscoveryUrls` returns `ClerkDiscoveryUrls`
  (`discoveryUrl`, `jwksUrl`) for an `https` issuer.
- `verifyMcpAccessToken` reuses `verifyClerkSessionToken` (RS256 only) and
  requires the token's `aud` to contain `audience`. It returns the verified
  session, or a `CREDENTIAL_REFUSED` refusal with the `401` envelope
  (`McpResourceServerConfig`, `VerifyMcpAccessTokenResult`):
  `bearer-missing` and `bearer-malformed` answer `invalid_request`,
  `token-invalid` answers `invalid_token` (wrong signature, issuer, audience,
  expiry or not-before are one answer), and an unreachable key set is `503`
  with no challenge (`jwks-unavailable`). A missing issuer or audience throws.
- Limits, stated: the token needs a `sub` and a `kid` (the Clerk session shape);
  the consumer fetches and caches the key set; no scope check is made on the
  token (read `r.session.claims`).

### The session from the raw request, with Clerk's own handshake (`/clerk-handshake`, 0.19.0)

On a development instance the Clerk session lives on the hosted sign-in domain;
only Clerk's handshake brings it to your host. `resolveClerkSessionFromRequest(request, { secretKey, publishableKey, authorizedParties?, jwtKey? })`
is built on `@clerk/backend` `authenticateRequest()` and returns a
`ClerkSessionFromRequest`: `signed-in` (`sessionToken`, `userId`, `sessionId`),
`handshake` (`status` + the `Location` / `Set-Cookie` headers to return as they
are) or `signed-out` (`reason`). `resumeAuthorizeFromRequest(request, input, clerk, cfg, deps)`
feeds the resume path from the request and returns a `ResumeFromRequestOutcome`
(an `AuthorizeOutcome` or the `handshake`). Options type:
`ClerkSessionFromRequestOptions`. Behind a proxy, forward `x-forwarded-host`
and `x-forwarded-proto`.

A form posted back to your host (the org picker's Approve / Deny) is read with
`resolveClerkSessionForFormPost(request, { ...ClerkSessionFromRequestOptions, expectedOrigin })`
(0.21.2, options type `ClerkSessionForFormPostOptions`), never by reading a
cookie yourself: a production instance names its cookie `__session_<suffix>`,
and the session token is often expired by the time the person clicks. It
refuses anything but a POST whose `Origin` is `expectedOrigin`
(`not-a-form-post`, `cross-origin-post`), then resolves the session as the GET
that served the form did, refreshing an expired token; append the returned
`Set-Cookie` headers to your response. A post that would need a handshake is
`signed-out` (`session-needs-handshake`). Keep verifying your form's own
anti-forgery token.

### From a token to `{ principal, orgId }` (`/tenant-from-token`, 0.18.0)

A downstream server never reads a raw claim off a token. It hands the
`Authorization` header and the same config it gives `verifyMcpAccessToken`
to one function and gets the person and the organisation, or a typed refusal.

```ts
import { resolveTenantFromAccessToken } from "@vantageos/cloud-identity/tenant-from-token";

const t = await resolveTenantFromAccessToken(req.headers.authorization, resourceServerConfig);
if (!t.ok) return respond(t.status, "headers" in t ? t.headers : {}); // 401, 403 or 503
// t.orgId                      the organisation ID: scope every row with it
// t.principal.subject          the verified `sub`
// t.principal.actorName        "user:<sub>"
// t.principal.role             the verified `org_role`, or null
```

- It is built on `verifyMcpAccessToken` and verifies nothing itself. A forged,
  expired, wrong-audience or wrong-issuer token, a missing or malformed header,
  and an unreachable key set are that function's answers, passed through
  unchanged (`401` with the RFC 6750 challenge, or `503`). No organisation and
  no principal is returned for a token that did not verify.
- The organisation is the verified token's `org_id` claim (also read under its
  other spellings `organizationId` and `orgId`), and it must be shaped like an
  organisation ID (`org_...`). A slug (`org_slug`) is a label: never read, and
  it never rescues a missing ID.
- A verified token with no usable organisation ID is refused, never resolved
  to an unscoped view: `RBAC_DENIED`, reason `no-verified-organisation`,
  `status: 403`. The refusal carries `door` (from the config, default
  `resolveTenantFromAccessToken`) and never the token.
- Types: `ResolveTenantFromAccessTokenResult`, `TokenPrincipal`.

### The member scope of a resolved organisation (`/member-scope`, 0.30.0)

A door that branches on a scope object for an ordinary member needs the
organisation's row and the verified principal copied into one shape. The
package builds it, so you assemble nothing:

```ts
import { memberScopeFrom, memberScopeOfPerson } from "@vantageos/cloud-identity/member-scope";

const built = memberScopeOfPerson(resolvedOrg, principal, { door: "tasks.create" });
if (!built.ok) return deny(built.refusal);
const scope = built.scope;   // scopeStanding(scope) === "member"
```

- `memberScopeFrom(org, { userId, orgRole?, orgId? }, { door? })` and
  `memberScopeOfPerson(org, personPrincipal, { door? })` return
  `{ ok: true, scope }` or `{ ok: false, refusal }`. The scope carries
  `userId`, `orgSlug` (the label), `orgClerkId` (the permanent ID), `allowedAgentIds`,
  `scopes`, `fleetWide: false`, `isMaster: false`, and `orgRole` only when the
  principal has a verified one. An absent roster is `[]` (nothing admitted). The
  lists are copies.
- Refusals (`RBAC_DENIED`): `org-mapping-record-invalid` (no permanent ID or label,
  or a malformed roster or scope list), `no-verified-subject`, and
  `other-organisation` when the actor's `orgId` is not the row's (compared by ID,
  never by label).
- **Declared divergence:** the scope has no `allowedOrchestrators`. That is the
  legacy name roster (deprecated since 0.24.0) and no export of this package takes
  a name. A consumer whose remaining legacy readers need it adds that one field
  from its own row until it removes them.
- Types: `MemberScope`, `MemberScopeOrg`, `MemberActor`, `MemberScopeOptions`,
  `MemberScopeResult`.

### The standing of a resolved org scope (`/scope-standing`, 0.20.0)

An org-scope resolver hands every door a scope object, and doors used to branch
on its `isMaster` boolean. That boolean mixes "may read the whole fleet" with
"is the fleet itself". `scopeStanding(scope)` is the one reading:

| standing | the scope |
|---|---|
| `"fleet"` | master, `masterSource` `"service-account"` or `"internal"` |
| `"operator-admin"` | master, `masterSource` `"operator-admin"`: reads the fleet, is not the fleet |
| `"member"` | not master, bound to one organisation by its permanent ID: a non-empty `orgClerkId` (0.31.0) |
| `"refused"` | anything else |

```ts
import { requireStanding, requireFleetStanding, hasFleetRead } from "@vantageos/cloud-identity/scope-standing";

requireFleetStanding(scope, "fleet.stats");                      // the fleet: service account or internal opt-in
requireStanding(scope, "tasks.list", ["fleet", "operator-admin", "member"]);
if (hasFleetRead(scope)) { /* unfiltered read: fleet or operator-admin */ }
```

- A slug is a label, not an identity (0.31.0). A non-master scope carrying
  `orgSlug` and no non-empty `orgClerkId` is `"refused"`, not `"member"`. Before
  0.31.0 such a scope was read as `"member"` while ids were being filled.
  Migration: a consumer whose resolver can build a member scope from an org with
  no permanent ID (e.g. a mapping row with no Clerk org ID) must either fill
  that ID or expect `"refused"` (and `requireStanding` to throw
  `scope-not-resolved`) for that scope.
- Fail closed. A scope is `"fleet"` or `"operator-admin"` only when `isMaster`,
  `fleetWide` and a known `masterSource` agree; an absent or malformed scope, the
  `refused` flag, no organisation, or any disagreement is `"refused"` — never the
  more powerful reading.
- `requireStanding` / `requireFleetStanding` throw `IdentityRefusalError`
  `RBAC_DENIED` naming the door: reason `scope-not-resolved` for a `"refused"`
  scope, `standing-not-allowed` otherwise. An empty `allowed` list is a
  `TypeError`, never a pass.
- `hasFleetRead(scope)` is true for `"fleet"` and `"operator-admin"`: the reading
  meaning of `isMaster`.
- Types: `ScopeStanding`, `StandingScope`.

**The service account apart from the internal opt-in (0.20.1).** `"fleet"`
covers two grants: the fleet's service account and an internal opt-in that
carries no credential. A door that must be the service account itself (a
verified actor, an agent credential) uses:

```ts
import { isServiceAccountScope, requireServiceAccountStanding } from "@vantageos/cloud-identity/scope-standing";

requireServiceAccountStanding(scope, "secrets.read");  // the service account only; the internal opt-in is refused
if (isServiceAccountScope(scope)) { /* ... */ }
```

`requireServiceAccountStanding` returns `"fleet"` (0.20.2) or throws `RBAC_DENIED` with `scope-not-resolved`
for a `"refused"` scope and `standing-not-allowed` for any other standing, the
internal opt-in included.

**A verified bearer context (0.20.1).** An MCP transport attaches a context to
each request after verifying its bearer: `isMaster` for the master population,
`viaMasterBearer` only when that master presented the network master bearer.
`bearerStanding(context)` reads it:

| standing | the context |
|---|---|
| `"service-bearer"` | master, through the network master bearer |
| `"local-trust"` | master with no network bearer (a process-local server) |
| `"caller"` | a non-master token |
| `"refused"` | absent, malformed, or `viaMasterBearer` on a non-master context |

Types: `BearerStanding`, `StandingBearer`.

**`@standingGate` (0.20.1).** `scopeStanding`, `hasFleetRead`, `requireStanding`,
`requireFleetStanding`, `isServiceAccountScope`, `requireServiceAccountStanding`
and `bearerStanding` carry the JSDoc tag `@standingGate` in the published
declarations, so an analyser credits a call to any of them as a delegated gate
instead of keeping its own list.

### From verified claims to the caller (`/caller-from-claims`, 0.20.0)

`resolveCallerFromClaims(claims, { orgLookups, principalLookups }, { adminRoles, door })`
is the one call from a VERIFIED identity's claim record to the caller. It chains
the existing primitives, deciding nothing new: `resolveOrgFromClaim` (the
organisation by the verified `org_id`; a slug never selects one), then
`resolveActingPrincipal` (the person as stored in that organisation), then
`assertOrgAdmin` (is that person an admin there).

```ts
import { resolveCallerFromClaims } from "@vantageos/cloud-identity/caller-from-claims";

const c = await resolveCallerFromClaims(identity, { orgLookups, principalLookups }, { adminRoles: ["org:admin"], door: "withOrgScope" });
if (!c.ok) {
  // c.refusal: typed RBAC_DENIED (no-verified-organisation, org-mapping-not-found, other-organisation, credential-invalid, ...)
  // c.claimsOrg: the claims NAME an organisation they could not prove (refuse loudly), vs none at all
  // c.subject (0.20.1): the verified subject when the claims had one, e.g. to decide a service account by subject
} else {
  // c.subject, c.actorName ("user:<sub>"), c.org { id, label, orgKind, ... }, c.principal, c.role, c.isOrgAdmin
}
```

- The role claim is read as `orgRole`, `org_role` or `organizationRole`
  (`readOrgRoleClaim`); none is `null`, and `null` is never an admin.
- `claimsAnOrganisation(claims)` only chooses a refusal's shape; it never names
  an organisation.
- An empty `adminRoles` is a `TypeError`, never a silent non-admin.
- Types: `CallerFromClaimsDeps`, `CallerFromClaimsOptions`, `CallerFromClaimsResult`.

### From a verified agent credential to the caller and its owner

`resolveCallerFromAgentCredential(credential, { orgLookups, principalLookups }, { door })`
is the agent twin of `resolveCallerFromClaims`, exported from the package root
(`AgentCallerCredential`, `AgentCallerDeps`, `AgentCallerOptions`,
`AgentCallerResult`). The credential is `{ agentId, verifiedOrgId, ownerPersonId? }`;
a name beside the IDs refuses it `credential-invalid`. It reads the
organisation by ID (`resolveOrgFromClaim`), then the agent by ID in that
organisation, then proves the owner, all through `resolveActingPrincipal`.

```ts
import { resolveCallerFromAgentCredential } from "@vantageos/cloud-identity";

const c = await resolveCallerFromAgentCredential(
  { agentId: row.id, verifiedOrgId: row.orgId, ownerPersonId: row.ownerPersonId },
  { orgLookups, principalLookups },
  { door: "tasks:list" },
);
if (!c.ok) throw toHttpError(c.refusal);
// c.org, c.principal (kind "agent"), c.owner: a person principal of the same org, or null when no owner was presented
```

### The agent behind a service-account write (`/agent-writer`)

The fleet service account calls a Convex mutation on behalf of an agent and
carries the claim the transport verified: the agent's stored ID and the
organisation ID it was verified in. `resolveAgentWriter` is the one decision on
that claim, so a door does not keep a local variant. It resolves the claim to
the stored agent principal, or throws `IdentityRefusalError`.

```ts
import { resolveAgentWriter } from "@vantageos/cloud-identity/agent-writer";

const writer = await resolveAgentWriter(
  { scope, verifiedActor: args.verifiedActor, targetOrgId: scope.orgId },
  { principalLookups }, // agentById, organisationById, orgKindOf: reads BY ID
  { door: "debate:postTurn" },
);
// writer = { principalId, orgId, kind: "agent" }, read from stored rows.
// The door still writes, and admits by comparing the stored IDs of the rows
// it touches with writer.principalId / writer.orgId.
```

It refuses (`RBAC_DENIED`, naming the door) when:

- the caller is not the fleet service account: a member, the internal opt-in
  and an operator admin are all refused (`standing-not-allowed`), an unresolved
  scope is `scope-not-resolved`;
- `verifiedActor` is absent, or is anything other than exactly `{ agentId, orgId }`:
  a name beside the IDs refuses it whole (`credential-invalid`);
- the claim is for another organisation than `targetOrgId`, or the stored agent
  sits in another organisation than the claim (`other-organisation`);
- the agent lookup misses, is not supplied, throws, or returns a deactivated or
  malformed row; or the organisation is not active.

It only resolves: it writes nothing and grants no write. It proves the caller is
the service account and that the IDs name one live agent of that organisation;
it cannot prove the transport verified the right agent, so `verifiedActor` must
be the transport's own result, never a value the end client chose. Tagged
`@callerResolver`. Types: `AgentWriterClaim`, `AgentWriterInput`,
`AgentWriterDeps`, `AgentWriterOptions`.

#### From the transport (`resolveAgentWriterFromIdentity`, 0.27.0)

`resolveAgentWriter` trusts a `scope` the consumer already resolved. When the
only way to get that scope is a local resolver, the identity decision is split
across two layers. `resolveAgentWriterFromIdentity` takes the host transport's
auth object instead (for Convex, `ctx.auth`), calls `getUserIdentity()` itself,
and decides the service-account standing from stored rows:

```ts
import { resolveAgentWriterFromIdentity } from "@vantageos/cloud-identity/agent-writer";

const w = await resolveAgentWriterFromIdentity(
  ctx.auth, // the consumer never reads the identity itself
  { verifiedActor: { agentId, orgId } },
  {
    principalLookups, // agentById, organisationById, orgKindOf: reads BY ID
    orgLookups, // orgById: the mapping row by org ID, carrying `serviceAccountId`
    serviceAccountLookups: {
      // the service-account rows carrying this verified subject: { id, orgId, active, subject }
      serviceAccountsBySubject: (subject) => readServiceRowsBySubject(subject),
    },
  },
  { door: "debate:postTurn" },
);
if (!w.ok) throw toHttpError(w.refusal); // the door refuses, the package never throws
// w.principal = { principalId, orgId, kind: "agent" }
```

Unlike `resolveAgentWriter`, which throws, it returns `{ ok: true, principal }`
or `{ ok: false, refusal }`, like the package's other `resolve*`, so the door
itself refuses on the absent principal.

The subject is the fleet service account when a row carries it (compared
byte-equal; a row for another subject is ignored), the row's organisation names
that row back (`OrgMappingRow.serviceAccountId`, read through `orgById`), and
the row resolves through `resolveActingPrincipal` to the `fleet` principal (the
operator organisation, active, the row active). An org claim on the identity
takes no part. Then the claim is resolved exactly as `resolveAgentWriter`
resolves it.

Its refusals (`RBAC_DENIED`, naming the door): `no-verified-subject` for no auth
object, no identity or no subject; `credential-invalid` when `getUserIdentity()`
throws (its text is never surfaced); `standing-not-allowed` for a member or
person, a row its organisation does not name, or a client organisation's
service account; `principal-lookup-failed` when the subject lookup is missing,
throws or answers a non-list; `org-mapping-lookup-failed` /
`org-mapping-record-invalid` for the organisation lookup; the row's own
refusals (`principal-inactive`, `no-verified-organisation`,
`organisation-not-active`); then every `resolveAgentWriter` refusal for the
claim. Tagged `@callerResolver`. Types: `TransportAuth`,
`AgentWriterFromIdentityInput`, `AgentWriterFromIdentityDeps`, `AgentWriterFromIdentityResult`,
`ServiceAccountIdentityLookups`, `ServiceAccountRow`.

### The agent a person acts as (`/personal-agent`)

An operator may designate one agent of a person's organisation as that person's
personal agent; the agent row stores the person's ID. `resolvePersonalAgent` is
the one decision "which principal does this verified person act as". The
consumer injects the by-ID read of the agents that designate the person.

```ts
import { resolvePersonalAgent } from "@vantageos/cloud-identity/personal-agent";

const r = await resolvePersonalAgent(
  { personId: token.userId, orgId: token.orgId }, // the verified token's stored IDs
  { designatedAgents, principalLookups },         // agent rows by (personId, orgId); agentById, organisationById, orgKindOf
  { door: "oauth:getAccessTokenByHash" },
);
if (!r.ok) throw toHttpError(r.refusal);            // a failed read never becomes "the person"
// r.actingAs === "agent":  r.principal = { principalId, orgId, kind: "agent" }
// r.actingAs === "person": r.reason is "none" | "inactive" | "ambiguous"
```

The person acts as the agent only when EXACTLY ONE active agent of the person's
organisation designates them. None or only inactive ones, and more than one
active (ambiguous), leave the person as the person. An agent of another
organisation, or one that designates someone else, is neither selected nor
counted. An absent or throwing lookup, a malformed row or an empty ID is a
refusal (`RBAC_DENIED`), and the lookup's text is never surfaced. Tagged
`@callerResolver`. Types: `PersonalAgentInput`, `PersonalAgentDeps`,
`PersonalAgentOptions`, `PersonalAgentResult`, `PersonalAgentRow`,
`PersonalAgentStayReason`.

### Rows in a person's scope, inside the organisation (`/person-scope`)

Organisation isolation answers "which organisation's rows". Inside one
organisation, a person may be allowed only part of the rows, for example the
records of the portfolios they manage. `filterTargetsInPersonScope` applies
that narrowing. Who sees which keys is your data; the package only applies it.

```ts
import { filterTargetsInPersonScope } from "@vantageos/cloud-identity/person-scope";

const out = await filterTargetsInPersonScope(who.principal, rows, {
  orgKindOf,
  scopeOf: async (p) => myScopeStore.scopeFor(p.principalId), // { kind: "keys", keys: new Set([...]) } | { kind: "all", grantedBy: "role:manager" } | null
  rowScopeKeys: (row) => row.portfolioId,                     // one key, several keys, or none
}, { door: "records:list" });
if (!out.ok) throw toHttpError(out.refusal);
return out.rows;
```

- Organisation isolation first: `filterTargetsBelongingTo` runs with the same
  `opts`, and its refusal is returned unchanged. A row of another organisation
  is dropped even when its key is in the set.
- A right is presented, never inferred. `scopeOf` returning `null` /
  `undefined` is refused `person-scope-absent`; an empty key set is refused
  `person-scope-empty`; `{ kind: "all" }` needs a non-empty `grantedBy` naming
  the right, or it is refused `person-scope-grant-unreasoned`; any other form
  is refused `person-scope-malformed`. A `"fleet"` or `"service"` principal
  needs a presented scope too: there is no implicit `"all"`.
- `scopeOf` or `rowScopeKeys` throwing is refused `person-scope-lookup-failed`,
  naming the error kind, never its message.
- A row is kept when at least one of its keys is in the set. A row with no key
  (`undefined`, `null`, `""`, `[]`) is dropped; a key of any other form refuses
  the call. Keys are IDs, compared as exact strings: no case folding, no
  trimming.
- Types: `PersonScope`, `PersonScopeDeps`, `PersonScopeOptions`,
  `PersonScopeResult`.
