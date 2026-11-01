# Reaching across organisations: support access and agent links

Part of the `@vantageos/cloud-identity` documentation. Start at the [README](../README.md).

## Support access: a time-bounded, audited grant instead of membership

A person principal of the operator organisation does not belong to a client
organisation, so client data is not visible to him by default. When a client
asks for help, the operator activates a support grant: who (the person's
stored ID), which organisation (the client's stored ID), why (a reason), until
when. Without a live grant the answer is a refusal (`RBAC_DENIED`). The package
decides; the consumer supplies storage and an audit sink only.

```ts
import { buildSupportGrant, resolveSupportAccess } from "@vantageos/cloud-identity";

// 1. The operator activates, on the client's request.
const built = buildSupportGrant(
  { personId, orgId: clientOrgId, reason: "client asked for help with import", grantedBy: adminId, now: Date.now(), durationMs: 2 * 3600_000 },
  { maxDurationMs: 8 * 3600_000 }, // the consumer's policy ceiling, required
);
if (built.ok) await store.insert(built.grant); // StoredSupportGrant

// 2. Every client-organisation read goes through the resolver.
const access = await resolveSupportAccess(principal, clientOrgId, {
  lookupSupportGrant: (personId, orgId) => store.byPersonAndOrg(personId, orgId),
  onSupportAccess: (event) => audit.write(event), // SupportAccessEvent
}, { door: "tasks:list" });
if (!access.ok) throw new IdentityRefusalError(access.refusal);
```

**`buildSupportGrant(input, { maxDurationMs })`** validates non-empty IDs, a
reason of at least 10 characters, a non-empty `grantedBy`, and
`0 < durationMs <= maxDurationMs`, and returns the row to store:
`{ personId, orgId, reason, grantedBy, grantedAt, expiresAt, revokedAt: null }`.
Otherwise `{ ok: false, refusal }` with `support-grant-invalid`. Types
`BuildSupportGrantInput`, `BuildSupportGrantPolicy`, `BuildSupportGrantResult`.

**`resolveSupportAccess(principal, targetOrgId, deps, { door })`** (tagged
`@callerResolver`) returns `{ ok: true, orgId, grant: { reason, grantedBy, expiresAt } }`
or `{ ok: false, refusal }`. Only a `person` principal can hold a grant; the
principal's own organisation is not a support access (use normal membership).
The stored row must equal the principal ID and the target organisation exactly.
Types `SupportAccessDeps`, `SupportAccessOptions`, `SupportAccessResult`.

| Refusal reason | Meaning |
|---|---|
| `support-grant-absent` | no row: denied by default |
| `support-grant-expired` | `now >= expiresAt` |
| `support-grant-revoked` | `revokedAt` is set |
| `support-grant-mismatch` | the lookup returned a row for another person or organisation |
| `support-grant-own-organisation` | the target is the principal's own organisation |
| `support-grant-not-a-person` | an agent, service or fleet principal |
| `support-grant-invalid` | malformed input or stored row |
| `support-grant-lookup-failed` | the lookup threw: answer unavailable, never a grant |

`onSupportAccess` receives a `SupportAccessEvent` on every granted access
(`outcome: "granted"`, with `reason` and `expiresAt`) and on every refusal
(`outcome: "refused"`, with the reason word), so attempts are audited. A
throwing sink never changes the outcome. Revoke by setting `revokedAt` on the
stored row; expiry needs no write. Refusals never echo another row's IDs or
reason text. `StoredSupportGrant` is the stored row type.

## Agent link: one agent of an organisation reaches one agent of another (0.23.0)

Organisations are isolated: an agent cannot message, or assign a task to, an
agent of another organisation, and a NAME never crosses an organisation. An
agent link is the one deliberate exception, and it is as narrow as it can be
written. It is what lets an agent of a consulting organisation and an agent of
a client organisation reach each other, and it is the path for a client
organisation linking agents of another organisation (a reseller).

- **Directional.** A row says `fromAgentId` may reach `toAgentId`; it says
  nothing about the reverse. "Both ways" is two rows.
- **Granted by the target side.** The row is activated by an ADMIN member of the
  TARGET agent's organisation (`toOrgId`). An admin of the source organisation,
  or a plain member of the target organisation, cannot create it.
- **Exact pair.** A third agent of the same two organisations is not covered.
- **Standing.** No expiry, unlike a support grant. Revocation (`revokedAt`) is
  the off switch.
- **Voided when the grantor leaves.** At every request the grantor must still be
  an active admin member of `toOrgId`. A grantor who was removed, lost the admin
  role, or whose membership went inactive voids the link with no write to the
  row; a current admin of `toOrgId` can grant it again.
- **By ID only.** Agents, persons and organisations are stored IDs. Nothing reads
  a name.

```ts
import { buildAgentLink, resolveAgentLink } from "@vantageos/cloud-identity";

// 1. The TARGET side's admin grants. One call, one direction.
const built = await buildAgentLink(
  { fromAgentId, fromOrgId, toAgentId, toOrgId, grantedBy: targetOrgAdminPersonId, reason: "HR onboarding coordination", now: Date.now() },
  {
    lookupAgent: (agentId) => agents.byId(agentId),                       // { id, orgId, active }
    lookupMembership: (personId, orgId) => members.byPersonAndOrg(personId, orgId), // { active, role, orgId? }
    adminRoles: ["org:admin"],
  },
);
if (built.ok) await store.insert(built.link); // StoredAgentLink

// 2. Every cross-organisation message or task assignment goes through the resolver.
const reach = await resolveAgentLink(
  { fromAgent: { agentId, orgId }, toAgentId, door: "tasks:create" },
  {
    lookupAgentLink: (fromAgentId, toAgentId) => store.byPair(fromAgentId, toAgentId),
    lookupAgent, lookupMembership, adminRoles: ["org:admin"],
    onAgentLink: (event) => audit.write(event), // AgentLinkEvent
  },
);
if (!reach.ok) throw new IdentityRefusalError(reach.refusal);
```

**`buildAgentLink(input, { lookupAgent, lookupMembership, adminRoles })`**
validates non-empty IDs, a reason of at least 10 characters, a finite `now`,
different organisations, that `grantedBy` is an active member of `toOrgId` whose
stored role is in `adminRoles`, and that both agents exist, are active and
belong to the organisations stated. It returns `{ ok: true, link }` with the row
to store, `{ fromAgentId, fromOrgId, toAgentId, toOrgId, grantedBy, grantedAt, revokedAt: null, reason }`,
or `{ ok: false, refusal }`. Types `BuildAgentLinkInput`, `BuildAgentLinkDeps`,
`BuildAgentLinkResult`, `AgentLinkLookups`.

**`resolveAgentLink({ fromAgent, toAgentId, door }, deps)`** (tagged
`@callerResolver`) returns `{ ok: true, toAgentId, toOrgId, link: { reason, grantedBy, grantedAt } }`
or `{ ok: false, refusal }`. It admits only a stored, non-revoked row for exactly
the (`fromAgent.agentId`, `toAgentId`) pair and the caller's organisation, while
the target agent is still active in `toOrgId` and the grantor is still an active
admin of `toOrgId`. Types `ResolveAgentLinkInput`, `ResolveAgentLinkDeps`,
`ResolveAgentLinkResult`, `StoredAgentLink`.

| Refusal reason | Meaning |
|---|---|
| `agent-link-absent` | no row for this pair (the reverse pair and a third agent land here) |
| `agent-link-revoked` | `revokedAt` is set |
| `agent-link-mismatch` | the lookup returned a row for another pair or another source organisation |
| `agent-link-invalid` | malformed input, deps or stored row |
| `agent-link-same-organisation` | build only: both agents are in one organisation |
| `agent-link-grantor-not-admin` | build only: the grantor is not an active admin of `toOrgId` |
| `agent-link-grantor-void` | resolve only: the grantor is no longer an active admin of `toOrgId` |
| `agent-link-agent-unavailable` | an agent is missing, inactive, or not in the organisation stated |
| `agent-link-lookup-failed` | a lookup threw: reported by error kind only, never a grant |

`onAgentLink` receives an `AgentLinkEvent` on every attempt (`outcome: "granted"`
with `reason` and `grantedBy`, or `outcome: "refused"` with the reason word). A
throwing sink never changes the outcome. Refusals never echo another row's IDs or
reason text.
