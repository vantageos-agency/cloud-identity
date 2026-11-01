# An organisation is its permanent ID

Part of the `@vantageos/cloud-identity` documentation. Start at the [README](../README.md).

## An organisation is its permanent ID (0.16.0)

A label (the slug an org can be renamed to) is display text. These functions
decide "which organisation" from the permanent org ID, with the store supplied
as adapters, and refuse by default. All are in `./org-by-id` and the root.

**`resolveOrgFromClaim(claims, lookups, opts)`** takes the claim record of a
VERIFIED credential (never a request field) and returns
`{ ok: true, org: { id, label, allowedOrchestrators?, allowedAgentIds?, scopes, orgKind } }`
or a typed `RBAC_DENIED` refusal. Each roster is on `org` only when the row
has it (since 0.24.0): `allowedOrchestrators` is the legacy name roster
(deprecated), `allowedAgentIds` the roster by agent ID. The `org_id` claim (also read from
`organizationId` and `orgId`, only when shaped like a Clerk org ID) selects the
mapping row through `lookups.orgById`; a stale label in the token is ignored,
so a rename never changes who the caller is. Refused: no claim, an ID no
mapping holds, an inactive org, a row that does not repeat the ID asked for, a
malformed row, a missing or throwing adapter.

```ts
const r = await resolveOrgFromClaim(identity, {
  orgById: (id) => db.mappingByClerkOrgId(id),
}, { door: "tasks:list" });
if (!r.ok) throw new IdentityRefusalError(r.refusal);
```

**`sameOrg(a, b, opts)`**, **`isFleetStamp(stamp, operator, opts)`** and
**`sameTenantStamp(a, b, operator, opts)`** compare `OrgRef` values
(`{ id?, label? }`). Two IDs are equal or they are not; unstamped is never
a match; `isFleetStamp` is true for an unstamped stamp or the operator's, and
`sameTenantStamp` is true for the same org or when both are the fleet's.

**`findOperatorOrg(lookups, opts)`** finds the operator organisation from
`lookups.activeOrganisations(limit)`: `one`, `none`, `many`, `overCap`
(`cap` defaults to 1000, the read is `cap + 1`) or `unreadable`. Only `one` is
an operator; pass `undefined` as `operator` otherwise and only unstamped rows
are the fleet's.

**`resolveOrgIdForLabelBackfillOnly(label, lookups)`** derives the permanent
ID of the org a label names, for a ONE-OFF BACKFILL that stamps rows written
before IDs existed. It must never be called on a request path: a request
decides its organisation from the verified `org_id` claim
(`resolveOrgFromClaim`), and a miss there is a refusal, never a retry by label.
It returns `{ present: true, orgId }` or a typed `ORG_ID_ABSENT` absence
(`no-label`, `lookup-failed`, `not-mapped`, `record-invalid`, `id-not-filled`).
It never invents an ID.

**`orgMappingRowSchema`** is the Zod shape of a mapping row an adapter returns
(`id`, `label`, `active`, `allowedOrchestrators?`, `allowedAgentIds?`,
`scopes`, `orgKind`). Both rosters are optional since 0.24.0; one that is
present but malformed refuses the row.

Types: `OrgRef`, `OrgMappingRow`, `OrgMappingLookups`,
`ResolvedOrg`, `ResolveOrgFromClaimOptions`, `ResolveOrgFromClaimResult`,
`OrgIdAbsence`, `OrgIdAbsenceReason`, `OrgIdResolution`, `OperatorOrgLookups`,
`FindOperatorOrgOptions`, `OperatorOrgResult`.

**No label resolution.** No function above compares or selects by label, and
no option turns that on: a reference or credential without an org ID names no
organisation and is refused. A store that has not filled every ID is filled
once, with `resolveOrgIdForLabelBackfillOnly`, before the consumer relies on
these functions.

**`resolveProvisioningLabel(label, lookups)`** (0.20.0) is the one boundary
where an operator's provisioning input names an organisation by label. It
returns `{ kind: "mapped", orgId, active }`, `{ kind: "unmapped" }` (the
organisation does not exist yet), `{ kind: "mapped-without-id", active }` or
`{ kind: "unreadable", reason }` (`no-label`, `lookup-failed`,
`record-invalid`). Every decision after it is by `orgId`; an unreadable store
is never "unmapped", so a failing read cannot authorise a creation. Type:
`ProvisioningLabelResult`.
