# The acting principal and the target, by ID

Part of the `@vantageos/cloud-identity` documentation. Start at the [README](../README.md).

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

**An agent bound to its human owner** (`./principal-by-id`)

An agent credential may also carry `ownerPersonId`: the person the agent is
bound to. It is an ID read from your VERIFIED credential row, never a request
argument. `resolveActingPrincipal` then proves it, and without it nothing
about the owner is read and the result is exactly what it was:

- the agent row's stored `ownerPersonId` must be byte-equal to the one
  presented (`agent-owner-mismatch`; an absent or `null` stored owner never
  matches);
- `personById(ownerPersonId, orgId)` must return an ACTIVE row of the same
  organisation, otherwise `agent-owner-not-member`. The detail names the case
  (not found, not active, another organisation, malformed record) and never
  quotes your lookup's own error text;
- `personById` throwing, or not supplied, is refused `principal-lookup-failed`:
  the check is never skipped;
- on success the principal carries `ownerPersonId`, set only when proven.

`PrincipalRow` gains the optional `ownerPersonId` (`string | null`); `ActingPrincipal`
gains the optional `ownerPersonId`.

**`assertAgentOwnedBy(principal, personId, opts)`** (`./principal-by-id`)

Synchronous. Returns `{ ok: true }` or `{ ok: false, refusal }`; `opts` is
`{ door? }`. Admits only a `kind: "agent"` principal whose proven
`ownerPersonId` is byte-equal to `personId`. A person, a service account, the
fleet principal, an agent with no proven owner, an absent or empty `personId`
and an absent principal all refuse `agent-not-owned`. Types:
`AssertAgentOwnedByOptions`, `AssertAgentOwnedByResult`.

```js
const owned = assertAgentOwnedBy(who.principal, task.requestedByPersonId, { door: "tasks:read" });
if (!owned.ok) throw toHttpError(owned.refusal);
```

**`assertRecipientAddressable(sender, recipient, lookups, opts)`** (`./principal-by-id`, 0.14.0)

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

**`filterTargetsBelongingTo(principal, rows, lookups, opts)`** (`./principal-by-id`, 0.14.0)

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

### A caller's standing (0.14.0)

`resolveCallerStanding(credential, lookups, { adminRoles, door? })` names which
of the four callers is asking. It is built on `resolveActingPrincipal` and
`assertOrgAdmin`; it is not a second path.

| Credential (verified by you) | Standing |
|---|---|
| none, garbled, unknown or inactive principal | `anonymous`, with the typed `refusal` |
| `{ kind: "person-no-org", personId }` | `pre-org` (signed in, no organisation) |
| person or agent, or a non-operator service account, without the admin role | `member`, with `principal` |
| person whose `verifiedOrgRole` is in `adminRoles` | `admin`, with `principal` |
| service account of the operator organisation (`orgKindOf` is `"operator"`) | `fleet`, with `principal` |

Types: `CallerCredential`, `AssertCallerStandingOptions`, `CallerStanding`.

- A master token reaches `fleet` by your mapping it to the operator service
  account: `validateMasterBearer` proves the secret, then you pass
  `{ kind: "service", serviceAccountId }`. The package never mints a fleet
  credential from a bearer.
- A Clerk session reaches the function through `verifyClerkSessionToken`: with
  an `org_id` claim, pass a `person` credential carrying `verifiedOrgId` and
  `verifiedOrgRole`; without one, pass `person-no-org`. A person credential
  that merely lacks `verifiedOrgId` is garbled and is `anonymous`, never `pre-org`.
- Branch on `standing`, never on the absence of a field. `pre-org` is not
  `anonymous`: refuse it where an organisation is needed, but answer it as a
  signed-in caller (see the refusal rules of your read doors).
