/**
 * The acting principal by ID, and the target checked by ID.
 *
 * An actor and a target are identified by their stored IDs, never by a name.
 * A name is a display label: it never selects a row and never authorises one.
 *
 * Motivating incident: an agent of organisation A named "eta", calling by name
 * through a service account, completed, updated and deleted the task of
 * organisation B's agent also named "eta" at ten task doors, because every door
 * admitted the caller by comparing names. Two different agents shared a label;
 * nothing compared their IDs.
 *
 * Two functions close that class:
 *
 *   - `resolveActingPrincipal(credential, lookups)` turns a VERIFIED credential
 *     into `{ principalId, orgId, kind }` read from stored rows, or refuses.
 *   - `assertTargetBelongsTo(principal, target, lookups, opts)` admits a target
 *     only when its stored organisation ID (and owner ID, where the door is
 *     owner-only) equals the principal's resolved IDs.
 *
 * The fleet is the OPERATOR ORGANISATION: the organisation the consumer's
 * `orgKindOf` adapter reports as `"operator"`, read from stored data at run
 * time. No organisation ID is reserved or spelled in this package; an
 * adapter that answers anything else, or nothing, means "not the fleet".
 *
 * RULING 5: membership of the operator org is ORDINARY membership. Its agents
 * and persons resolve as `kind: "agent"` / `"person"` of that org and reach its
 * rows only. Cross-org reach (`kind: "fleet"` + `fleetCrossOrg`) belongs to the
 * operator org's SERVICE ACCOUNT alone; `reserved-fleet-scope` refuses a claim
 * of that scope by any other credential, never plain membership.
 *
 * Pure functions over injected lookups: no database, no framework, no network.
 * The consumer performs each indexed read by ID and passes the function in;
 * every failure (throwing lookup, miss, malformed row, inactive row, wrong
 * organisation) is a typed `IdentityRefusal`, never a default principal.
 *
 * @security This module verifies NOTHING about the credential itself. The IDs
 * in a credential must come from the consumer's verification of what the
 * caller presented (a bearer row, a person's token, the service secret). A
 * client-supplied argument passed as a credential becomes the principal.
 */

import { z } from "zod";
import { type IdentityRefusal, refusal } from "./identity-refusal.js";

// ---------------------------------------------------------------------------
// The credential: verified IDs only, no name field anywhere
// ---------------------------------------------------------------------------

/**
 * A verified credential, in the package's vocabulary. Every identity field is
 * an ID. The schemas are STRICT: a credential carrying any other key (an
 * `agentName`, a `callerOrchestrator`, a `name`) is refused whole, so a name
 * cannot be smuggled in beside an ID.
 *
 *   - `agent`: an agent's own bearer, verified by the consumer (for example by
 *     `validatePresentedBearer`): the agent ID and the organisation the bearer
 *     row is stamped with.
 *   - `person`: a person's token, verified by the consumer: the stored person
 *     ID (the verified subject) and the organisation the token is bound to.
 *     Optionally (0.12.0) the role the SAME token carries in that organisation
 *     (`verifiedOrgRole`, for example Clerk's `org_role`), read by
 *     `assertOrgAdmin`. Only a verified claim belongs here, never an argument.
 *   - `service`: the service account, verified by the consumer. When it acts
 *     for an agent it names that agent BY ID (`actingForAgentId`); the agent
 *     is resolved within the service account's own organisation.
 */
export const actingCredentialSchema = z.discriminatedUnion("kind", [
  z.strictObject({
    kind: z.literal("agent"),
    agentId: z.string().min(1),
    verifiedOrgId: z.string().min(1),
  }),
  z.strictObject({
    kind: z.literal("person"),
    personId: z.string().min(1),
    verifiedOrgId: z.string().min(1),
    verifiedOrgRole: z.string().min(1).optional(),
  }),
  z.strictObject({
    kind: z.literal("service"),
    serviceAccountId: z.string().min(1),
    actingForAgentId: z.string().min(1).optional(),
  }),
]);

export type ActingCredential = z.input<typeof actingCredentialSchema>;

// ---------------------------------------------------------------------------
// The stored rows the consumer's lookups return
// ---------------------------------------------------------------------------

/**
 * Each row repeats its own ID, so a loose lookup (prefix match, wrong index)
 * returning another row cannot become a principal. `active` is REQUIRED and
 * must be `true`: an absent flag grants nothing. Extra fields (a display name)
 * are allowed and ignored.
 */
export const principalRowSchema = z.object({
  id: z.string().min(1),
  orgId: z.string().min(1).nullish(),
  active: z.boolean(),
});
export type PrincipalRow = z.input<typeof principalRowSchema>;

export const organisationRowSchema = z.object({
  id: z.string().min(1),
  active: z.boolean(),
});
export type OrganisationRow = z.input<typeof organisationRowSchema>;

/**
 * The kind of a stored organisation, as the consumer's mapping row records it.
 * `"operator"` is the fleet: the operator's own organisation, whose rows are
 * the master scope. Any other answer, `null` included, is not the fleet.
 */
export type OrgKind = "operator" | "client";

type Lookup<A extends unknown[], R> = (
  ...args: A
) => Promise<R | null | undefined> | R | null | undefined;

/** Indexed reads BY ID. Only the lookups of the presented path are called. */
export type PrincipalLookups = {
  agentById?: Lookup<[agentId: string], PrincipalRow>;
  /** A person's row IN one organisation (their membership there). */
  personById?: Lookup<[personId: string, orgId: string], PrincipalRow>;
  serviceAccountById?: Lookup<[serviceAccountId: string], PrincipalRow>;
  /** The organisation row; the operator organisation is checked like any other. */
  organisationById?: Lookup<[orgId: string], OrganisationRow>;
  /**
   * The stored kind of an organisation (for example `orgKind` on its mapping
   * row). Decides, from data, whether an organisation is the operator org,
   * that is the fleet. `null`, a miss, or any value other than exactly
   * `"operator"` is NOT the fleet. A missing or throwing adapter refuses.
   */
  orgKindOf?: Lookup<[orgId: string], OrgKind>;
};

/** The one lookup `assertTargetBelongsTo` reads. */
export type OrgKindLookups = Pick<PrincipalLookups, "orgKindOf">;

// ---------------------------------------------------------------------------
// The resolved principal
// ---------------------------------------------------------------------------

export type ActingPrincipalKind = "agent" | "person" | "service" | "fleet";

export type ActingPrincipal = {
  /** The stored ID of the actor: agent ID, person ID or service-account ID. */
  principalId: string;
  /** The stored organisation ID. The operator org's ID for `fleet`. */
  orgId: string;
  kind: ActingPrincipalKind;
  /** Set when a service account acts for an agent: the service account's ID. */
  viaServiceAccountId?: string;
  /**
   * `kind: "person"` only, and only when the credential carried
   * `verifiedOrgRole`: the verified role in `orgId`. Read by `assertOrgAdmin`.
   */
  orgRole?: string;
};

export type ResolveActingPrincipalResult =
  | { ok: true; principal: ActingPrincipal }
  | { ok: false; refusal: IdentityRefusal };

export type TargetIds = {
  /** The target row's stored organisation ID. Absent: unstamped. */
  orgId?: string | null;
  /** The target row's stored owner ID (agent, person or service account). */
  ownerId?: string | null;
};

export type AssertTargetOptions = {
  /** The consumer's name for the door; carried on every refusal. */
  door?: string;
  /** Owner-only door: the target's `ownerId` must equal `principalId`. */
  ownerOnly?: boolean;
  /**
   * A fleet principal may reach a row of a CLIENT organisation only when the
   * door declares it (a master export), and only when `orgKindOf` reports that
   * organisation as `"client"`. Default `false`: refused.
   */
  fleetCrossOrg?: boolean;
};

export type AssertTargetResult = { ok: true } | { ok: false; refusal: IdentityRefusal };

// ---------------------------------------------------------------------------
// resolveActingPrincipal
// ---------------------------------------------------------------------------

type Reason = Parameters<typeof refusal>[1];
type Refused = { ok: false; refusal: IdentityRefusal };
type Loaded<T> = { ok: true; row: T } | Refused;

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function denied(reason: Reason, door: string, detail: string): Refused {
  return { ok: false, refusal: refusal("RBAC_DENIED", reason, door, detail) };
}

/**
 * Reads one principal row BY ID and checks it: the lookup is supplied and does
 * not throw, the row exists, is well formed, repeats the ID asked for, and is
 * active. The lookup's own error text is never surfaced.
 */
async function loadPrincipalRow<A extends unknown[]>(
  lookup: Lookup<A, PrincipalRow> | undefined,
  args: A,
  expectedId: string,
  what: string,
  door: string,
): Promise<Loaded<z.output<typeof principalRowSchema>>> {
  if (typeof lookup !== "function") {
    return denied("principal-lookup-failed", door, `No lookup was supplied for the ${what}.`);
  }
  let raw: unknown;
  try {
    raw = await lookup(...args);
  } catch {
    return denied("principal-lookup-failed", door, `The ${what} could not be read, so none is resolved.`);
  }
  if (raw === null || raw === undefined) {
    return denied("principal-not-found", door, `No ${what} has this ID.`);
  }
  const parsed = principalRowSchema.safeParse(raw);
  if (!parsed.success || parsed.data.id !== expectedId) {
    return denied("principal-record-invalid", door, `The ${what} record is not well formed.`);
  }
  if (parsed.data.active !== true) {
    return denied("principal-inactive", door, `The ${what} is not active.`);
  }
  return { ok: true, row: parsed.data };
}

/**
 * Reads the stored kind of an organisation. Refusal by default: a missing or
 * throwing adapter refuses; a miss or any answer other than exactly
 * `"operator"` / `"client"` is `null`, which is never the fleet.
 */
async function loadOrgKind(
  lookups: OrgKindLookups | null | undefined,
  orgId: string,
  door: string,
): Promise<{ ok: true; kind: OrgKind | null } | Refused> {
  const lookup = lookups?.orgKindOf;
  if (typeof lookup !== "function") {
    return denied("principal-lookup-failed", door, "No lookup was supplied for the organisation kind.");
  }
  let raw: unknown;
  try {
    raw = await lookup(orgId);
  } catch {
    return denied(
      "principal-lookup-failed",
      door,
      "The organisation kind could not be read, so none is resolved.",
    );
  }
  return { ok: true, kind: raw === "operator" || raw === "client" ? raw : null };
}

/** Every organisation, the operator org included, must exist and be active. */
async function checkOrganisation(
  orgId: string,
  lookups: PrincipalLookups,
  door: string,
): Promise<Refused | null> {
  const lookup = lookups.organisationById;
  if (typeof lookup !== "function") {
    return denied("principal-lookup-failed", door, "No lookup was supplied for the organisation.");
  }
  let raw: unknown;
  try {
    raw = await lookup(orgId);
  } catch {
    return denied("principal-lookup-failed", door, "The organisation could not be read, so none is resolved.");
  }
  const parsed = organisationRowSchema.safeParse(raw);
  if (!parsed.success || parsed.data.id !== orgId || parsed.data.active !== true) {
    return denied("organisation-not-active", door, "The organisation is not mapped or not active.");
  }
  return null;
}

function served(principal: ActingPrincipal): ResolveActingPrincipalResult {
  return { ok: true, principal };
}

/**
 * Resolves the acting principal from a VERIFIED credential to stored IDs, or
 * refuses. Refusal by default: a credential claiming the fleet kind
 * (`reserved-fleet-scope`), a credential that does not parse (including one
 * carrying any name field), a missing or throwing lookup, a miss, a malformed
 * or inactive row, an unstamped row and an inactive organisation are all
 * refused. Nothing is ever resolved by a name, and nothing falls back to a
 * master principal.
 *
 *   - agent: the agent row by `agentId`; its stored org must equal the org
 *     the credential was verified for. An agent of the operator org resolves
 *     as an ordinary `kind: "agent"` of that org (RULING 5).
 *   - person: the person row by (`personId`, `verifiedOrgId`); it must be
 *     stamped with that org. A person of the operator org resolves as an
 *     ordinary `kind: "person"` of that org (RULING 5).
 *   - service: the service-account row by `serviceAccountId`. Alone, it acts
 *     as itself (`kind: "service"`, or `kind: "fleet"` when `orgKindOf` reports
 *     its stored org as `"operator"`). With `actingForAgentId`, the agent row is read by
 *     ID and must be stamped with the service account's own org; the principal
 *     is that agent, with `viaServiceAccountId` recording the carrier.
 */
export async function resolveActingPrincipal(
  credential: ActingCredential | null | undefined,
  lookups: PrincipalLookups,
  door = "resolveActingPrincipal",
): Promise<ResolveActingPrincipalResult> {
  if (
    credential !== null &&
    typeof credential === "object" &&
    (credential as { kind?: unknown }).kind === "fleet"
  ) {
    return denied(
      "reserved-fleet-scope",
      door,
      "The fleet scope is held only by the operator organisation's service account; no credential claims it.",
    );
  }
  const parsed = actingCredentialSchema.safeParse(credential);
  if (!parsed.success) {
    return denied(
      "credential-invalid",
      door,
      "The credential does not identify a principal by ID.",
    );
  }
  const cred = parsed.data;
  const look: PrincipalLookups = lookups ?? {};

  if (cred.kind === "agent" || cred.kind === "person") {
    // The org's kind is read so a missing or throwing adapter refuses here as
    // on every path; an operator-org member is NOT refused (RULING 5).
    const credKind = await loadOrgKind(look, cred.verifiedOrgId, door);
    if (!credKind.ok) return credKind;
    const loaded =
      cred.kind === "agent"
        ? await loadPrincipalRow(look.agentById, [cred.agentId], cred.agentId, "agent", door)
        : await loadPrincipalRow(
            look.personById,
            [cred.personId, cred.verifiedOrgId],
            cred.personId,
            "person",
            door,
          );
    if (!loaded.ok) return loaded;
    const rowOrg = loaded.row.orgId;
    if (!nonEmpty(rowOrg)) {
      return denied("no-verified-organisation", door, `The ${cred.kind} is stamped with no organisation.`);
    }
    if (rowOrg !== cred.verifiedOrgId) {
      return denied(
        "other-organisation",
        door,
        `The ${cred.kind} belongs to another organisation than its credential.`,
      );
    }
    const orgRefusal = await checkOrganisation(rowOrg, look, door);
    if (orgRefusal !== null) return orgRefusal;
    if (cred.kind === "person" && cred.verifiedOrgRole !== undefined) {
      return served({
        principalId: loaded.row.id,
        orgId: rowOrg,
        kind: cred.kind,
        orgRole: cred.verifiedOrgRole,
      });
    }
    return served({ principalId: loaded.row.id, orgId: rowOrg, kind: cred.kind });
  }

  // service account
  const svc = await loadPrincipalRow(
    look.serviceAccountById,
    [cred.serviceAccountId],
    cred.serviceAccountId,
    "service account",
    door,
  );
  if (!svc.ok) return svc;
  const svcOrg = svc.row.orgId;
  if (!nonEmpty(svcOrg)) {
    return denied("no-verified-organisation", door, "The service account is stamped with no organisation.");
  }
  const svcKind = await loadOrgKind(look, svcOrg, door);
  if (!svcKind.ok) return svcKind;
  const orgRefusal = await checkOrganisation(svcOrg, look, door);
  if (orgRefusal !== null) return orgRefusal;

  if (cred.actingForAgentId === undefined) {
    return served({
      principalId: svc.row.id,
      orgId: svcOrg,
      kind: svcKind.kind === "operator" ? "fleet" : "service",
    });
  }

  const agent = await loadPrincipalRow(
    look.agentById,
    [cred.actingForAgentId],
    cred.actingForAgentId,
    "agent",
    door,
  );
  if (!agent.ok) return agent;
  if (agent.row.orgId !== svcOrg) {
    return denied(
      "acting-agent-other-organisation",
      door,
      "The service account may act only for an agent of its own organisation.",
    );
  }
  return served({
    principalId: agent.row.id,
    orgId: svcOrg,
    kind: "agent",
    viaServiceAccountId: svc.row.id,
  });
}

// ---------------------------------------------------------------------------
// assertTargetBelongsTo
// ---------------------------------------------------------------------------

/**
 * Admits a target only by comparing its STORED IDs with the principal's
 * resolved IDs, byte for byte. No name field is read; there is none to read.
 *
 * Whether an organisation is the operator org (the fleet) is read from
 * `lookups.orgKindOf`; a missing or throwing adapter refuses.
 *
 *   - An absent principal, or one with an empty ID, is refused.
 *   - A `kind: "fleet"` principal outside the operator org is refused, and so
 *     is a `kind: "service"` principal inside it (the operator org's service
 *     account is the fleet). An agent or person of the operator org is an
 *     ordinary member of it (RULING 5).
 *   - An unstamped target (no `orgId`) is refused to EVERY principal, the
 *     fleet principal included. No right is inferred from an absence: a fleet
 *     row carries the operator org's ID explicitly, and a row with no
 *     organisation is never treated as a master row.
 *   - An operator-org row is refused to every client principal.
 *   - Otherwise the target's `orgId` must equal the principal's. A fleet
 *     principal reaches a client organisation's row only when the door sets
 *     `fleetCrossOrg` (a master export) AND `orgKindOf` reports that
 *     organisation as `"client"`; an unknown organisation is refused. Any
 *     other principal reaching across organisations under `fleetCrossOrg`
 *     claims the fleet scope and is refused `reserved-fleet-scope`.
 *   - `ownerOnly`: the target's `ownerId` must also equal `principalId`; an
 *     absent owner is refused.
 */
export async function assertTargetBelongsTo(
  principal: ActingPrincipal | null | undefined,
  target: TargetIds | null | undefined,
  lookups: OrgKindLookups,
  opts: AssertTargetOptions = {},
): Promise<AssertTargetResult> {
  const door = opts.door ?? "assertTargetBelongsTo";
  if (
    principal === null ||
    typeof principal !== "object" ||
    !nonEmpty(principal.principalId) ||
    !nonEmpty(principal.orgId)
  ) {
    return denied("credential-invalid", door, "No resolved principal stands behind this call.");
  }

  const principalKind = await loadOrgKind(lookups, principal.orgId, door);
  if (!principalKind.ok) return principalKind;
  const inFleet = principalKind.kind === "operator";
  const isFleet = principal.kind === "fleet";
  if ((isFleet && !inFleet) || (inFleet && principal.kind === "service")) {
    return denied("reserved-fleet-scope", door, "The principal does not hold the fleet scope.");
  }

  const targetOrg = target?.orgId;
  if (!nonEmpty(targetOrg)) {
    return denied("target-unstamped", door, "The target carries no organisation, so it is not reachable.");
  }
  if (targetOrg !== principal.orgId) {
    const targetKind = await loadOrgKind(lookups, targetOrg, door);
    if (!targetKind.ok) return targetKind;
    if (targetKind.kind === "operator") {
      return denied("reserved-fleet-scope", door, "The target is in the fleet scope.");
    }
    if (!isFleet && opts.fleetCrossOrg === true) {
      return denied(
        "reserved-fleet-scope",
        door,
        "Cross-organisation reach is held only by the operator organisation's service account.",
      );
    }
    const masterExport = isFleet && opts.fleetCrossOrg === true && targetKind.kind === "client";
    if (!masterExport) {
      return denied("target-other-organisation", door, "The target belongs to another organisation.");
    }
  }

  if (opts.ownerOnly === true) {
    const owner = target?.ownerId;
    if (!nonEmpty(owner) || owner !== principal.principalId) {
      return denied("target-owner-mismatch", door, "Only the target's owner may act on it.");
    }
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// assertOrgAdmin (0.12.0)
// ---------------------------------------------------------------------------

export type AssertOrgAdminOptions = {
  /**
   * The role values that count as organisation admin, exactly as the verified
   * claim spells them (for Clerk: `["org:admin"]`). Data supplied by the
   * consumer; an empty or malformed list admits nobody.
   */
  adminRoles: readonly string[];
  /** The consumer's name for the door; carried on every refusal. */
  door?: string;
};

export type AssertOrgAdminResult = { ok: true } | { ok: false; refusal: IdentityRefusal };

/**
 * Admits a principal as ADMIN of the target organisation, deciding by ID only.
 * The principal must come from `resolveActingPrincipal`; the role is the
 * verified claim its person credential carried (`verifiedOrgRole`), so no host
 * lookup is needed and none is read here.
 *
 *   - An absent principal, or one with an empty ID, is refused.
 *   - Only a PERSON is an organisation admin. An agent, a service account and
 *     the fleet principal are refused `principal-not-a-person`, whatever they
 *     carry: the service account keeps its own rules and never becomes an
 *     admin through this check.
 *   - The target organisation must be present and byte-equal to the
 *     principal's stored organisation: an admin of A is not an admin of B.
 *   - The role must be byte-equal to one entry of `adminRoles`. An absent
 *     role, an unknown role, and an empty or malformed `adminRoles` refuse.
 *     No case folding, no prefix stripping, no default role.
 */
export function assertOrgAdmin(
  principal: ActingPrincipal | null | undefined,
  targetOrgId: string | null | undefined,
  opts: AssertOrgAdminOptions,
): AssertOrgAdminResult {
  const door = opts?.door ?? "assertOrgAdmin";
  if (
    principal === null ||
    typeof principal !== "object" ||
    !nonEmpty(principal.principalId) ||
    !nonEmpty(principal.orgId)
  ) {
    return denied("credential-invalid", door, "No resolved principal stands behind this call.");
  }
  if (principal.kind !== "person") {
    return denied(
      "principal-not-a-person",
      door,
      "Only a person is an organisation admin; this principal is not a person.",
    );
  }
  if (!nonEmpty(targetOrgId)) {
    return denied("target-unstamped", door, "No target organisation was named, so none is administered.");
  }
  if (targetOrgId !== principal.orgId) {
    return denied(
      "target-other-organisation",
      door,
      "The target organisation is not the principal's organisation.",
    );
  }
  const adminRoles = opts?.adminRoles;
  const rolesValid =
    Array.isArray(adminRoles) && adminRoles.length > 0 && adminRoles.every((r) => nonEmpty(r));
  const role = principal.orgRole;
  if (!rolesValid || !nonEmpty(role) || !adminRoles.includes(role)) {
    return denied("role-not-admin", door, "The principal's role is not an organisation-admin role.");
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// assertPrincipalListed (0.13.0)
// ---------------------------------------------------------------------------

/**
 * A stored list of principal IDs scoped to one organisation, for example a
 * client's roster of agents. Every entry is an ID; a name is never an entry.
 */
export type PrincipalIdList = {
  /** The organisation the list is stored under. */
  orgId: string;
  /** Stored principal (agent) IDs, compared byte for byte. */
  principalIds: readonly string[];
};

export type AssertPrincipalListedOptions = {
  /** The consumer's name for the door; carried on every refusal. */
  door?: string;
};

export type AssertPrincipalListedResult = { ok: true } | { ok: false; refusal: IdentityRefusal };

/**
 * Admits a principal only when its AGENT ID is an entry of a stored list that
 * belongs to its own organisation. The principal must come from
 * `resolveActingPrincipal`; synchronous, no lookup, no name read anywhere.
 *
 * Refusal by default. Each of these refuses with a typed `RBAC_DENIED`
 * carrying the door (default `"assertPrincipalListed"`):
 *
 *   - an absent principal, or one with an empty ID or organisation
 *     (`credential-invalid`). A principal carrying only a name has no ID.
 *   - a principal that is not `kind: "agent"` (`principal-not-an-agent`): the
 *     list holds agent IDs, so a person, a service account and the fleet
 *     principal are not admitted by it. An agent acting through a service
 *     account is `kind: "agent"` and is judged by its own ID.
 *   - an absent list (`list-absent`).
 *   - a list with a missing or empty `orgId` (`target-unstamped`), or one
 *     stored under another organisation (`target-other-organisation`).
 *   - an empty or malformed `principalIds` (`list-empty`).
 *   - an ID that is not byte-equal to an entry (`principal-not-listed`). No
 *     case folding, no trimming, no prefix match.
 *
 * There is no wildcard: a `"*"` entry is an ordinary string, never "everyone".
 * The fleet sentinel is out of scope here.
 */
export function assertPrincipalListed(
  principal: ActingPrincipal | null | undefined,
  list: PrincipalIdList | null | undefined,
  opts?: AssertPrincipalListedOptions,
): AssertPrincipalListedResult {
  const door = opts?.door ?? "assertPrincipalListed";
  if (
    principal === null ||
    typeof principal !== "object" ||
    !nonEmpty(principal.principalId) ||
    !nonEmpty(principal.orgId)
  ) {
    return denied("credential-invalid", door, "No resolved principal stands behind this call.");
  }
  if (principal.kind !== "agent") {
    return denied(
      "principal-not-an-agent",
      door,
      "The list holds agent IDs; this principal is not an agent.",
    );
  }
  if (list === null || list === undefined || typeof list !== "object") {
    return denied("list-absent", door, "No list was supplied, so nobody is listed.");
  }
  if (!nonEmpty(list.orgId)) {
    return denied("target-unstamped", door, "The list carries no organisation, so it admits nobody.");
  }
  if (list.orgId !== principal.orgId) {
    return denied(
      "target-other-organisation",
      door,
      "The list belongs to another organisation than the principal.",
    );
  }
  const ids = list.principalIds;
  if (!Array.isArray(ids) || ids.length === 0) {
    return denied("list-empty", door, "The list holds no principal IDs, so nobody is listed.");
  }
  if (!ids.some((id) => id === principal.principalId)) {
    return denied("principal-not-listed", door, "The principal's ID is not on the list.");
  }
  return { ok: true };
}

// ---------------------------------------------------------------------------
// assertRecipientAddressable (0.13.0)
// ---------------------------------------------------------------------------

/** The recipient of a message, named by its stored agent ID and organisation ID. */
export type RecipientIds = {
  /** The recipient agent's stored ID. */
  agentId: string;
  /** The recipient agent's stored organisation ID. */
  orgId: string;
};

/**
 * The lookups `assertRecipientAddressable` reads: the organisation kind, and
 * the stored roster of agent IDs of one organisation (a client's list of the
 * fleet agents it may reach). `null`, a miss or a throw is an unresolvable
 * roster and refuses.
 */
export type RecipientLookups = OrgKindLookups & {
  rosterOf?: Lookup<[orgId: string], PrincipalIdList>;
};

export type AssertRecipientAddressableOptions = {
  /** The consumer's name for the door; carried on every refusal. */
  door?: string;
};

export type AssertRecipientAddressableResult = { ok: true } | { ok: false; refusal: IdentityRefusal };

/**
 * Decides whether a sender may address a recipient, across organisations
 * included, by AGENT ID only. The sender must come from
 * `resolveActingPrincipal`. No name is read anywhere; a name never matches.
 *
 * Admitted iff one of these holds:
 *   (a) same organisation: the sender's `orgId` equals the recipient's;
 *   (b) client to operator: the sender is in a client organisation, the
 *       recipient is in the operator organisation, and the RECIPIENT's ID is
 *       on the SENDER organisation's roster;
 *   (c) operator to client: the sender is in the operator organisation, the
 *       recipient is in a client organisation, and the SENDER's ID is on the
 *       RECIPIENT organisation's roster.
 *
 * Everything else is refused with a typed `RBAC_DENIED` carrying the door
 * (default `"assertRecipientAddressable"`): an absent sender or one without an
 * ID (`credential-invalid`), a sender that is not `kind: "agent"`
 * (`principal-not-an-agent`), an absent recipient or one without an agent ID
 * or organisation (`target-unstamped`), client to client across organisations
 * and an organisation kind that is neither operator nor client
 * (`target-other-organisation`), a missing or throwing `orgKindOf` /
 * `rosterOf` (`principal-lookup-failed`), an absent roster (`list-absent`), and
 * a roster that is empty, stored under the wrong organisation or does not list
 * the ID (the refusals of {@link assertPrincipalListed}, which is reused for
 * that check).
 */
export async function assertRecipientAddressable(
  sender: ActingPrincipal | null | undefined,
  recipient: RecipientIds | null | undefined,
  lookups: RecipientLookups,
  opts?: AssertRecipientAddressableOptions,
): Promise<AssertRecipientAddressableResult> {
  const door = opts?.door ?? "assertRecipientAddressable";
  if (
    sender === null ||
    typeof sender !== "object" ||
    !nonEmpty(sender.principalId) ||
    !nonEmpty(sender.orgId)
  ) {
    return denied("credential-invalid", door, "No resolved sender stands behind this call.");
  }
  if (sender.kind !== "agent") {
    return denied("principal-not-an-agent", door, "Only an agent addresses a recipient; the sender is not an agent.");
  }
  if (
    recipient === null ||
    typeof recipient !== "object" ||
    !nonEmpty(recipient.agentId) ||
    !nonEmpty(recipient.orgId)
  ) {
    return denied("target-unstamped", door, "The recipient carries no agent ID and organisation.");
  }
  if (recipient.orgId === sender.orgId) return { ok: true };

  const senderKind = await loadOrgKind(lookups, sender.orgId, door);
  if (!senderKind.ok) return senderKind;
  const recipientKind = await loadOrgKind(lookups, recipient.orgId, door);
  if (!recipientKind.ok) return recipientKind;

  let clientOrgId: string;
  let listed: { principalId: string };
  if (senderKind.kind === "client" && recipientKind.kind === "operator") {
    clientOrgId = sender.orgId;
    listed = { principalId: recipient.agentId };
  } else if (senderKind.kind === "operator" && recipientKind.kind === "client") {
    clientOrgId = recipient.orgId;
    listed = { principalId: sender.principalId };
  } else {
    return denied(
      "target-other-organisation",
      door,
      "The recipient belongs to another organisation that this sender may not reach.",
    );
  }

  const rosterOf = lookups?.rosterOf;
  if (typeof rosterOf !== "function") {
    return denied("principal-lookup-failed", door, "No lookup was supplied for the roster.");
  }
  let roster: PrincipalIdList | null | undefined;
  try {
    roster = await rosterOf(clientOrgId);
  } catch {
    return denied("principal-lookup-failed", door, "The roster could not be read, so none is resolved.");
  }
  return assertPrincipalListed({ ...listed, orgId: clientOrgId, kind: "agent" }, roster, { door });
}
