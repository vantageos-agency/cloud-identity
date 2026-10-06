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
