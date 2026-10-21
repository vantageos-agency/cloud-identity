/**
 * Agent link: an explicit, revocable channel between ONE agent of an
 * organisation and ONE agent of another, by ID only.
 *
 * Organisations are isolated: an agent cannot message or assign a task to an
 * agent of another organisation. A link is the one deliberate exception, and
 * it is as narrow as it can be written:
 *
 *   - DIRECTIONAL. A row says `fromAgentId` may reach `toAgentId`; it says
 *     nothing about the reverse. "Both ways" is two rows.
 *   - GRANTED BY THE TARGET SIDE. The row is activated by an ADMIN member of
 *     the TARGET agent's organisation (`toOrgId`): the side that receives the
 *     traffic decides to accept it. An admin of the source organisation, or a
 *     plain member of the target organisation, cannot create it.
 *   - EXACT PAIR. A third agent of the same two organisations is not covered.
 *   - STANDING. No expiry; revocation (`revokedAt`) is the off switch.
 *   - VOIDED BY THE GRANTOR LEAVING. At every request the grantor must still be
 *     an active ADMIN member of `toOrgId`. A grantor who has been removed, has
 *     lost the admin role, or whose membership is inactive voids the link,
 *     without any write to the row. The consumer may re-grant by a current
 *     admin.
 *
 * The identity decision lives here; the consumer supplies storage only:
 *
 *   - `buildAgentLink` validates an activation and returns the row to store.
 *   - `resolveAgentLink` decides, per request, from the stored row, and
 *     reports every attempt (granted or refused) to the consumer's audit sink.
 *
 * Nothing here reads a name: agents, persons and organisations are identified
 * by stored ID. A name addressed across organisations stays refused, because
 * no path here accepts one.
 *
 * @security The refusals never echo another row's IDs or its reason text, and a
 * lookup error is reported by kind only, never by its message.
 */

import { type IdentityRefusal, refusal } from "./identity-refusal.js";
import { type PrincipalRow, principalRowSchema } from "./principal-by-id.js";
import { type MembershipRecord, resolveMembership } from "./tenant-membership.js";

/** Minimum length of the reason, the same as a support grant. */
const MIN_REASON_LENGTH = 10;

/** The row the consumer stores. One row per direction. */
export type StoredAgentLink = {
  /** The agent that is allowed to reach the other one. */
  fromAgentId: string;
  /** The organisation `fromAgentId` belongs to. */
  fromOrgId: string;
  /** The agent that may be reached. */
  toAgentId: string;
  /** The organisation `toAgentId` belongs to; the grantor administers it. */
  toOrgId: string;
  /** The stored ID of the person, admin of `toOrgId`, who granted the link. */
  grantedBy: string;
  grantedAt: number;
  revokedAt: number | null;
  reason: string;
};

type Lookup<A extends unknown[], R> = (
  ...args: A
) => Promise<R | null | undefined> | R | null | undefined;

/** Reads BY ID, supplied by the consumer. Storage only. */
export type AgentLinkLookups = {
  /** An agent's stored row by its ID: `{ id, orgId, active }`. */
  lookupAgent: Lookup<[agentId: string], PrincipalRow>;
  /** A person's membership of ONE organisation: `{ active, role, orgId? }`. */
  lookupMembership: Lookup<[personId: string, orgId: string], MembershipRecord>;
  /**
   * The role values that count as organisation admin, exactly as the stored
   * membership spells them (for Clerk: `["org:admin"]`). Required; an empty or
   * malformed list admits nobody.
   */
  adminRoles: readonly string[];
};

export type BuildAgentLinkInput = {
  fromAgentId: string;
  fromOrgId: string;
  toAgentId: string;
  toOrgId: string;
  /** The stored ID of the person who grants: an admin of `toOrgId`. */
  grantedBy: string;
  /** Why the link is granted; at least 10 characters. */
  reason: string;
  /** Epoch milliseconds at activation. */
  now: number;
};

export type BuildAgentLinkDeps = AgentLinkLookups;

export type BuildAgentLinkResult =
  | { ok: true; link: StoredAgentLink }
  | { ok: false; refusal: IdentityRefusal };

export type AgentLinkEvent =
  | {
      outcome: "granted";
      fromAgentId: string;
      fromOrgId: string;
      toAgentId: string;
      toOrgId: string;
      door: string;
      reason: string;
      grantedBy: string;
      at: number;
    }
  | {
      outcome: "refused";
      fromAgentId: string;
      fromOrgId: string;
      toAgentId: string;
      door: string;
      /** The refusal reason word, e.g. `agent-link-absent`. */
      reason: string;
      at: number;
    };

export type ResolveAgentLinkInput = {
  /** The calling agent, as resolved by ID: its stored ID and organisation. */
  fromAgent: { agentId: string; orgId: string };
  /** The stored ID of the agent being reached. */
  toAgentId: string;
  /** The consumer's own name for the entry point asking. */
  door: string;
};

export type ResolveAgentLinkDeps = AgentLinkLookups & {
  /** Reads the stored link for exactly this (from, to) pair, or nothing. */
  lookupAgentLink: Lookup<[fromAgentId: string, toAgentId: string], StoredAgentLink>;
  /** Injectable clock, epoch milliseconds. */
  now?: () => number;
  /** Audit sink. Must not throw; if it does, the throw is swallowed and the outcome stands. */
  onAgentLink?: (event: AgentLinkEvent) => void;
};

export type ResolveAgentLinkResult =
  | {
      ok: true;
      toAgentId: string;
      toOrgId: string;
      link: { reason: string; grantedBy: string; grantedAt: number };
    }
  | { ok: false; refusal: IdentityRefusal };

function nonEmpty(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0;
}

function validAdminRoles(roles: unknown): roles is readonly string[] {
  return Array.isArray(roles) && roles.length > 0 && roles.every((r) => nonEmpty(r));
}

function lookupKind(err: unknown): string {
  return err instanceof Error ? err.name : typeof err;
}

function deny(
  reason: Parameters<typeof refusal>[1],
  door: string,
  detail: string,
): { ok: false; refusal: IdentityRefusal } {
  return { ok: false, refusal: refusal("RBAC_DENIED", reason, door, detail) };
}

type AgentCheck = "ok" | "unavailable" | "lookup-failed";

/** An agent is usable when its stored row repeats its ID, names exactly this organisation, and is active. */
async function checkAgent(
  lookupAgent: AgentLinkLookups["lookupAgent"],
  agentId: string,
  orgId: string,
): Promise<{ verdict: AgentCheck; kind?: string }> {
  let row: unknown;
  try {
    row = await lookupAgent(agentId);
  } catch (err) {
    return { verdict: "lookup-failed", kind: lookupKind(err) };
  }
  const parsed = principalRowSchema.safeParse(row);
  if (!parsed.success) return { verdict: "unavailable" };
  const r = parsed.data;
  if (r.id !== agentId || r.orgId !== orgId || r.active !== true) return { verdict: "unavailable" };
  return { verdict: "ok" };
}

type GrantorCheck = "admin" | "not-admin" | "lookup-failed";

/** The grantor must be an ACTIVE member of `orgId` whose stored role is an admin role. */
async function checkGrantorAdmin(
  deps: AgentLinkLookups,
  personId: string,
  orgId: string,
  door: string,
): Promise<{ verdict: GrantorCheck; kind?: string }> {
  // resolveMembership reports a throwing lookup without its kind; keep the kind here.
  let thrownKind: string | undefined;
  const m = await resolveMembership({
    subject: personId,
    orgId,
    lookup: async (subject, org) => {
      try {
        return await deps.lookupMembership(subject, org);
      } catch (err) {
        thrownKind = lookupKind(err);
        throw err;
      }
    },
    door,
  });
  if (!m.ok) {
    return m.refusal.reason === "membership-lookup-failed"
      ? { verdict: "lookup-failed", kind: thrownKind }
      : { verdict: "not-admin" };
  }
  const role = m.membership.role;
  if (!validAdminRoles(deps.adminRoles) || role === null || !deps.adminRoles.includes(role)) {
    return { verdict: "not-admin" };
  }
  return { verdict: "admin" };
}

function depsUsable(deps: Partial<AgentLinkLookups> | null | undefined): deps is AgentLinkLookups {
  return (
    !!deps &&
    typeof deps.lookupAgent === "function" &&
    typeof deps.lookupMembership === "function" &&
    validAdminRoles(deps.adminRoles)
  );
}

/**
 * Validates an agent link activation and returns the row to store.
 *
 * Proves, through the consumer's lookups, that `grantedBy` is an active ADMIN
 * member of `toOrgId` (the TARGET organisation), that both agents exist, are
 * active and belong to the organisations stated, that the two organisations
 * differ, and that the reason is not trivial. One call makes one direction.
 */
export async function buildAgentLink(
  input: BuildAgentLinkInput,
  deps: BuildAgentLinkDeps,
): Promise<BuildAgentLinkResult> {
  const door = "buildAgentLink";
  const invalid = (detail: string) => deny("agent-link-invalid", door, detail);
  if (!depsUsable(deps)) {
    return invalid("The agent, membership lookups and the admin role list are required.");
  }
  if (!input || typeof input !== "object") return invalid("The link input is missing.");
  if (!nonEmpty(input.fromAgentId)) return invalid("The source agent ID is required.");
  if (!nonEmpty(input.fromOrgId)) return invalid("The source organisation ID is required.");
  if (!nonEmpty(input.toAgentId)) return invalid("The target agent ID is required.");
  if (!nonEmpty(input.toOrgId)) return invalid("The target organisation ID is required.");
  if (!nonEmpty(input.grantedBy)) return invalid("The granting person ID is required.");
  if (typeof input.reason !== "string" || input.reason.trim().length < MIN_REASON_LENGTH) {
    return invalid(`A reason of at least ${MIN_REASON_LENGTH} characters is required.`);
  }
  if (typeof input.now !== "number" || !Number.isFinite(input.now)) {
    return invalid("The activation time is required.");
  }
  if (input.fromOrgId === input.toOrgId) {
    return deny(
      "agent-link-same-organisation",
      door,
      "Both agents are in one organisation; a link is for agents of different organisations.",
    );
  }

  const grantor = await checkGrantorAdmin(deps, input.grantedBy, input.toOrgId, door);
  if (grantor.verdict === "lookup-failed") {
    return deny("agent-link-lookup-failed", door, `The membership lookup failed (${grantor.kind}).`);
  }
  if (grantor.verdict === "not-admin") {
    return deny(
      "agent-link-grantor-not-admin",
      door,
      "The grantor is not an admin of the target organisation.",
    );
  }

  for (const [agentId, orgId] of [
    [input.fromAgentId, input.fromOrgId],
    [input.toAgentId, input.toOrgId],
  ] as const) {
    const checked = await checkAgent(deps.lookupAgent, agentId, orgId);
    if (checked.verdict === "lookup-failed") {
      return deny("agent-link-lookup-failed", door, `The agent lookup failed (${checked.kind}).`);
    }
    if (checked.verdict === "unavailable") {
      return deny(
        "agent-link-agent-unavailable",
        door,
        "An agent is not found, not active, or not in the organisation stated.",
      );
    }
  }

  return {
    ok: true,
    link: {
      fromAgentId: input.fromAgentId,
      fromOrgId: input.fromOrgId,
      toAgentId: input.toAgentId,
      toOrgId: input.toOrgId,
      grantedBy: input.grantedBy,
      grantedAt: input.now,
      revokedAt: null,
      reason: input.reason,
    },
  };
}

function isStoredShape(row: unknown): row is StoredAgentLink {
  if (!row || typeof row !== "object") return false;
  const r = row as Record<string, unknown>;
  return (
    nonEmpty(r.fromAgentId) &&
    nonEmpty(r.fromOrgId) &&
    nonEmpty(r.toAgentId) &&
    nonEmpty(r.toOrgId) &&
    r.fromOrgId !== r.toOrgId &&
    nonEmpty(r.grantedBy) &&
    typeof r.reason === "string" &&
    typeof r.grantedAt === "number" &&
    Number.isFinite(r.grantedAt) &&
    (r.revokedAt === null ||
      r.revokedAt === undefined ||
      (typeof r.revokedAt === "number" && Number.isFinite(r.revokedAt)))
  );
}

/**
 * Whether the calling agent may reach `toAgentId` in another organisation under
 * a stored link. Denied by default: only a stored, non-revoked row for exactly
 * this (from, to) pair admits, and only while the target agent is still active
 * in `toOrgId` and the grantor is still an active admin of `toOrgId`. Every
 * outcome is reported to `onAgentLink`.
 *
 * @callerResolver — resolves a verified caller; consumers may derive their accepted sinks from this tag.
 */
export async function resolveAgentLink(
  input: ResolveAgentLinkInput,
  deps: ResolveAgentLinkDeps,
): Promise<ResolveAgentLinkResult> {
  const door = nonEmpty(input?.door) ? input.door : "resolveAgentLink";
  const clock = typeof deps?.now === "function" ? deps.now : Date.now;
  const at = clock();
  const fromAgentId = nonEmpty(input?.fromAgent?.agentId) ? input.fromAgent.agentId : "";
  const fromOrgId = nonEmpty(input?.fromAgent?.orgId) ? input.fromAgent.orgId : "";
  const toAgentId = typeof input?.toAgentId === "string" ? input.toAgentId : "";

  const emit = (event: AgentLinkEvent): void => {
    if (typeof deps?.onAgentLink !== "function") return;
    try {
      deps.onAgentLink(event);
    } catch {
      // A failing audit sink must never change an authorization outcome.
    }
  };
  const refuse = (reason: Parameters<typeof refusal>[1], detail: string): ResolveAgentLinkResult => {
    emit({ outcome: "refused", fromAgentId, fromOrgId, toAgentId, door, reason, at });
    return deny(reason, door, detail);
  };

  if (
    !depsUsable(deps) ||
    typeof deps.lookupAgentLink !== "function" ||
    fromAgentId === "" ||
    fromOrgId === "" ||
    !nonEmpty(toAgentId)
  ) {
    return refuse("agent-link-invalid", "The calling agent, the target agent ID and the lookups are required.");
  }

  let row: StoredAgentLink | null | undefined;
  try {
    row = await deps.lookupAgentLink(fromAgentId, toAgentId);
  } catch (err) {
    return refuse("agent-link-lookup-failed", `The agent link lookup failed (${lookupKind(err)}).`);
  }
  if (row === null || row === undefined) {
    return refuse("agent-link-absent", "No agent link exists for this pair.");
  }
  if (!isStoredShape(row)) {
    return refuse("agent-link-invalid", "The stored agent link is not readable.");
  }
  if (row.fromAgentId !== fromAgentId || row.toAgentId !== toAgentId || row.fromOrgId !== fromOrgId) {
    return refuse("agent-link-mismatch", "The stored agent link is not for this pair.");
  }
  if (row.revokedAt !== null && row.revokedAt !== undefined) {
    return refuse("agent-link-revoked", "The agent link was revoked.");
  }

  const target = await checkAgent(deps.lookupAgent, toAgentId, row.toOrgId);
  if (target.verdict === "lookup-failed") {
    return refuse("agent-link-lookup-failed", `The agent lookup failed (${target.kind}).`);
  }
  if (target.verdict === "unavailable") {
    return refuse("agent-link-agent-unavailable", "The target agent is not available in its organisation.");
  }

  const grantor = await checkGrantorAdmin(deps, row.grantedBy, row.toOrgId, door);
  if (grantor.verdict === "lookup-failed") {
    return refuse("agent-link-lookup-failed", `The membership lookup failed (${grantor.kind}).`);
  }
  if (grantor.verdict === "not-admin") {
    return refuse("agent-link-grantor-void", "The link no longer stands: its grantor is not a current admin.");
  }

  emit({
    outcome: "granted",
    fromAgentId,
    fromOrgId,
    toAgentId,
    toOrgId: row.toOrgId,
    door,
    reason: row.reason,
    grantedBy: row.grantedBy,
    at,
  });
  return {
    ok: true,
    toAgentId,
    toOrgId: row.toOrgId,
    link: { reason: row.reason, grantedBy: row.grantedBy, grantedAt: row.grantedAt },
  };
}
