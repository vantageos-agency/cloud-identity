/**
 * The ordinary MEMBER scope (0.30.0).
 *
 * A consumer's org-scope resolver hands doors a scope object. For a member (not
 * the fleet, not the operator's admin) that object is the resolved
 * organisation's row plus the verified principal, copied field by field. This
 * module is that copy, so a consumer assembles nothing itself and cannot get a
 * field wrong (an `isMaster` that is not false, a roster taken from the wrong
 * row, a label used as the organisation's identity).
 *
 * The result is a plain object of the shape `scopeStanding` reads as "member".
 * It is never master: `isMaster` and `fleetWide` are the literal `false`, and
 * no `masterSource` is set. Pure: no store is read.
 *
 * Fail closed: an organisation without a permanent ID or a label, a malformed
 * roster, a principal without a subject, or a principal whose organisation ID
 * is not the row's is a typed refusal, never a partial scope.
 */

import { type IdentityRefusal, refusal } from "./identity-refusal.js";
import type { ResolvedOrg } from "./org-by-id.js";
import type { PersonPrincipal } from "./person-principal.js";

/**
 * The member scope: what a door branches on for a caller bound to one organisation.
 *
 * DECLARED DIVERGENCE from a consumer's own scope object: there is no
 * `allowedOrchestrators` here. That field is the legacy NAME roster (names are
 * labels, not identity; deprecated since 0.24.0) and no export of this package
 * takes a name as an input. A consumer whose remaining legacy readers still need
 * it adds that one field from its own row until its contract phase removes it.
 */
export type MemberScope = {
  /** The verified subject of the caller. */
  userId: string;
  /** The organisation's CURRENT label. Display text, never identity. */
  orgSlug: string;
  /** The organisation's permanent ID: rows belong to an organisation by this value. */
  orgClerkId: string;
  /** The roster by agent ID; `[]` when the row stores none (nothing is admitted). */
  allowedAgentIds: string[];
  fleetWide: false;
  scopes: string[];
  isMaster: false;
  /** The caller's verified role in this organisation, verbatim; absent when none. */
  orgRole?: string;
};

/**
 * The fields of a resolved organisation the member scope reads. A `ResolvedOrg`
 * satisfies it; the legacy name roster is deliberately not among them.
 */
export type MemberScopeOrg = Pick<ResolvedOrg, "id" | "label" | "allowedAgentIds" | "scopes">;

/** The verified actor a member scope is built for. */
export type MemberActor = {
  userId: string;
  /** The verified role claim, when the credential carried one. Never defaulted. */
  orgRole?: string | null;
  /**
   * The permanent ID of the organisation the actor was verified in, when the
   * credential carried one. When present it must equal the resolved
   * organisation's ID; absent, the scope is built for the organisation given.
   */
  orgId?: string | null;
};

export type MemberScopeOptions = {
  /** The consumer's name for the door; carried on every refusal. */
  door?: string;
};

export type MemberScopeResult =
  | { ok: true; scope: MemberScope }
  | { ok: false; refusal: IdentityRefusal };

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function stringList(value: unknown): string[] | null {
  if (value === undefined) return [];
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) return null;
  return [...value];
}

/**
 * Builds the member scope of `org` for `actor`, or refuses.
 *
 * Checks, in order: the organisation is well formed (permanent ID, label,
 * well-formed rosters and scopes: `org-mapping-record-invalid`); the actor has a
 * subject (`no-verified-subject`); the actor's organisation ID, when it carries
 * one, is the row's (`other-organisation`, compared by ID, never by label).
 */
export function memberScopeFrom(
  org: MemberScopeOrg,
  actor: MemberActor,
  options?: MemberScopeOptions,
): MemberScopeResult {
  const door = options?.door ?? "memberScopeFrom";
  const deny = (reason: Parameters<typeof refusal>[1], detail: string): MemberScopeResult => ({
    ok: false,
    refusal: refusal("RBAC_DENIED", reason, door, detail),
  });

  const row = org as Partial<MemberScopeOrg> | null | undefined;
  const agentIds = stringList(row?.allowedAgentIds);
  const scopes = row?.scopes === undefined ? null : stringList(row.scopes);
  if (
    row === null ||
    row === undefined ||
    !nonEmpty(row.id) ||
    !nonEmpty(row.label) ||
    agentIds === null ||
    scopes === null
  ) {
    return deny("org-mapping-record-invalid", "The organisation mapping record is not well formed.");
  }
  if (actor === null || actor === undefined || !nonEmpty(actor.userId)) {
    return deny("no-verified-subject", "The credential carries no verified subject.");
  }
  if (actor.orgId !== undefined && actor.orgId !== null && actor.orgId !== row.id) {
    return deny("other-organisation", "The caller was verified in another organisation.");
  }
  return {
    ok: true,
    scope: {
      userId: actor.userId,
      orgSlug: row.label,
      orgClerkId: row.id,
      allowedAgentIds: agentIds,
      fleetWide: false,
      scopes,
      isMaster: false,
      ...(typeof actor.orgRole === "string" ? { orgRole: actor.orgRole } : {}),
    },
  };
}

/**
 * {@link memberScopeFrom} for a resolved person: the subject becomes `userId`,
 * the verified role and the organisation ID (when the token carried one) are
 * the principal's own.
 */
export function memberScopeOfPerson(
  org: MemberScopeOrg,
  principal: PersonPrincipal,
  options?: MemberScopeOptions,
): MemberScopeResult {
  return memberScopeFrom(
    org,
    {
      userId: principal?.subject,
      ...(principal?.orgRole !== undefined ? { orgRole: principal.orgRole } : {}),
      ...(principal?.orgId !== undefined ? { orgId: principal.orgId } : {}),
    },
    options,
  );
}
