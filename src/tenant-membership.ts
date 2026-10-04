/**
 * Membership resolution, row-in-tenant visibility and the org-admin proof.
 *
 * The package cannot query a datastore, so the membership read is an INJECTED
 * async lookup. Everything that can be got wrong stays here: a throwing lookup,
 * a miss, an inactive row, a row of the wrong shape and a row that names a
 * different organisation are all refusals. Nothing in this module returns a
 * grant on an error path.
 *
 * Identifiers are OPAQUE and compared byte-for-byte: no trimming, no case
 * folding, and never a slug compared against an id (supply the same kind of
 * identifier on both sides).
 */

import { z } from "zod";
import {
  IdentityRefusalError,
  refusal,
  type IdentityRefusal,
} from "./identity-refusal.js";

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

// ---------------------------------------------------------------------------
// Row in tenant
// ---------------------------------------------------------------------------

/**
 * True only when the row is stamped with an organisation, the caller has one,
 * and the two are strictly equal. An unstamped row is NEVER visible, including
 * to a caller that also has no organisation (absence equals absence is not a
 * match).
 */
export function isRowInTenant(input: {
  rowOrgId: string | null | undefined;
  callerOrgId: string | null | undefined;
}): boolean {
  const { rowOrgId, callerOrgId } = input;
  return nonEmpty(rowOrgId) && nonEmpty(callerOrgId) && rowOrgId === callerOrgId;
}

// ---------------------------------------------------------------------------
// Membership
// ---------------------------------------------------------------------------

/**
 * What the consumer's lookup returns for (subject, organisation).
 * `orgId`, when the row carries it, is re-checked here so a loose lookup (a
 * prefix match, a wrong index) cannot become a membership in another org.
 */
export const membershipRecordSchema = z.object({
  active: z.boolean(),
  role: z.string().nullish(),
  orgId: z.string().nullish(),
});

export type MembershipRecord = z.infer<typeof membershipRecordSchema>;

export type ResolvedMembership = {
  subject: string;
  orgId: string;
  /** The role the record carries, or null when it carries none. */
  role: string | null;
};

export type ResolveMembershipInput = {
  /** The verified subject. Never a client-supplied argument. */
  subject: string;
  /** The verified organisation id. */
  orgId: string;
  /** Indexed read of one membership. Return null/undefined on a miss. */
  lookup: (
    subject: string,
    orgId: string,
  ) => Promise<MembershipRecord | null | undefined> | MembershipRecord | null | undefined;
  door?: string;
};

export type ResolveMembershipResult =
  | { ok: true; membership: ResolvedMembership }
  | { ok: false; refusal: IdentityRefusal };

function deny(
  reason: Parameters<typeof refusal>[1],
  door: string,
  detail: string,
): { ok: false; refusal: IdentityRefusal } {
  return { ok: false, refusal: refusal("RBAC_DENIED", reason, door, detail) };
}

/**
 * Resolve the membership of a verified subject in a verified organisation via
 * the injected `lookup`. Only `active === true` on a well-shaped record that
 * names no other organisation is served. The lookup's own error text is never
 * surfaced.
 */
export async function resolveMembership(
  input: ResolveMembershipInput,
): Promise<ResolveMembershipResult> {
  const door = input.door ?? "resolveMembership";
  if (typeof input?.lookup !== "function") {
    // A programming error in the consumer, not a claim about any caller.
    throw new TypeError("resolveMembership: lookup must be a function.");
  }
  const { subject, orgId, lookup } = input;
  if (!nonEmpty(subject) || !nonEmpty(orgId)) {
    return deny(
      "membership-invalid-input",
      door,
      "A verified subject and a verified organisation are both required.",
    );
  }

  let record: unknown;
  try {
    record = await lookup(subject, orgId);
  } catch {
    return deny(
      "membership-lookup-failed",
      door,
      "The membership could not be read, so none is granted.",
    );
  }

  if (record === null || record === undefined) {
    return deny("membership-not-found", door, "No membership for this subject in this organisation.");
  }
  const parsed = membershipRecordSchema.safeParse(record);
  if (!parsed.success) {
    return deny("membership-record-invalid", door, "The membership record is not well formed.");
  }
  const row = parsed.data;
  if (nonEmpty(row.orgId) && row.orgId !== orgId) {
    return deny("other-organisation", door, "The membership belongs to another organisation.");
  }
  if (row.active !== true) {
    return deny("membership-inactive", door, "The membership is not active.");
  }
  return {
    ok: true,
    membership: { subject, orgId, role: nonEmpty(row.role) ? row.role : null },
  };
}

// ---------------------------------------------------------------------------
// Org-admin proof
// ---------------------------------------------------------------------------

export type RequireOrgAdminInput = {
  /** The organisation the credential was VERIFIED for (a verified claim). */
  verifiedOrgId: string | null | undefined;
  /** The organisation the action is aimed at. Must equal `verifiedOrgId`. */
  targetOrgId: string | null | undefined;
  /** The caller's verified role. */
  role: string | null | undefined;
  /** Roles that count as organisation admin: data, supplied by the consumer. */
  adminRoles: readonly string[];
  door?: string;
};

/**
 * An org-admin proof is bound to the caller's own verified organisation: the
 * target must equal it, and the role must be one of `adminRoles`. Being an
 * admin somewhere is not being an admin of the target. Throws
 * `IdentityRefusalError`; returns nothing when served. An empty `adminRoles`
 * admits nobody.
 */
export function requireOrgAdmin(input: RequireOrgAdminInput): void {
  const door = input.door ?? "requireOrgAdmin";
  const { verifiedOrgId, targetOrgId, role, adminRoles } = input;
  const fail = (
    reason: Parameters<typeof refusal>[1],
    detail: string,
  ): never => {
    throw new IdentityRefusalError(refusal("RBAC_DENIED", reason, door, detail));
  };

  if (!nonEmpty(verifiedOrgId)) {
    fail("no-verified-organisation", "The caller has no verified organisation.");
  }
  if (!nonEmpty(targetOrgId) || targetOrgId !== verifiedOrgId) {
    fail("other-organisation", "The target organisation is not the caller's verified organisation.");
  }
  if (!nonEmpty(role) || !Array.isArray(adminRoles) || !adminRoles.includes(role)) {
    fail("role-not-admin", "The caller's role is not an organisation-admin role.");
  }
}
