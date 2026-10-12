/**
 * One entry from a VERIFIED credential's claims to the caller (0.20.0).
 *
 * A consumer that holds a verified identity (a Clerk session's claim record)
 * used to chain three package calls itself: `resolveOrgFromClaim` (which
 * organisation, by the verified `org_id`), `resolveActingPrincipal` (the person
 * stored in that organisation) and `assertOrgAdmin` (is that person an admin of
 * it). The chain, the role-claim spellings and the "does the token claim an
 * organisation at all" test were each re-read in the consumer. This function is
 * that chain, once:
 *
 *   claims -> org (by org_id) -> person principal in that org -> role -> isOrgAdmin
 *
 * It decides nothing new: every decision is the existing primitive's, in the
 * same order, with the same refusals. A label (slug) claim never selects an
 * organisation.
 */

import { personActorName } from "./person-principal.js";
import { type IdentityRefusal, refusal } from "./identity-refusal.js";
import { type OrgMappingLookups, type ResolvedOrg, resolveOrgFromClaim } from "./org-by-id.js";
import {
  type ActingPrincipal,
  type PrincipalLookups,
  assertOrgAdmin,
  resolveActingPrincipal,
} from "./principal-by-id.js";

export type CallerFromClaimsDeps = {
  /** The mapping store, read by `resolveOrgFromClaim` (only `orgById` is used). */
  orgLookups: OrgMappingLookups;
  /** The principal store, read by `resolveActingPrincipal` for a person. */
  principalLookups: PrincipalLookups;
};

export type CallerFromClaimsOptions = {
  /** The roles that make a person an admin of their organisation, byte-equal. Non-empty. */
  adminRoles: readonly string[];
  /** The consumer's name for the door; carried on every refusal. */
  door?: string;
};

export type CallerFromClaimsResult =
  | {
      ok: true;
      /** The verified subject. */
      subject: string;
      /** `user:<subject>`, the person's actor name. */
      actorName: string;
      /** The organisation, resolved by the verified `org_id`. */
      org: ResolvedOrg;
      /** The person, as stored in that organisation. */
      principal: ActingPrincipal;
      /** The verified role claim, or null when the credential carries none. */
      role: string | null;
      /** True when `role` is one of `adminRoles` in this organisation (`assertOrgAdmin`). */
      isOrgAdmin: boolean;
    }
  | {
      ok: false;
      refusal: IdentityRefusal;
      /**
       * True when the claims NAME an organisation (an id or a slug, in any
       * spelling) that did not resolve. Lets a consumer tell "signed in with no
       * organisation" from "claims an organisation it cannot prove"; it is
       * never an organisation itself.
       */
      claimsOrg: boolean;
      /**
       * The verified subject, when the claims carried one (0.20.1). A consumer
       * that decides some callers by subject before any organisation (a fleet
       * service account) reads it here, never from the credential. Absent when
       * the refusal is the missing subject itself.
       */
      subject?: string;
    };

const ROLE_KEYS = ["orgRole", "org_role", "organizationRole"] as const;
const ORG_CLAIM_KEYS = ["organizationSlug", "org_slug", "organizationId", "org_id", "orgId"] as const;

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/** The verified org role claim, under any of its spellings, or null. */
export function readOrgRoleClaim(claims: Record<string, unknown>): string | null {
  for (const key of ROLE_KEYS) {
    if (nonEmpty(claims[key])) return claims[key] as string;
  }
  return null;
}

/** Whether the claims name any organisation (id or slug, any spelling). Chooses a refusal's shape, never an org. */
export function claimsAnOrganisation(claims: Record<string, unknown>): boolean {
  return ORG_CLAIM_KEYS.some((key) => claims[key] !== undefined && claims[key] !== null);
}

/**
 * Resolves the caller behind a verified claim record: organisation by `org_id`,
 * the person stored in it, the role claim and whether that role is an admin
 * role there; or a typed refusal with `claimsOrg`.
 *
 * @callerResolver — resolves a verified caller; consumers may derive their accepted sinks from this tag.
 */
export async function resolveCallerFromClaims(
  claims: Record<string, unknown> | null | undefined,
  deps: CallerFromClaimsDeps,
  options: CallerFromClaimsOptions,
): Promise<CallerFromClaimsResult> {
  const adminRoles = options?.adminRoles;
  if (!Array.isArray(adminRoles) || adminRoles.length === 0 || !adminRoles.every(nonEmpty)) {
    throw new TypeError("resolveCallerFromClaims: `adminRoles` must name at least one role.");
  }
  const door = options.door ?? "resolveCallerFromClaims";
  const record: Record<string, unknown> =
    claims !== null && typeof claims === "object" && !Array.isArray(claims) ? claims : {};
  const claimsOrg = claimsAnOrganisation(record);

  const subject = record.subject ?? record.sub;
  if (!nonEmpty(subject)) {
    return {
      ok: false,
      claimsOrg,
      refusal: refusal("RBAC_DENIED", "credential-invalid", door, "The verified claims carry no subject."),
    };
  }

  const resolved = await resolveOrgFromClaim(record, deps?.orgLookups, { door });
  if (!resolved.ok) return { ok: false, claimsOrg, subject, refusal: resolved.refusal };
  const org = resolved.org;

  const role = readOrgRoleClaim(record);
  const person = await resolveActingPrincipal(
    {
      kind: "person",
      personId: subject,
      verifiedOrgId: org.id,
      ...(role !== null ? { verifiedOrgRole: role } : {}),
    },
    deps?.principalLookups,
    door,
  );
  if (!person.ok) return { ok: false, claimsOrg, subject, refusal: person.refusal };

  const isOrgAdmin = assertOrgAdmin(person.principal, org.id, { adminRoles, door }).ok;
  return {
    ok: true,
    subject,
    actorName: personActorName(subject),
    org,
    principal: person.principal,
    role,
    isOrgAdmin,
  };
}
