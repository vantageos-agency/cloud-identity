/**
 * @vantageos/cloud-identity 0.4.0 — Human-path resolver (Clerk → { tenant,
 * subject, role }).
 *
 * Additive-only: does not import any Clerk SDK, and does not modify any
 * existing export. The caller resolves a Clerk session (or any session
 * provider with an equivalent shape) *outside* this package and passes in a
 * plain, already-resolved object; this module only normalizes it into the
 * package's contract.
 *
 * `role` is a NEW literal union (`owner | admin | member | client`),
 * distinct from `workspaceRoleSchema` (`Admin | Editor | Viewer`) in
 * `./tenancy-domain.ts` — the two are unrelated vocabularies (workspace
 * membership role vs. organization-account role) and are never conflated.
 *
 * Consistent with the package's "a right is presented, never inferred from
 * an absence" contract: a session with no organization refuses (throws),
 * and an unrecognized/absent Clerk org role refuses (throws) rather than
 * silently defaulting to a role.
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// HumanAccountRole
// ---------------------------------------------------------------------------

export const humanAccountRoleSchema = z.enum([
  "owner",
  "admin",
  "member",
  "client",
]);
export type HumanAccountRole = z.infer<typeof humanAccountRoleSchema>;

// ---------------------------------------------------------------------------
// ClerkSessionLike — framework-agnostic input shape
// ---------------------------------------------------------------------------

/**
 * The minimal shape this package needs out of an already-resolved Clerk
 * session (e.g. the object returned by Clerk's own `auth()` in a Next.js
 * server context). No Clerk SDK type is imported — this is a structural
 * shape the caller supplies directly.
 */
export type ClerkSessionLike = {
  orgId?: string | null;
  userId?: string | null;
  orgRole?: string | null;
};

// ---------------------------------------------------------------------------
// ResolvedHumanIdentity
// ---------------------------------------------------------------------------

export type ResolvedHumanIdentity = {
  tenant: string;
  subject: string;
  role: HumanAccountRole;
};

/**
 * Maps Clerk's own org-role strings (`org:admin`, `org:member`, etc. — and
 * their bare forms `admin`, `member`) onto the package's `HumanAccountRole`
 * union. Deliberately explicit and exhaustive-by-throw: any string not
 * listed here is refused rather than silently coerced to a default, per
 * "presented, never inferred from an absence."
 */
const CLERK_ORG_ROLE_MAP: Record<string, HumanAccountRole> = {
  "org:owner": "owner",
  owner: "owner",
  "org:admin": "admin",
  admin: "admin",
  "org:member": "member",
  member: "member",
  "org:client": "client",
  client: "client",
};

/**
 * @security ⚠️ DECODE/NORMALIZE-ONLY. NOT AUTHENTICATION. NOT VERIFICATION.
 *
 * This function does NOT authenticate a request and does NOT verify
 * anything. It NORMALIZES a session that the caller has ALREADY verified
 * upstream — e.g. via Clerk's own server-side `auth()` in a Next.js/Convex
 * server context — into this package's `{ tenant, subject, role }` contract.
 *
 * Passing an unverified, client-supplied object here (for example
 * `req.body`, a query-string payload, or anything else an attacker
 * controls) makes THAT object the trusted source of `tenant`, `subject`,
 * AND `role` — a privilege-escalation bug. The shape checks below (missing
 * orgId/userId/orgRole) only guard against malformed input; they perform
 * NO signature check, NO issuer check, NO session-validity check.
 *
 * Callers MUST verify the session upstream (Clerk `auth()` server-side, or
 * an equivalent signed-session verifier) BEFORE calling this function. Only
 * pass in the object Clerk itself already verified — never pass through an
 * unverified request body.
 *
 * Resolves an already-verified, framework-agnostic Clerk session object into
 * the package's `{ tenant, subject, role }` contract.
 *
 *   - throws when `session` is null/undefined ("Unauthenticated: no
 *     session.") — same refusal message class as `requireTenantId`'s
 *     session branch, for consistent error handling across both resolvers.
 *   - throws when `session.orgId` is missing or empty ("No active
 *     organization on this session...") — human path is cloud fail-closed,
 *     same invariant as `requireTenantId`.
 *   - throws when `session.userId` is missing or empty.
 *   - throws when `session.orgRole` is missing, empty, or not a recognized
 *     Clerk org role (unknown roles are refused, never defaulted).
 *
 * Named to make the already-verified precondition explicit at the
 * call-site — see CHANGELOG.md 0.4.0 for the naming history — mirroring
 * `decodeUnverifiedBearer`'s equivalent rename in `./tenancy-domain.ts`.
 *
 * @example
 * ```ts
 * // session MUST already be verified upstream, e.g.:
 * // const { orgId, userId, orgRole } = await auth(); // Clerk server-side
 * const { tenant, subject, role } = normalizeVerifiedHumanSession({
 *   orgId: "org_abc",
 *   userId: "user_123",
 *   orgRole: "org:admin",
 * });
 * // -> { tenant: "org_abc", subject: "user_123", role: "admin" }
 * ```
 */
export function normalizeVerifiedHumanSession(
  session: ClerkSessionLike | null | undefined,
): ResolvedHumanIdentity {
  if (!session) {
    throw new Error("Unauthenticated: no session.");
  }

  const { orgId, userId, orgRole } = session;

  if (typeof orgId !== "string" || orgId.length === 0) {
    throw new Error(
      "No active organization on this session: select an organization before accessing agents.",
    );
  }

  if (typeof userId !== "string" || userId.length === 0) {
    throw new Error("No user id on this session: cannot resolve subject.");
  }

  if (typeof orgRole !== "string" || orgRole.length === 0) {
    throw new Error(
      "No organization role on this session: role must be presented explicitly, never inferred.",
    );
  }

  const mapped = CLERK_ORG_ROLE_MAP[orgRole];
  if (!mapped) {
    throw new Error(
      `Unrecognized organization role "${orgRole}": expected one of ${Object.keys(
        CLERK_ORG_ROLE_MAP,
      ).join(", ")}.`,
    );
  }

  return { tenant: orgId, subject: userId, role: mapped };
}
