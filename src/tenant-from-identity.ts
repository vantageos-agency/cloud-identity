import { claimedOrgId, readClaimedOrgId } from "./claimed-org-id.js";
import { IdentityRefusalError, refusal } from "./identity-refusal.js";

/**
 * The tenant of a caller whose identity the host has ALREADY verified — for a
 * Convex function, the object `ctx.auth.getUserIdentity()` returns (or null).
 *
 * The organisation ID claim is read by the package's one claim reader
 * (`claimedOrgId`: the same three claim names and the same Clerk `org_` shape
 * as `resolveOrgFromClaim` and `resolveTenantFromAccessToken`), so a consumer
 * never reads `org_id` itself. No identity, no claim, or a claim that is not
 * an organisation ID refuses with `RBAC_DENIED` / `no-verified-organisation`;
 * there is no fallback to a slug, a name or a default tenant.
 *
 * This function does not verify anything: it trusts the host to have checked
 * the token's signature and issuer before handing the identity over.
 *
 * @callerResolver — resolves a verified caller; consumers may derive their accepted sinks from this tag.
 */
export function requireTenantFromIdentity(
  identity: Record<string, unknown> | null | undefined,
  options: { door: string },
): string {
  const tenantId = identity ? claimedOrgId(identity) : undefined;
  if (tenantId === undefined) {
    throw new IdentityRefusalError(
      refusal(
        "RBAC_DENIED",
        "no-verified-organisation",
        options.door,
        identity
          ? "The verified identity carries no organisation ID."
          : "No verified identity was presented.",
      ),
    );
  }
  return tenantId;
}

/**
 * Why `tenantFromIdentityOrAbsent` found no tenant: no identity at all, no
 * organisation claim name present, or the first present claim is not an
 * organisation ID.
 */
export type IdentityTenantAbsenceReason = "no-identity" | "no-organization-claim" | "invalid-organization-claim";

/**
 * Result of `tenantFromIdentityOrAbsent`. Branch on `present`. The absence
 * carries the same `TENANT_ABSENT` code as `resolveTenantIdOrAbsent`'s, and
 * never the claim value.
 */
export type IdentityTenantResolution =
  | { present: true; tenantId: string }
  | { present: false; absence: { code: "TENANT_ABSENT"; reason: IdentityTenantAbsenceReason } };

/**
 * NON-throwing sibling of `requireTenantFromIdentity`, for a READ path (a
 * subscribed Convex query, where a throw crashes a mounted render). Takes an
 * identity the host has ALREADY verified (`ctx.auth.getUserIdentity()`, or
 * null) and returns `{ present: true, tenantId }` or a typed absence; it never
 * throws.
 *
 * Claim order is the one a Clerk Convex consumer reads by hand
 * (`org_id ?? orgId ?? o?.id`): the FIRST of `org_id`, `orgId`, nested
 * `o.id` whose value is not null/undefined decides. An invalid value there
 * (empty, non-string, not a Clerk `org_` ID) is an absence; it never falls
 * through to the next name. `organizationId` is not read. This order differs
 * from `requireTenantFromIdentity`, which keeps its own (`org_id`,
 * `organizationId`, `orgId`, skipping invalid values).
 *
 * @callerResolver — resolves a verified caller; consumers may derive their accepted sinks from this tag.
 */
export function tenantFromIdentityOrAbsent(
  identity: Record<string, unknown> | null | undefined,
): IdentityTenantResolution {
  const absent = (reason: IdentityTenantAbsenceReason): IdentityTenantResolution => ({
    present: false,
    absence: { code: "TENANT_ABSENT", reason },
  });
  if (identity === null || identity === undefined || typeof identity !== "object") return absent("no-identity");
  const read = readClaimedOrgId(identity, "first-present");
  return read.present ? { present: true, tenantId: read.orgId } : absent(read.reason);
}

/**
 * The subject (the person or service the session belongs to) of an identity
 * the host has ALREADY verified — for a Convex function, the object
 * `ctx.auth.getUserIdentity()` returns (or null). Use it for an audit stamp
 * such as `createdBy`, so a consumer never reads `identity.subject` itself.
 * No identity, or a subject that is not a non-empty string, refuses with
 * `RBAC_DENIED` / `no-verified-subject`; there is no fallback to a name or a
 * default actor. Like `requireTenantFromIdentity`, it verifies nothing itself.
 *
 * @callerResolver — resolves a verified caller; consumers may derive their accepted sinks from this tag.
 */
export function requireSubjectFromIdentity(
  identity: Record<string, unknown> | null | undefined,
  options: { door: string },
): string {
  const subject = identity?.subject;
  if (typeof subject !== "string" || subject === "") {
    throw new IdentityRefusalError(
      refusal(
        "RBAC_DENIED",
        "no-verified-subject",
        options.door,
        identity ? "The verified identity carries no subject." : "No verified identity was presented.",
      ),
    );
  }
  return subject;
}
