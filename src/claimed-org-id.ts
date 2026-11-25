import { resolveTenantIdOrAbsent } from "./org-guard.js";

/**
 * The one reader of a verified credential's organisation ID claim. Internal:
 * not exported from the package. Two modes share the shape check and the
 * final pass through `resolveTenantIdOrAbsent`; they differ only in which
 * claim names are read and what an invalid value does.
 *
 * - `"first-valid"` (default): names `org_id`, `organizationId`, `orgId`; an
 *   invalid value is skipped and the next name is tried. Used by
 *   `requireTenantFromIdentity`, `resolveOrgFromClaim` and
 *   `resolveTenantFromAccessToken`, unchanged since they shipped.
 * - `"first-present"`: names `org_id`, `orgId`, nested `o.id`, in that order
 *   (a Clerk Convex JWT consumer's `org_id ?? orgId ?? o?.id`). The FIRST name
 *   whose value is not null/undefined decides; an invalid value there is an
 *   absence and never falls through. `organizationId` is not read. Used by
 *   `tenantFromIdentityOrAbsent`.
 */
const CLERK_ORG_ID_SHAPE = /^org_[A-Za-z0-9]+$/;

/**
 * Whether the `"first-present"` reader requires the Clerk `org_` shape.
 * Ruled `true` on 2026-11-25: one
 * shape rule for every door, so a non-empty value such as `"acme"` is refused.
 * The `"first-valid"` readers always require the shape.
 */
const IDENTITY_READER_REQUIRES_ORG_SHAPE = true;

const FIRST_VALID_CLAIMS = ["org_id", "organizationId", "orgId"] as const;

export type ClaimReadMode = "first-valid" | "first-present";

export type ClaimedOrgIdRead =
  | { present: true; orgId: string }
  | { present: false; reason: "no-organization-claim" | "invalid-organization-claim" };

function acceptedOrgId(value: unknown, requireShape: boolean): string | undefined {
  if (typeof value !== "string") return undefined;
  if (requireShape && !CLERK_ORG_ID_SHAPE.test(value)) return undefined;
  const resolved = resolveTenantIdOrAbsent({ kind: "session", identity: { orgId: value } });
  return resolved.present ? resolved.tenantId : undefined;
}

function firstPresentValues(claims: Record<string, unknown>): unknown[] {
  const o = claims.o;
  const nested = typeof o === "object" && o !== null ? (o as Record<string, unknown>).id : undefined;
  return [claims.org_id, claims.orgId, nested];
}

export function readClaimedOrgId(claims: Record<string, unknown>, mode: ClaimReadMode): ClaimedOrgIdRead {
  if (mode === "first-present") {
    const decider = firstPresentValues(claims).find((value) => value !== null && value !== undefined);
    if (decider === undefined) return { present: false, reason: "no-organization-claim" };
    const orgId = acceptedOrgId(decider, IDENTITY_READER_REQUIRES_ORG_SHAPE);
    return orgId === undefined
      ? { present: false, reason: "invalid-organization-claim" }
      : { present: true, orgId };
  }

  let sawClaim = false;
  for (const name of FIRST_VALID_CLAIMS) {
    const value = claims[name];
    if (value !== null && value !== undefined) sawClaim = true;
    const orgId = acceptedOrgId(value, true);
    if (orgId !== undefined) return { present: true, orgId };
  }
  return { present: false, reason: sawClaim ? "invalid-organization-claim" : "no-organization-claim" };
}

export function claimedOrgId(
  claims: Record<string, unknown>,
  mode: ClaimReadMode = "first-valid",
): string | undefined {
  const read = readClaimedOrgId(claims, mode);
  return read.present ? read.orgId : undefined;
}
