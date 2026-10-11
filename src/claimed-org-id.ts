import { resolveTenantIdOrAbsent } from "./org-guard.js";

/**
 * The one reader of a verified credential's organisation ID claim, shared by
 * `resolveOrgFromClaim` and `resolveTenantFromAccessToken`. Internal: not
 * exported from the package.
 */
const CLERK_ORG_ID_SHAPE = /^org_[A-Za-z0-9]+$/;
const ID_CLAIMS = ["org_id", "organizationId", "orgId"] as const;

export function claimedOrgId(claims: Record<string, unknown>): string | undefined {
  for (const name of ID_CLAIMS) {
    const value = claims[name];
    if (typeof value !== "string" || !CLERK_ORG_ID_SHAPE.test(value)) continue;
    const resolved = resolveTenantIdOrAbsent({ kind: "session", identity: { orgId: value } });
    if (resolved.present) return resolved.tenantId;
  }
  return undefined;
}
