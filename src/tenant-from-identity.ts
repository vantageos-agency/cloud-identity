import { claimedOrgId } from "./claimed-org-id.js";
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
