import { refusal, type IdentityRefusal } from "./identity-refusal.js";
import { claimedOrgId } from "./claimed-org-id.js";
import { personActorName } from "./person-principal.js";
import {
  verifyMcpAccessToken,
  type McpResourceServerConfig,
} from "./resource-server.js";

/**
 * Session to tenant: the one answer to "which person, in which organisation, is
 * behind this access token?" for a server that is an OAuth resource.
 *
 * A downstream server hands over the `Authorization` header and the same
 * resource-server config it already uses to guard its routes. The token is
 * verified by `verifyMcpAccessToken` (signature, issuer, audience, expiry), and
 * only then is the claim record read. This module never verifies anything
 * itself and never reads a claim off a token that was not verified: a
 * downstream server never touches a raw claim.
 *
 * The organisation comes from the verified token's `org_id` claim (the ID, e.g.
 * `org_2abc...`). `organizationId` and `orgId` are accepted as the same claim
 * under their other spellings. A slug (`org_slug`) is a label: it is never read
 * and never rescues a missing ID. A verified token that carries no usable
 * organisation ID is refused (`no-verified-organisation`, HTTP 403): the answer
 * is never an unscoped or master view.
 */

/** The person behind a verified access token. */
export type TokenPrincipal = {
  /** The verified subject (`sub`). */
  subject: string;
  /** How the person is recorded as "who did it": `user:<subject>`. */
  actorName: string;
  /** The verified `org_role` claim, or null when the token carries none. */
  role: string | null;
};

export type ResolveTenantFromAccessTokenResult =
  | { ok: true; principal: TokenPrincipal; orgId: string }
  // Not verified: 401 with an RFC 6750 challenge, or 503 when the key set is unreachable.
  | {
      ok: false;
      status: 401;
      refusal: IdentityRefusal;
      headers: { "WWW-Authenticate": string };
    }
  | { ok: false; status: 503; refusal: IdentityRefusal }
  // Verified, but no organisation to scope to.
  | { ok: false; status: 403; refusal: IdentityRefusal };

/**
 * Resolves `{ principal, orgId }` from an `Authorization` header, or fails with
 * a typed refusal. Never returns an org for a token that did not verify; never
 * returns undefined in silence. `nowMs` is injectable for tests.
 */
export async function resolveTenantFromAccessToken(
  authorization: string | undefined,
  config: McpResourceServerConfig,
  nowMs: number = Date.now(),
): Promise<ResolveTenantFromAccessTokenResult> {
  const verified = await verifyMcpAccessToken(authorization, config, nowMs);
  if (!verified.ok) return verified;

  const { userId, claims } = verified.session;
  const orgId = claimedOrgId({ ...claims });
  if (orgId === undefined) {
    return {
      ok: false,
      status: 403,
      refusal: refusal(
        "RBAC_DENIED",
        "no-verified-organisation",
        config.door ?? "resolveTenantFromAccessToken",
        "The access token verified but carries no organisation ID.",
      ),
    };
  }
  const role = typeof claims.org_role === "string" && claims.org_role.length > 0 ? claims.org_role : null;
  return {
    ok: true,
    orgId,
    principal: { subject: userId, actorName: personActorName(userId), role },
  };
}
