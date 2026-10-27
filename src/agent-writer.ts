/**
 * The agent behind a write the fleet service account makes on its behalf.
 *
 * A Convex mutation reached through the MCP transport is called by the fleet
 * service account. When the write is an agent's, the transport has already
 * verified which agent (its stored ID and organisation ID) and carries that
 * claim as an argument. The claim is only as good as the caller that presents
 * it, so a door must not decide identity itself: this module is the one
 * decision. It resolves the claim to the stored agent principal, or throws.
 *
 * It only RESOLVES. It writes nothing and returns no permission to write. The
 * door still writes, and still compares the stored IDs of the row it touches
 * with `principalId` / `orgId` of the principal returned here.
 *
 * Every step reuses an existing primitive and adds no rule of its own:
 *
 *   1. the caller must be the fleet service account (`requireServiceAccountStanding`);
 *   2. the claim must be exactly `{ agentId, orgId }`, IDs only (strict: a name beside
 *      the IDs refuses it whole);
 *   3. when the call names its target organisation, the claim must be for it;
 *   4. the agent is read by ID and must be active, stamped with the claim's
 *      organisation, and that organisation active (`resolveActingPrincipal`).
 *
 * Nothing is resolved by a name, and nothing falls back to a default principal.
 *
 * @security `verifiedActor` must be the transport's own result of verifying the
 * agent, never a value the end client chose. This module proves that the caller
 * is the service account and that the IDs name one live agent of that
 * organisation; it cannot prove the transport verified the right agent.
 */

import { z } from "zod";
import { IdentityRefusalError, refusal } from "./identity-refusal.js";
import { type ActingPrincipal, type PrincipalLookups, resolveActingPrincipal } from "./principal-by-id.js";
import { requireServiceAccountStanding } from "./scope-standing.js";

const verifiedActorSchema = z.strictObject({
  agentId: z.string().min(1),
  orgId: z.string().min(1),
});

/** The transport-verified claim: the agent's stored ID and the organisation ID it was verified in. */
export type AgentWriterClaim = z.input<typeof verifiedActorSchema>;

export type AgentWriterInput = {
  /** The caller's resolved scope; it must be the fleet service account's. */
  scope: unknown;
  /** The `verifiedActor` claim the transport carried; absent or malformed is refused. */
  verifiedActor: AgentWriterClaim | null | undefined;
  /** The organisation ID the call acts in, when the call names one; the claim must be for it. */
  targetOrgId?: string | null;
};

export type AgentWriterDeps = {
  /**
   * Indexed reads BY ID. Used: `agentById`, `organisationById`, `orgKindOf`
   * (the same three `resolveActingPrincipal` reads for an agent).
   */
  principalLookups: PrincipalLookups;
};

export type AgentWriterOptions = {
  /** The consumer's name for the door; carried on every refusal. */
  door?: string;
};

/**
 * Resolves a service-account agent write to the stored agent principal
 * `{ principalId, orgId, kind: "agent" }`, or throws `IdentityRefusalError`
 * RBAC_DENIED naming the door:
 *
 *   - "scope-not-resolved" / "standing-not-allowed"  the caller is not the service account
 *     (a member, the internal opt-in and an operator admin are all refused);
 *   - "credential-invalid"       `verifiedActor` is absent, or is not exactly `{ agentId, orgId }`;
 *   - "other-organisation"       the claim is for another organisation than `targetOrgId`, or
 *     the stored agent sits in another organisation than the claim;
 *   - "principal-not-found" / "principal-inactive" / "principal-record-invalid" /
 *     "principal-lookup-failed"  the agent lookup missed, found a deactivated or malformed
 *     row, was not supplied, or threw (its text is never surfaced);
 *   - "organisation-not-active"  the organisation is not mapped or not active.
 *
 * @callerResolver — resolves a verified caller; consumers may derive their accepted sinks from this tag.
 */
export async function resolveAgentWriter(
  input: AgentWriterInput,
  deps: AgentWriterDeps,
  options?: AgentWriterOptions,
): Promise<ActingPrincipal> {
  const door = options?.door ?? "resolveAgentWriter";

  requireServiceAccountStanding(input?.scope, door);

  const parsed = verifiedActorSchema.safeParse(input?.verifiedActor);
  if (!parsed.success) {
    throw new IdentityRefusalError(
      refusal("RBAC_DENIED", "credential-invalid", door, "The call carries no verified agent identified by ID."),
    );
  }
  const claim = parsed.data;

  const target = input.targetOrgId;
  if (target !== undefined && target !== null && target !== claim.orgId) {
    throw new IdentityRefusalError(
      refusal(
        "RBAC_DENIED",
        "other-organisation",
        door,
        "The verified agent belongs to another organisation than the one this call acts in.",
      ),
    );
  }

  const resolved = await resolveActingPrincipal(
    { kind: "agent", agentId: claim.agentId, verifiedOrgId: claim.orgId },
    deps?.principalLookups,
    door,
  );
  if (!resolved.ok) throw new IdentityRefusalError(resolved.refusal);
  return resolved.principal;
}
