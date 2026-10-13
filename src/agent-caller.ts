/**
 * One entry from a VERIFIED agent credential to the caller: the organisation,
 * the agent, and the human owner it is bound to.
 *
 * The agent twin of `resolveCallerFromClaims`. It decides nothing new: the
 * organisation is read by its permanent ID (`resolveOrgFromClaim`), then the
 * agent and its owner are proven by `resolveActingPrincipal`, in that order.
 * Every identity field is an ID; a name beside the IDs refuses the credential.
 */

import { z } from "zod";
import { type IdentityRefusal, refusal } from "./identity-refusal.js";
import { type OrgMappingLookups, type ResolvedOrg, resolveOrgFromClaim } from "./org-by-id.js";
import { type ActingPrincipal, type PrincipalLookups, resolveActingPrincipal } from "./principal-by-id.js";

const agentCallerCredentialSchema = z.strictObject({
  agentId: z.string().min(1),
  verifiedOrgId: z.string().min(1),
  ownerPersonId: z.string().min(1).optional(),
});

/**
 * A verified agent credential. `ownerPersonId` comes from the consumer's
 * VERIFIED credential row, never from a request argument.
 */
export type AgentCallerCredential = z.input<typeof agentCallerCredentialSchema>;

export type AgentCallerDeps = {
  /** The mapping store, read by `resolveOrgFromClaim` (only `orgById` is used). */
  orgLookups: OrgMappingLookups;
  /** The principal store, read by `resolveActingPrincipal` (agent, owner, organisation). */
  principalLookups: PrincipalLookups;
};

export type AgentCallerOptions = {
  /** The consumer's name for the door; carried on every refusal. */
  door?: string;
};

export type AgentCallerResult =
  | {
      ok: true;
      /** The organisation, resolved by the verified organisation ID. */
      org: ResolvedOrg;
      /** The agent, as stored in that organisation; carries `ownerPersonId` when proven. */
      principal: ActingPrincipal;
      /** The proven owner, a person of the same organisation; `null` when the credential presented none. */
      owner: ActingPrincipal | null;
    }
  | { ok: false; refusal: IdentityRefusal };

/**
 * Resolves the caller behind a verified agent credential: organisation by ID,
 * the agent stored in it, and, when the credential presents `ownerPersonId`,
 * the owner proven against the agent's stored owner and the owner's active
 * membership of the same organisation; or a typed refusal.
 *
 * @callerResolver — resolves a verified caller; consumers may derive their accepted sinks from this tag.
 */
export async function resolveCallerFromAgentCredential(
  credential: AgentCallerCredential | null | undefined,
  deps: AgentCallerDeps,
  options?: AgentCallerOptions,
): Promise<AgentCallerResult> {
  const door = options?.door ?? "resolveCallerFromAgentCredential";
  const parsed = agentCallerCredentialSchema.safeParse(credential);
  if (!parsed.success) {
    return {
      ok: false,
      refusal: refusal("RBAC_DENIED", "credential-invalid", door, "The credential does not identify an agent by ID."),
    };
  }
  const cred = parsed.data;

  const resolved = await resolveOrgFromClaim({ org_id: cred.verifiedOrgId }, deps?.orgLookups, { door });
  if (!resolved.ok) return { ok: false, refusal: resolved.refusal };
  const org = resolved.org;

  const agent = await resolveActingPrincipal(
    {
      kind: "agent",
      agentId: cred.agentId,
      verifiedOrgId: org.id,
      ...(cred.ownerPersonId !== undefined ? { ownerPersonId: cred.ownerPersonId } : {}),
    },
    deps?.principalLookups,
    door,
  );
  if (!agent.ok) return { ok: false, refusal: agent.refusal };

  const ownerId = agent.principal.ownerPersonId;
  const owner: ActingPrincipal | null =
    ownerId === undefined ? null : { principalId: ownerId, orgId: org.id, kind: "person" };
  return { ok: true, org, principal: agent.principal, owner };
}
