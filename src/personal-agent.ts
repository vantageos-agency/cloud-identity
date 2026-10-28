/**
 * The agent a person acts as.
 *
 * A PERSON signed in through an OAuth connector acts as the person. An operator
 * may designate, per person, ONE agent of the person's organisation as that
 * person's personal agent (the agent row stores the person's ID). This module is
 * the one decision "which agent does this person act as": the consumer injects
 * the BY-ID read of the agents that designate the person, and this module
 * decides.
 *
 * The rule, with no part left to the consumer:
 *
 *   - the agents considered are those whose stored organisation ID equals the
 *     person's organisation ID AND whose stored designation equals the person's
 *     ID. An agent of another organisation is never selected and never counted;
 *   - EXACTLY ONE active such agent: the person acts as it. The agent is then
 *     re-read by ID and judged by `resolveActingPrincipal` (active, stamped with
 *     the organisation, the organisation active);
 *   - none, or only inactive ones: the person stays the person;
 *   - more than one active: ambiguous, the person stays the person. Nothing
 *     picks one of several;
 *   - a lookup that is absent, throws, or returns a malformed row is a typed
 *     refusal, never a default and never "the person": a failed read must not
 *     silently change who is acting. Its error text is never surfaced.
 *
 * It only RESOLVES. It writes nothing and grants nothing the agent does not
 * already hold; the door still compares stored IDs with the principal returned.
 *
 * @security `personId` and `orgId` must be the consumer's VERIFIED person and
 * organisation (the stored IDs of a live person token), never a request
 * argument. The designation is the operator's data; this module cannot prove the
 * operator designated the right agent.
 */

import { z } from "zod";
import { type IdentityRefusal, refusal } from "./identity-refusal.js";
import {
  type ActingPrincipal,
  type PrincipalLookups,
  principalRowSchema,
  resolveActingPrincipal,
} from "./principal-by-id.js";

/** One agent row that designates a person, in the package's vocabulary. */
const personalAgentRowSchema = principalRowSchema.extend({
  /** The person ID the agent row stores as its designation. */
  personalAgentOf: z.string().min(1),
});
export type PersonalAgentRow = z.input<typeof personalAgentRowSchema>;

export type PersonalAgentInput = {
  /** The verified person's stored ID. */
  personId: string;
  /** The verified organisation's stored ID, the one the agents are stamped with. */
  orgId: string;
};

export type PersonalAgentDeps = {
  /**
   * Indexed read BY ID: the agent rows of `orgId` whose designation equals
   * `personId`. A bounded read; the module re-checks every row it is given.
   */
  designatedAgents: (
    personId: string,
    orgId: string,
  ) => Promise<readonly PersonalAgentRow[] | null | undefined> | readonly PersonalAgentRow[] | null | undefined;
  /** `agentById`, `organisationById`, `orgKindOf`: the reads `resolveActingPrincipal` makes for an agent. */
  principalLookups: PrincipalLookups;
};

export type PersonalAgentOptions = {
  /** The consumer's name for the door; carried on every refusal. */
  door?: string;
};

/** Why the person stays the person. */
export type PersonalAgentStayReason = "none" | "inactive" | "ambiguous";

export type PersonalAgentResult =
  | { ok: true; actingAs: "agent"; principal: ActingPrincipal }
  | { ok: true; actingAs: "person"; reason: PersonalAgentStayReason }
  | { ok: false; refusal: IdentityRefusal };

/**
 * Resolves which principal a verified person acts as: the one active agent that
 * designates them, or the person. Refusals (RBAC_DENIED, naming the door):
 *
 *   - "credential-invalid"          an empty person or organisation ID (no lookup is made);
 *   - "principal-lookup-failed"     the designation lookup was not supplied or threw
 *     (its text is never surfaced);
 *   - "principal-record-invalid"    a returned row is not well formed;
 *   - "principal-not-found" / "principal-inactive" / "organisation-not-active" and the other
 *     `resolveActingPrincipal` reasons, for the one selected agent.
 *
 * @callerResolver — resolves a verified caller; consumers may derive their accepted sinks from this tag.
 */
export async function resolvePersonalAgent(
  input: PersonalAgentInput,
  deps: PersonalAgentDeps,
  options?: PersonalAgentOptions,
): Promise<PersonalAgentResult> {
  const door = options?.door ?? "resolvePersonalAgent";
  const refuse = (
    reason: Parameters<typeof refusal>[1],
    detail: string,
  ): { ok: false; refusal: IdentityRefusal } => ({
    ok: false,
    refusal: refusal("RBAC_DENIED", reason, door, detail),
  });

  const personId = input?.personId;
  const orgId = input?.orgId;
  if (typeof personId !== "string" || personId === "" || typeof orgId !== "string" || orgId === "") {
    return refuse("credential-invalid", "The call carries no verified person and organisation identified by ID.");
  }
  if (typeof deps?.designatedAgents !== "function") {
    return refuse("principal-lookup-failed", "No lookup was supplied for the personal agent.");
  }

  let raw: readonly unknown[] | null | undefined;
  try {
    raw = await deps.designatedAgents(personId, orgId);
  } catch {
    return refuse("principal-lookup-failed", "The personal agent could not be read, so none is resolved.");
  }

  const active: z.output<typeof personalAgentRowSchema>[] = [];
  let designated = 0;
  for (const candidate of raw ?? []) {
    const parsed = personalAgentRowSchema.safeParse(candidate);
    if (!parsed.success) {
      return refuse("principal-record-invalid", "A personal-agent record is not well formed.");
    }
    const row = parsed.data;
    // Another organisation's agent, or one that designates someone else, is not a
    // candidate: it is neither selected nor counted toward ambiguity.
    if (row.orgId !== orgId || row.personalAgentOf !== personId) continue;
    designated += 1;
    if (row.active === true) active.push(row);
  }

  if (active.length === 0) {
    return { ok: true, actingAs: "person", reason: designated === 0 ? "none" : "inactive" };
  }
  if (active.length > 1) return { ok: true, actingAs: "person", reason: "ambiguous" };

  const resolved = await resolveActingPrincipal(
    { kind: "agent", agentId: active[0].id, verifiedOrgId: orgId },
    deps.principalLookups,
    door,
  );
  if (!resolved.ok) return { ok: false, refusal: resolved.refusal };
  return { ok: true, actingAs: "agent", principal: resolved.principal };
}
