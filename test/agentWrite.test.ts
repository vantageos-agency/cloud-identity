import { describe, expect, it, vi } from "vitest";
import {
  IdentityRefusalError,
  type PrincipalLookups,
  type PrincipalRow,
  resolveAgentWriter,
} from "../src/index.js";

/**
 * resolveAgentWriter: the fleet service account calls a mutation on behalf of
 * an agent and carries the transport-verified claim `{ agentId, orgId }`. The
 * package resolves that claim to the stored agent principal, or refuses. The
 * door still writes and compares stored IDs with the resolved IDs.
 */

const SERVICE_ACCOUNT_SCOPE = { isMaster: true, fleetWide: true, masterSource: "service-account" };
const INTERNAL_SCOPE = { isMaster: true, fleetWide: true, masterSource: "internal" };
const OPERATOR_ADMIN_SCOPE = { isMaster: true, fleetWide: true, masterSource: "operator-admin" };
const MEMBER_SCOPE = { isMaster: false, fleetWide: false, orgSlug: "acme", orgClerkId: "org_a" };

const AGENTS: Record<string, PrincipalRow> = {
  agent_a_eta: { id: "agent_a_eta", orgId: "org_a", active: true },
  agent_b_eta: { id: "agent_b_eta", orgId: "org_b", active: true },
  agent_a_off: { id: "agent_a_off", orgId: "org_a", active: false },
};

function lookups(overrides: Partial<PrincipalLookups> = {}): PrincipalLookups {
  return {
    agentById: (id) => AGENTS[id] ?? null,
    organisationById: (id) => ({ id, active: true }),
    orgKindOf: () => "client",
    ...overrides,
  };
}

async function refusalOf(p: Promise<unknown>) {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(IdentityRefusalError);
    return (e as IdentityRefusalError).refusal;
  }
  throw new Error("expected a refusal, the call resolved");
}

describe("resolveAgentWriter", () => {
  it("GREEN: the service account carrying a verified claim resolves to the stored agent and org IDs", async () => {
    const principal = await resolveAgentWriter(
      { scope: SERVICE_ACCOUNT_SCOPE, verifiedActor: { agentId: "agent_a_eta", orgId: "org_a" } },
      { principalLookups: lookups() },
    );
    expect(principal).toEqual({ principalId: "agent_a_eta", orgId: "org_a", kind: "agent" });
  });

  it("GREEN: a call that names its target organisation resolves when the claim is for that organisation", async () => {
    const principal = await resolveAgentWriter(
      {
        scope: SERVICE_ACCOUNT_SCOPE,
        verifiedActor: { agentId: "agent_a_eta", orgId: "org_a" },
        targetOrgId: "org_a",
      },
      { principalLookups: lookups() },
    );
    expect(principal.orgId).toBe("org_a");
  });

  it("GREEN: the agent is read by its ID, once, and no name is ever passed to a lookup", async () => {
    const agentById = vi.fn((id: string) => AGENTS[id] ?? null);
    await resolveAgentWriter(
      { scope: SERVICE_ACCOUNT_SCOPE, verifiedActor: { agentId: "agent_a_eta", orgId: "org_a" } },
      { principalLookups: lookups({ agentById }) },
    );
    expect(agentById).toHaveBeenCalledTimes(1);
    expect(agentById).toHaveBeenCalledWith("agent_a_eta");
  });

  it.each([undefined, null])("RED: a missing verifiedActor (%s) is refused without a lookup", async (claim) => {
    const agentById = vi.fn(() => null);
    const r = await refusalOf(
      resolveAgentWriter(
        { scope: SERVICE_ACCOUNT_SCOPE, verifiedActor: claim },
        { principalLookups: lookups({ agentById }) },
      ),
    );
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe("credential-invalid");
    expect(agentById).not.toHaveBeenCalled();
  });

  it("RED: a claim carrying a name beside the IDs is refused whole", async () => {
    const r = await refusalOf(
      resolveAgentWriter(
        {
          scope: SERVICE_ACCOUNT_SCOPE,
          verifiedActor: { agentId: "agent_a_eta", orgId: "org_a", name: "eta" } as never,
        },
        { principalLookups: lookups() },
      ),
    );
    expect(r.reason).toBe("credential-invalid");
  });

  it.each([
    ["a member", MEMBER_SCOPE, "standing-not-allowed"],
    ["the internal opt-in", INTERNAL_SCOPE, "standing-not-allowed"],
    ["an operator admin", OPERATOR_ADMIN_SCOPE, "standing-not-allowed"],
    ["an unresolved scope", { refused: true }, "scope-not-resolved"],
    ["no scope", undefined, "scope-not-resolved"],
  ])("RED: %s is not the service account, so its claim is refused without a lookup", async (_n, scope, reason) => {
    const agentById = vi.fn(() => AGENTS.agent_a_eta);
    const r = await refusalOf(
      resolveAgentWriter(
        { scope, verifiedActor: { agentId: "agent_a_eta", orgId: "org_a" } },
        { principalLookups: lookups({ agentById }) },
      ),
    );
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe(reason);
    expect(agentById).not.toHaveBeenCalled();
  });

  it("RED: a lookup miss is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriter(
        { scope: SERVICE_ACCOUNT_SCOPE, verifiedActor: { agentId: "agent_ghost", orgId: "org_a" } },
        { principalLookups: lookups() },
      ),
    );
    expect(r.reason).toBe("principal-not-found");
  });

  it("RED: a throwing lookup is refused, never resolved", async () => {
    const r = await refusalOf(
      resolveAgentWriter(
        { scope: SERVICE_ACCOUNT_SCOPE, verifiedActor: { agentId: "agent_a_eta", orgId: "org_a" } },
        {
          principalLookups: lookups({
            agentById: () => {
              throw new Error("db down");
            },
          }),
        },
      ),
    );
    expect(r.reason).toBe("principal-lookup-failed");
    expect(JSON.stringify(r)).not.toContain("db down");
  });

  it("RED: no agent lookup supplied is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriter(
        { scope: SERVICE_ACCOUNT_SCOPE, verifiedActor: { agentId: "agent_a_eta", orgId: "org_a" } },
        { principalLookups: { organisationById: (id) => ({ id, active: true }), orgKindOf: () => "client" } },
      ),
    );
    expect(r.reason).toBe("principal-lookup-failed");
  });

  it("RED: a deactivated agent is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriter(
        { scope: SERVICE_ACCOUNT_SCOPE, verifiedActor: { agentId: "agent_a_off", orgId: "org_a" } },
        { principalLookups: lookups() },
      ),
    );
    expect(r.reason).toBe("principal-inactive");
  });

  it("RED: a mismatched agent (the row returned is another agent) is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriter(
        { scope: SERVICE_ACCOUNT_SCOPE, verifiedActor: { agentId: "agent_a_eta", orgId: "org_a" } },
        { principalLookups: lookups({ agentById: () => AGENTS.agent_b_eta }) },
      ),
    );
    expect(r.reason).toBe("principal-record-invalid");
  });

  it("RED: a mismatched org (the stored agent sits in another organisation than the claim) is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriter(
        { scope: SERVICE_ACCOUNT_SCOPE, verifiedActor: { agentId: "agent_b_eta", orgId: "org_a" } },
        { principalLookups: lookups() },
      ),
    );
    expect(r.reason).toBe("other-organisation");
  });

  it("RED: a mismatched org (the claim is for another organisation than the call targets) is refused without a lookup", async () => {
    const agentById = vi.fn(() => AGENTS.agent_a_eta);
    const r = await refusalOf(
      resolveAgentWriter(
        {
          scope: SERVICE_ACCOUNT_SCOPE,
          verifiedActor: { agentId: "agent_a_eta", orgId: "org_a" },
          targetOrgId: "org_b",
        },
        { principalLookups: lookups({ agentById }) },
      ),
    );
    expect(r.reason).toBe("other-organisation");
    expect(agentById).not.toHaveBeenCalled();
  });

  it("RED: an inactive organisation is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriter(
        { scope: SERVICE_ACCOUNT_SCOPE, verifiedActor: { agentId: "agent_a_eta", orgId: "org_a" } },
        { principalLookups: lookups({ organisationById: (id) => ({ id, active: false }) }) },
      ),
    );
    expect(r.reason).toBe("organisation-not-active");
  });

  it("a refusal carries the door the host named, and no claim", async () => {
    const r = await refusalOf(
      resolveAgentWriter(
        { scope: MEMBER_SCOPE, verifiedActor: { agentId: "agent_a_eta", orgId: "org_a" } },
        { principalLookups: lookups() },
        { door: "debate:postTurn" },
      ),
    );
    expect(r.door).toBe("debate:postTurn");
    expect(JSON.stringify(r)).not.toContain("agent_a_eta");
  });
});
