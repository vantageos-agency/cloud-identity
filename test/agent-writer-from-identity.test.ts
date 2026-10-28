import { describe, expect, it, vi } from "vitest";
import {
  IdentityRefusalError,
  type PrincipalLookups,
  type PrincipalRow,
  resolveAgentWriterFromIdentity,
  type ServiceAccountIdentityLookups,
  type ServiceAccountRow,
} from "../src/index.js";

/**
 * resolveAgentWriterFromIdentity: the same decision as resolveAgentWriter, but
 * the package resolves the caller's standing ITSELF from the identity the host
 * transport verified (for Convex, `ctx.auth.getUserIdentity()`), instead of
 * trusting a scope the consumer resolved locally.
 *
 *   verified subject
 *     -> the stored service-account rows carrying that subject
 *     -> each row's organisation names that row as its own service account
 *     -> the row resolves (resolveActingPrincipal) to the `fleet` principal
 *     -> then the claim `{ agentId, orgId }` resolves to the stored agent.
 */

const OP = "org_op";
const SVC_SUBJECT = "user_svc";

const SERVICE_ROWS: ServiceAccountRow[] = [{ id: "svc_1", orgId: OP, active: true, subject: SVC_SUBJECT }];

const AGENTS: Record<string, PrincipalRow> = {
  agent_a_eta: { id: "agent_a_eta", orgId: "org_a", active: true },
  agent_b_eta: { id: "agent_b_eta", orgId: "org_b", active: true },
};

function principalLookups(overrides: Partial<PrincipalLookups> = {}): PrincipalLookups {
  return {
    agentById: (id) => AGENTS[id] ?? null,
    organisationById: (id) => ({ id, active: true }),
    orgKindOf: (id) => (id === OP ? "operator" : "client"),
    ...overrides,
  };
}

function serviceLookups(overrides: Partial<ServiceAccountIdentityLookups> = {}): ServiceAccountIdentityLookups {
  return {
    serviceAccountsBySubject: (subject) => SERVICE_ROWS.filter((r) => r.subject === subject),
    serviceAccountIdOfOrg: (orgId) => (orgId === OP ? "svc_1" : null),
    ...overrides,
  };
}

function deps(p: Partial<PrincipalLookups> = {}, s: Partial<ServiceAccountIdentityLookups> = {}) {
  return { principalLookups: principalLookups(p), serviceAccountLookups: serviceLookups(s) };
}

const CLAIM = { agentId: "agent_a_eta", orgId: "org_a" };
const SVC_IDENTITY = { subject: SVC_SUBJECT, issuer: "https://clerk.example", tokenIdentifier: "x|user_svc" };

async function refusalOf(p: Promise<unknown>) {
  try {
    await p;
  } catch (e) {
    expect(e).toBeInstanceOf(IdentityRefusalError);
    return (e as IdentityRefusalError).refusal;
  }
  throw new Error("expected a refusal, the call resolved");
}

describe("resolveAgentWriterFromIdentity", () => {
  it("GREEN: the service account's transport identity resolves the claim to the stored agent principal", async () => {
    const principal = await resolveAgentWriterFromIdentity({ identity: SVC_IDENTITY, verifiedActor: CLAIM }, deps());
    expect(principal).toEqual({ principalId: "agent_a_eta", orgId: "org_a", kind: "agent" });
  });

  it("GREEN: the standing is decided by subject; an org claim on the identity neither upgrades nor downgrades it", async () => {
    const principal = await resolveAgentWriterFromIdentity(
      { identity: { ...SVC_IDENTITY, org_id: "org_a", org_role: "org:member" }, verifiedActor: CLAIM, targetOrgId: "org_a" },
      deps(),
    );
    expect(principal.orgId).toBe("org_a");
  });

  it("GREEN: every lookup is keyed by the verified subject or a stored ID, never a name", async () => {
    const bySubject = vi.fn((subject: string) => SERVICE_ROWS.filter((r) => r.subject === subject));
    const idOfOrg = vi.fn((orgId: string) => (orgId === OP ? "svc_1" : null));
    const agentById = vi.fn((id: string) => AGENTS[id] ?? null);
    await resolveAgentWriterFromIdentity(
      { identity: SVC_IDENTITY, verifiedActor: CLAIM },
      deps({ agentById }, { serviceAccountsBySubject: bySubject, serviceAccountIdOfOrg: idOfOrg }),
    );
    expect(bySubject).toHaveBeenCalledWith(SVC_SUBJECT);
    expect(idOfOrg).toHaveBeenCalledWith(OP);
    expect(agentById).toHaveBeenCalledWith("agent_a_eta");
  });

  it.each([undefined, null])("RED: an absent identity (%s) is refused without a lookup", async (identity) => {
    const bySubject = vi.fn(() => SERVICE_ROWS);
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        { identity, verifiedActor: CLAIM },
        deps({}, { serviceAccountsBySubject: bySubject }),
        { door: "debate:postTurn" },
      ),
    );
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe("no-verified-subject");
    expect(r.door).toBe("debate:postTurn");
    expect(bySubject).not.toHaveBeenCalled();
  });

  it.each([
    ["a string", "user_svc"],
    ["an array", [SVC_IDENTITY]],
    ["no subject", { issuer: "x" }],
    ["an empty subject", { subject: "" }],
    ["a non-string subject", { subject: 42 }],
  ])("RED: a malformed identity (%s) is refused without a lookup", async (_n, identity) => {
    const bySubject = vi.fn(() => SERVICE_ROWS);
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        { identity, verifiedActor: CLAIM },
        deps({}, { serviceAccountsBySubject: bySubject }),
        { door: "debate:postTurn" },
      ),
    );
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe("no-verified-subject");
    expect(r.door).toBe("debate:postTurn");
    expect(bySubject).not.toHaveBeenCalled();
  });

  it("RED: a member / person identity (no service account carries its subject) is refused before the claim is read", async () => {
    const agentById = vi.fn(() => AGENTS.agent_a_eta);
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        { identity: { subject: "user_alice", org_id: "org_a", org_role: "org:admin" }, verifiedActor: CLAIM },
        deps({ agentById }),
        { door: "debate:postTurn" },
      ),
    );
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe("standing-not-allowed");
    expect(r.door).toBe("debate:postTurn");
    expect(agentById).not.toHaveBeenCalled();
  });

  it("RED: a row returned for another subject than the verified one is ignored, so the caller is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        { identity: { subject: "user_alice" }, verifiedActor: CLAIM },
        deps({}, { serviceAccountsBySubject: () => SERVICE_ROWS }),
      ),
    );
    expect(r.reason).toBe("standing-not-allowed");
  });

  it("RED: a service account its organisation does not name as its own is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        { identity: SVC_IDENTITY, verifiedActor: CLAIM },
        deps({}, { serviceAccountIdOfOrg: () => "svc_other" }),
      ),
    );
    expect(r.reason).toBe("standing-not-allowed");
  });

  it("RED: the service account of a client organisation is a service, not the fleet, and is refused", async () => {
    const rows: ServiceAccountRow[] = [{ id: "svc_c", orgId: "org_a", active: true, subject: SVC_SUBJECT }];
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        { identity: SVC_IDENTITY, verifiedActor: CLAIM },
        deps({}, { serviceAccountsBySubject: () => rows, serviceAccountIdOfOrg: () => "svc_c" }),
      ),
    );
    expect(r.reason).toBe("standing-not-allowed");
  });

  it("RED: a deactivated service account is refused", async () => {
    const rows: ServiceAccountRow[] = [{ id: "svc_1", orgId: OP, active: false, subject: SVC_SUBJECT }];
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        { identity: SVC_IDENTITY, verifiedActor: CLAIM },
        deps({}, { serviceAccountsBySubject: () => rows }),
      ),
    );
    expect(r.reason).toBe("principal-inactive");
  });

  it("RED: a service-account row stamped with no organisation is refused", async () => {
    const rows: ServiceAccountRow[] = [{ id: "svc_1", orgId: null, active: true, subject: SVC_SUBJECT }];
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        { identity: SVC_IDENTITY, verifiedActor: CLAIM },
        deps({}, { serviceAccountsBySubject: () => rows }),
      ),
    );
    expect(r.reason).toBe("no-verified-organisation");
  });

  it.each([
    [
      "the subject lookup throws",
      {
        serviceAccountsBySubject: () => {
          throw new Error("db down");
        },
      },
    ],
    [
      "the organisation lookup throws",
      {
        serviceAccountIdOfOrg: () => {
          throw new Error("db down");
        },
      },
    ],
    ["the subject lookup is not supplied", { serviceAccountsBySubject: undefined }],
    ["the organisation lookup is not supplied", { serviceAccountIdOfOrg: undefined }],
    ["the subject lookup answers a non-list", { serviceAccountsBySubject: () => SERVICE_ROWS[0] as never }],
  ])("RED: %s: refused, never resolved, no lookup text surfaced", async (_n, s) => {
    const r = await refusalOf(
      resolveAgentWriterFromIdentity({ identity: SVC_IDENTITY, verifiedActor: CLAIM }, deps({}, s)),
    );
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe("principal-lookup-failed");
    expect(JSON.stringify(r)).not.toContain("db down");
  });

  it("RED: no service-account lookups at all is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        { identity: SVC_IDENTITY, verifiedActor: CLAIM },
        { principalLookups: principalLookups() } as never,
      ),
    );
    expect(r.reason).toBe("principal-lookup-failed");
  });

  it("RED: the service account with a malformed claim is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        { identity: SVC_IDENTITY, verifiedActor: { ...CLAIM, name: "eta" } as never },
        deps(),
      ),
    );
    expect(r.reason).toBe("credential-invalid");
  });

  it("RED: the service account with no claim is refused", async () => {
    const r = await refusalOf(resolveAgentWriterFromIdentity({ identity: SVC_IDENTITY, verifiedActor: undefined }, deps()));
    expect(r.reason).toBe("credential-invalid");
  });

  it("RED: a claim for another organisation than the call targets is refused without an agent lookup", async () => {
    const agentById = vi.fn(() => AGENTS.agent_a_eta);
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        { identity: SVC_IDENTITY, verifiedActor: CLAIM, targetOrgId: "org_b" },
        deps({ agentById }),
      ),
    );
    expect(r.reason).toBe("other-organisation");
    expect(agentById).not.toHaveBeenCalled();
  });

  it("RED: a stored agent of another organisation than the claim is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        { identity: SVC_IDENTITY, verifiedActor: { agentId: "agent_b_eta", orgId: "org_a" } },
        deps(),
      ),
    );
    expect(r.reason).toBe("other-organisation");
  });

  it("the default door names the function; a refusal carries no subject and no claim", async () => {
    const r = await refusalOf(
      resolveAgentWriterFromIdentity({ identity: { subject: "user_alice" }, verifiedActor: CLAIM }, deps()),
    );
    expect(r.door).toBe("resolveAgentWriterFromIdentity");
    expect(JSON.stringify(r)).not.toContain("user_alice");
    expect(JSON.stringify(r)).not.toContain("agent_a_eta");
  });
});
