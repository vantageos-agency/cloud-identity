import { describe, expect, it, vi } from "vitest";
import {
  IdentityRefusalError,
  type PrincipalLookups,
  type PrincipalRow,
  resolveAgentWriterFromIdentity,
  type OrgMappingRow,
  type ServiceAccountIdentityLookups,
  type ServiceAccountRow,
  type TransportAuth,
} from "../src/index.js";

/**
 * resolveAgentWriterFromIdentity: the same decision as resolveAgentWriter, but
 * the package resolves the caller's standing ITSELF from the host transport
 * (for Convex, `ctx.auth`: the package calls `getUserIdentity()`), instead of
 * trusting a scope the consumer resolved locally.
 *
 *   verified subject
 *     -> the stored service-account rows carrying that subject
 *     -> each row's organisation mapping row (orgById) names that row (serviceAccountId)
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
    ...overrides,
  };
}

function orgRow(id: string, serviceAccountId: string | null): OrgMappingRow {
  return {
    id,
    label: id,
    active: true,
    scopes: [],
    orgKind: id === OP ? "operator" : "client",
    serviceAccountId,
  };
}

type OrgById = (orgId: string) => OrgMappingRow | null;
const ORG_BY_ID: OrgById = (orgId) => orgRow(orgId, orgId === OP ? "svc_1" : null);

function deps(
  p: Partial<PrincipalLookups> = {},
  s: Partial<ServiceAccountIdentityLookups> = {},
  orgById: unknown = ORG_BY_ID,
) {
  return {
    principalLookups: principalLookups(p),
    orgLookups: { orgById: orgById as OrgById },
    serviceAccountLookups: serviceLookups(s),
  };
}

/** A Convex-shaped `ctx.auth`: the package calls `getUserIdentity()` itself. */
function auth(identity: unknown): TransportAuth {
  return { getUserIdentity: async () => identity };
}

const CLAIM = { agentId: "agent_a_eta", orgId: "org_a" };
const SVC_IDENTITY = {
  subject: SVC_SUBJECT,
  issuer: "https://clerk.example",
  tokenIdentifier: "x|user_svc",
};

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
    const principal = await resolveAgentWriterFromIdentity(auth(SVC_IDENTITY), { verifiedActor: CLAIM }, deps());
    expect(principal).toEqual({
      principalId: "agent_a_eta",
      orgId: "org_a",
      kind: "agent",
    });
  });

  it("GREEN: the standing is decided by subject; an org claim on the identity neither upgrades nor downgrades it", async () => {
    const principal = await resolveAgentWriterFromIdentity(
      auth({ ...SVC_IDENTITY, org_id: "org_a", org_role: "org:member" }),
      { verifiedActor: CLAIM, targetOrgId: "org_a" },
      deps(),
    );
    expect(principal.orgId).toBe("org_a");
  });

  it("GREEN: every lookup is keyed by the verified subject or a stored ID, never a name", async () => {
    const bySubject = vi.fn((subject: string) => SERVICE_ROWS.filter((r) => r.subject === subject));
    const idOfOrg = vi.fn(ORG_BY_ID);
    const agentById = vi.fn((id: string) => AGENTS[id] ?? null);
    await resolveAgentWriterFromIdentity(
      auth(SVC_IDENTITY),
      { verifiedActor: CLAIM },
      deps({ agentById }, { serviceAccountsBySubject: bySubject }, idOfOrg),
    );
    expect(bySubject).toHaveBeenCalledWith(SVC_SUBJECT);
    expect(idOfOrg).toHaveBeenCalledWith(OP);
    expect(agentById).toHaveBeenCalledWith("agent_a_eta");
  });

  it.each([undefined, null])("RED: an absent identity (%s) is refused without a lookup", async (identity) => {
    const bySubject = vi.fn(() => SERVICE_ROWS);
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        auth(identity),
        { verifiedActor: CLAIM },
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
        auth(identity),
        { verifiedActor: CLAIM },
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
        auth({ subject: "user_alice", org_id: "org_a", org_role: "org:admin" }),
        { verifiedActor: CLAIM },
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
        auth({ subject: "user_alice" }),
        { verifiedActor: CLAIM },
        deps({}, { serviceAccountsBySubject: () => SERVICE_ROWS }),
      ),
    );
    expect(r.reason).toBe("standing-not-allowed");
  });

  it("RED: a service account its organisation does not name as its own is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        auth(SVC_IDENTITY),
        { verifiedActor: CLAIM },
        deps({}, {}, (orgId: string) => orgRow(orgId, "svc_other")),
      ),
    );
    expect(r.reason).toBe("standing-not-allowed");
  });

  it("RED: the service account of a client organisation is a service, not the fleet, and is refused", async () => {
    const rows: ServiceAccountRow[] = [{ id: "svc_c", orgId: "org_a", active: true, subject: SVC_SUBJECT }];
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        auth(SVC_IDENTITY),
        { verifiedActor: CLAIM },
        deps({}, { serviceAccountsBySubject: () => rows }, (orgId: string) => orgRow(orgId, "svc_c")),
      ),
    );
    expect(r.reason).toBe("standing-not-allowed");
  });

  it("RED: a deactivated service account is refused", async () => {
    const rows: ServiceAccountRow[] = [{ id: "svc_1", orgId: OP, active: false, subject: SVC_SUBJECT }];
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        auth(SVC_IDENTITY),
        { verifiedActor: CLAIM },
        deps({}, { serviceAccountsBySubject: () => rows }),
      ),
    );
    expect(r.reason).toBe("principal-inactive");
  });

  it("RED: a service-account row stamped with no organisation is refused", async () => {
    const rows: ServiceAccountRow[] = [{ id: "svc_1", orgId: null, active: true, subject: SVC_SUBJECT }];
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        auth(SVC_IDENTITY),
        { verifiedActor: CLAIM },
        deps({}, { serviceAccountsBySubject: () => rows }),
      ),
    );
    expect(r.reason).toBe("no-verified-organisation");
  });

  it.each([
    ["no auth object", undefined],
    ["a null auth object", null],
    ["an auth object without getUserIdentity", {}],
  ])("RED: %s is refused without a lookup", async (_n, a) => {
    const bySubject = vi.fn(() => SERVICE_ROWS);
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        a as never,
        { verifiedActor: CLAIM },
        deps({}, { serviceAccountsBySubject: bySubject }),
        {
          door: "debate:postTurn",
        },
      ),
    );
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe("no-verified-subject");
    expect(r.door).toBe("debate:postTurn");
    expect(bySubject).not.toHaveBeenCalled();
  });

  it("RED: getUserIdentity() throwing is refused, never resolved, its text never surfaced", async () => {
    const bySubject = vi.fn(() => SERVICE_ROWS);
    const throwing: TransportAuth = {
      getUserIdentity: async () => {
        throw new Error("jwt secret-xyz expired");
      },
    };
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        throwing,
        { verifiedActor: CLAIM },
        deps({}, { serviceAccountsBySubject: bySubject }),
        {
          door: "debate:postTurn",
        },
      ),
    );
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe("credential-invalid");
    expect(r.door).toBe("debate:postTurn");
    expect(JSON.stringify(r)).not.toContain("secret-xyz");
    expect(bySubject).not.toHaveBeenCalled();
  });

  it("GREEN: getUserIdentity is called as a method of the auth object (its `this` is kept)", async () => {
    const host = {
      identity: SVC_IDENTITY,
      async getUserIdentity(this: { identity: unknown }) {
        return this.identity;
      },
    };
    const principal = await resolveAgentWriterFromIdentity(host, { verifiedActor: CLAIM }, deps());
    expect(principal.principalId).toBe("agent_a_eta");
  });

  it.each([
    [
      "the organisation lookup throws",
      () => {
        throw new Error("db down");
      },
      "org-mapping-lookup-failed",
    ],
    ["the organisation lookup is not supplied", null, "org-mapping-lookup-failed"],
    ["the organisation row is malformed", () => ({ id: OP }), "org-mapping-record-invalid"],
    ["the organisation row is another organisation's", () => orgRow("org_x", "svc_1"), "org-mapping-record-invalid"],
  ])("RED: %s: refused, no lookup text surfaced", async (_n, orgById, reason) => {
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(auth(SVC_IDENTITY), { verifiedActor: CLAIM }, deps({}, {}, orgById)),
    );
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe(reason);
    expect(JSON.stringify(r)).not.toContain("db down");
  });

  it("RED: an organisation with no mapping row names no service account, so the caller is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        auth(SVC_IDENTITY),
        { verifiedActor: CLAIM },
        deps({}, {}, () => null),
      ),
    );
    expect(r.reason).toBe("standing-not-allowed");
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
    ["the subject lookup is not supplied", { serviceAccountsBySubject: undefined }],
    ["the subject lookup answers a non-list", { serviceAccountsBySubject: () => SERVICE_ROWS[0] as never }],
  ])("RED: %s: refused, never resolved, no lookup text surfaced", async (_n, s) => {
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(auth(SVC_IDENTITY), { verifiedActor: CLAIM }, deps({}, s)),
    );
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe("principal-lookup-failed");
    expect(JSON.stringify(r)).not.toContain("db down");
  });

  it("RED: no service-account lookups at all is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(auth(SVC_IDENTITY), { verifiedActor: CLAIM }, {
        principalLookups: principalLookups(),
        orgLookups: { orgById: ORG_BY_ID },
      } as never),
    );
    expect(r.reason).toBe("principal-lookup-failed");
  });

  it("RED: the service account with a malformed claim is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(auth(SVC_IDENTITY), { verifiedActor: { ...CLAIM, name: "eta" } as never }, deps()),
    );
    expect(r.reason).toBe("credential-invalid");
  });

  it("RED: the service account with no claim is refused", async () => {
    const r = await refusalOf(resolveAgentWriterFromIdentity(auth(SVC_IDENTITY), { verifiedActor: undefined }, deps()));
    expect(r.reason).toBe("credential-invalid");
  });

  it("RED: a claim for another organisation than the call targets is refused without an agent lookup", async () => {
    const agentById = vi.fn(() => AGENTS.agent_a_eta);
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        auth(SVC_IDENTITY),
        { verifiedActor: CLAIM, targetOrgId: "org_b" },
        deps({ agentById }),
      ),
    );
    expect(r.reason).toBe("other-organisation");
    expect(agentById).not.toHaveBeenCalled();
  });

  it("RED: a stored agent of another organisation than the claim is refused", async () => {
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(
        auth(SVC_IDENTITY),
        { verifiedActor: { agentId: "agent_b_eta", orgId: "org_a" } },
        deps(),
      ),
    );
    expect(r.reason).toBe("other-organisation");
  });

  it("the default door names the function; a refusal carries no subject and no claim", async () => {
    const r = await refusalOf(
      resolveAgentWriterFromIdentity(auth({ subject: "user_alice" }), { verifiedActor: CLAIM }, deps()),
    );
    expect(r.door).toBe("resolveAgentWriterFromIdentity");
    expect(JSON.stringify(r)).not.toContain("user_alice");
    expect(JSON.stringify(r)).not.toContain("agent_a_eta");
  });
});
