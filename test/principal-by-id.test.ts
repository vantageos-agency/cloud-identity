import { describe, expect, it, vi } from "vitest";
import {
  type ActingPrincipal,
  assertTargetBelongsTo,
  FLEET_SCOPE_ORG_ID,
  type OrganisationRow,
  type PrincipalLookups,
  type PrincipalRow,
  resolveActingPrincipal,
} from "../src/index.js";

/**
 * Two organisations, each with an agent displayed as "eta". The labels collide;
 * the IDs do not. Every admission below must be decided by the IDs.
 */
const AGENTS: Record<string, PrincipalRow & { name?: string }> = {
  agent_a_eta: { id: "agent_a_eta", orgId: "org_a", active: true, name: "eta" },
  agent_a_rho: { id: "agent_a_rho", orgId: "org_a", active: true, name: "rho" },
  agent_b_eta: { id: "agent_b_eta", orgId: "org_b", active: true, name: "eta" },
  agent_a_off: { id: "agent_a_off", orgId: "org_a", active: false, name: "off" },
  agent_fleet: { id: "agent_fleet", orgId: FLEET_SCOPE_ORG_ID, active: true, name: "pi" },
  agent_unstamped: { id: "agent_unstamped", active: true, name: "ghost" },
  agent_off_org: { id: "agent_off_org", orgId: "org_off", active: true },
};
const PERSONS: Record<string, PrincipalRow> = {
  "user_1|org_a": { id: "user_1", orgId: "org_a", active: true },
  "user_1|org_b": { id: "user_1", orgId: "org_b", active: false },
  [`user_1|${FLEET_SCOPE_ORG_ID}`]: { id: "user_1", orgId: FLEET_SCOPE_ORG_ID, active: true },
};
const SERVICES: Record<string, PrincipalRow> = {
  svc_a: { id: "svc_a", orgId: "org_a", active: true },
  svc_fleet: { id: "svc_fleet", orgId: FLEET_SCOPE_ORG_ID, active: true },
  svc_unstamped: { id: "svc_unstamped", active: true },
  svc_off: { id: "svc_off", orgId: "org_a", active: false },
};
const ORGS: Record<string, OrganisationRow> = {
  org_a: { id: "org_a", active: true },
  org_b: { id: "org_b", active: true },
  org_off: { id: "org_off", active: false },
};

function world(overrides: Partial<PrincipalLookups> = {}) {
  const lookups = {
    agentById: vi.fn(async (id: string) => AGENTS[id] ?? null),
    personById: vi.fn(async (id: string, org: string) => PERSONS[`${id}|${org}`] ?? null),
    serviceAccountById: vi.fn(async (id: string) => SERVICES[id] ?? null),
    organisationById: vi.fn(async (id: string) => ORGS[id] ?? null),
    ...overrides,
  };
  return lookups;
}

async function refusedReason(p: ReturnType<typeof resolveActingPrincipal>) {
  const r = await p;
  expect(r.ok).toBe(false);
  if (r.ok) return undefined;
  expect(r.refusal.code).toBe("RBAC_DENIED");
  return r.refusal.reason;
}

// ---------------------------------------------------------------------------
// resolveActingPrincipal — served paths
// ---------------------------------------------------------------------------

describe("resolveActingPrincipal — each path resolves to stored IDs", () => {
  it("machine path: an agent credential resolves to the agent row ID and its org", async () => {
    const r = await resolveActingPrincipal(
      { kind: "agent", agentId: "agent_a_eta", verifiedOrgId: "org_a" },
      world(),
    );
    expect(r).toEqual({
      ok: true,
      principal: { principalId: "agent_a_eta", orgId: "org_a", kind: "agent" },
    });
  });

  it("human path: a person credential resolves to the person ID and the token's org", async () => {
    const lookups = world();
    const r = await resolveActingPrincipal(
      { kind: "person", personId: "user_1", verifiedOrgId: "org_a" },
      lookups,
    );
    expect(r).toEqual({
      ok: true,
      principal: { principalId: "user_1", orgId: "org_a", kind: "person" },
    });
    expect(lookups.personById).toHaveBeenCalledWith("user_1", "org_a");
  });

  it("a service account acting for an agent names it BY ID, resolved within its own org", async () => {
    const r = await resolveActingPrincipal(
      { kind: "service", serviceAccountId: "svc_a", actingForAgentId: "agent_a_eta" },
      world(),
    );
    expect(r).toEqual({
      ok: true,
      principal: {
        principalId: "agent_a_eta",
        orgId: "org_a",
        kind: "agent",
        viaServiceAccountId: "svc_a",
      },
    });
  });

  it("a service account acting as itself resolves to kind service in its org", async () => {
    const r = await resolveActingPrincipal(
      { kind: "service", serviceAccountId: "svc_a" },
      world(),
    );
    expect(r).toEqual({
      ok: true,
      principal: { principalId: "svc_a", orgId: "org_a", kind: "service" },
    });
  });

  it("the service account stamped with the fleet scope resolves to kind fleet (no org lookup)", async () => {
    const lookups = world();
    const r = await resolveActingPrincipal(
      { kind: "service", serviceAccountId: "svc_fleet" },
      lookups,
    );
    expect(r).toEqual({
      ok: true,
      principal: { principalId: "svc_fleet", orgId: FLEET_SCOPE_ORG_ID, kind: "fleet" },
    });
    expect(lookups.organisationById).not.toHaveBeenCalled();
  });

  it("the fleet service acting for a fleet-stamped agent resolves that agent in the fleet scope", async () => {
    const r = await resolveActingPrincipal(
      { kind: "service", serviceAccountId: "svc_fleet", actingForAgentId: "agent_fleet" },
      world(),
    );
    expect(r).toEqual({
      ok: true,
      principal: {
        principalId: "agent_fleet",
        orgId: FLEET_SCOPE_ORG_ID,
        kind: "agent",
        viaServiceAccountId: "svc_fleet",
      },
    });
  });
});

// ---------------------------------------------------------------------------
// resolveActingPrincipal — refusal by default
// ---------------------------------------------------------------------------

describe("resolveActingPrincipal — an unresolved credential is refused", () => {
  it("refuses an absent or malformed credential without calling any lookup", async () => {
    for (const credential of [
      null,
      undefined,
      {},
      { kind: "agent" },
      { kind: "agent", agentId: "", verifiedOrgId: "org_a" },
      { kind: "person", personId: "user_1" },
      { kind: "master" },
      "agent_a_eta",
    ]) {
      const lookups = world();
      // biome-ignore lint/suspicious/noExplicitAny: probing the runtime guard with untyped input
      const reason = await refusedReason(resolveActingPrincipal(credential as any, lookups));
      expect(reason).toBe("credential-invalid");
      expect(lookups.agentById).not.toHaveBeenCalled();
      expect(lookups.serviceAccountById).not.toHaveBeenCalled();
    }
  });

  it("refuses when the lookup for the presented path is not supplied", async () => {
    const reason = await refusedReason(
      resolveActingPrincipal(
        { kind: "agent", agentId: "agent_a_eta", verifiedOrgId: "org_a" },
        { organisationById: async (id) => ORGS[id] ?? null },
      ),
    );
    expect(reason).toBe("principal-lookup-failed");
  });

  it("refuses a throwing lookup without surfacing its error text", async () => {
    const r = await resolveActingPrincipal(
      { kind: "agent", agentId: "agent_a_eta", verifiedOrgId: "org_a" },
      world({
        agentById: async () => {
          throw new Error("db down secret-xyz");
        },
      }),
    );
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal.reason).toBe("principal-lookup-failed");
      expect(JSON.stringify(r.refusal)).not.toContain("secret-xyz");
    }
  });

  it("refuses a miss, a malformed row, an inactive row and a row with no active flag", async () => {
    const cases: Array<[Partial<PrincipalLookups>, string]> = [
      [{ agentById: async () => null }, "principal-not-found"],
      [
        // biome-ignore lint/suspicious/noExplicitAny: a malformed row is the point
        { agentById: async () => ({ orgId: "org_a", active: true }) as any },
        "principal-record-invalid",
      ],
      [
        // biome-ignore lint/suspicious/noExplicitAny: an absent active flag grants nothing
        { agentById: async () => ({ id: "agent_a_eta", orgId: "org_a" }) as any },
        "principal-record-invalid",
      ],
      [
        { agentById: async () => ({ id: "agent_a_eta", orgId: "org_a", active: false }) },
        "principal-inactive",
      ],
    ];
    for (const [override, expected] of cases) {
      const reason = await refusedReason(
        resolveActingPrincipal(
          { kind: "agent", agentId: "agent_a_eta", verifiedOrgId: "org_a" },
          world(override),
        ),
      );
      expect(reason).toBe(expected);
    }
  });

  it("refuses a loose lookup that returns another row than the ID asked for", async () => {
    const reason = await refusedReason(
      resolveActingPrincipal(
        { kind: "agent", agentId: "agent_a_eta", verifiedOrgId: "org_a" },
        world({ agentById: async () => AGENTS.agent_a_rho }),
      ),
    );
    expect(reason).toBe("principal-record-invalid");
  });

  it("refuses an agent whose stored org is not the org its credential was verified for", async () => {
    const reason = await refusedReason(
      resolveActingPrincipal(
        { kind: "agent", agentId: "agent_b_eta", verifiedOrgId: "org_a" },
        world(),
      ),
    );
    expect(reason).toBe("other-organisation");
  });

  it("refuses an unstamped agent row and an unstamped service account", async () => {
    expect(
      await refusedReason(
        resolveActingPrincipal(
          { kind: "agent", agentId: "agent_unstamped", verifiedOrgId: "org_a" },
          world(),
        ),
      ),
    ).toBe("no-verified-organisation");
    expect(
      await refusedReason(
        resolveActingPrincipal({ kind: "service", serviceAccountId: "svc_unstamped" }, world()),
      ),
    ).toBe("no-verified-organisation");
  });

  it("refuses an inactive or unmapped organisation, and an organisation lookup that throws", async () => {
    expect(
      await refusedReason(
        resolveActingPrincipal(
          { kind: "agent", agentId: "agent_off_org", verifiedOrgId: "org_off" },
          world(),
        ),
      ),
    ).toBe("organisation-not-active");
    expect(
      await refusedReason(
        resolveActingPrincipal(
          { kind: "agent", agentId: "agent_a_eta", verifiedOrgId: "org_a" },
          world({ organisationById: async () => null }),
        ),
      ),
    ).toBe("organisation-not-active");
    expect(
      await refusedReason(
        resolveActingPrincipal(
          { kind: "agent", agentId: "agent_a_eta", verifiedOrgId: "org_a" },
          world({ organisationById: undefined }),
        ),
      ),
    ).toBe("principal-lookup-failed");
    expect(
      await refusedReason(
        resolveActingPrincipal(
          { kind: "agent", agentId: "agent_a_eta", verifiedOrgId: "org_a" },
          world({
            organisationById: async () => {
              throw new Error("down");
            },
          }),
        ),
      ),
    ).toBe("principal-lookup-failed");
  });

  it("refuses an inactive person membership and an inactive service account", async () => {
    expect(
      await refusedReason(
        resolveActingPrincipal(
          { kind: "person", personId: "user_1", verifiedOrgId: "org_b" },
          world(),
        ),
      ),
    ).toBe("principal-inactive");
    expect(
      await refusedReason(
        resolveActingPrincipal({ kind: "service", serviceAccountId: "svc_off" }, world()),
      ),
    ).toBe("principal-inactive");
  });

  it("carries the consumer's door on the refusal", async () => {
    const r = await resolveActingPrincipal(null, world(), "tasks:complete");
    expect(!r.ok && r.refusal.door).toBe("tasks:complete");
  });
});

// ---------------------------------------------------------------------------
// The incident: two orgs, same agent name, different IDs
// ---------------------------------------------------------------------------

describe("name collision — org-a's 'eta' never reaches org-b's 'eta'", () => {
  it("a service account of org-a acting for org-b's eta by ID is refused", async () => {
    const reason = await refusedReason(
      resolveActingPrincipal(
        { kind: "service", serviceAccountId: "svc_a", actingForAgentId: "agent_b_eta" },
        world(),
      ),
    );
    expect(reason).toBe("acting-agent-other-organisation");
  });

  it("the fleet service account cannot act for a client org's agent", async () => {
    const reason = await refusedReason(
      resolveActingPrincipal(
        { kind: "service", serviceAccountId: "svc_fleet", actingForAgentId: "agent_b_eta" },
        world(),
      ),
    );
    expect(reason).toBe("acting-agent-other-organisation");
  });

  it("naming the agent by NAME is refused whole, before any lookup", async () => {
    for (const credential of [
      { kind: "service", serviceAccountId: "svc_a", actingForAgentName: "eta" },
      { kind: "service", serviceAccountId: "svc_a", callerOrchestrator: "eta" },
      { kind: "agent", agentName: "eta", verifiedOrgId: "org_a" },
      { kind: "agent", agentId: "agent_a_eta", verifiedOrgId: "org_a", name: "eta" },
      { kind: "person", personId: "user_1", verifiedOrgId: "org_a", assignedTo: "eta" },
    ]) {
      const lookups = world();
      // biome-ignore lint/suspicious/noExplicitAny: a name-carrying credential is the probe
      const reason = await refusedReason(resolveActingPrincipal(credential as any, lookups));
      expect(reason).toBe("credential-invalid");
      expect(lookups.agentById).not.toHaveBeenCalled();
      expect(lookups.serviceAccountById).not.toHaveBeenCalled();
    }
  });

  it("end to end: org-a's eta, acting through the service account, is refused on org-b's eta task and served on its own", async () => {
    const r = await resolveActingPrincipal(
      { kind: "service", serviceAccountId: "svc_a", actingForAgentId: "agent_a_eta" },
      world(),
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    const orgBEtaTask = { orgId: "org_b", ownerId: "agent_b_eta" };
    const orgAEtaTask = { orgId: "org_a", ownerId: "agent_a_eta" };
    for (const ownerOnly of [false, true]) {
      const foreign = assertTargetBelongsTo(r.principal, orgBEtaTask, { ownerOnly });
      expect(foreign.ok).toBe(false);
      if (!foreign.ok) expect(foreign.refusal.reason).toBe("target-other-organisation");
      expect(assertTargetBelongsTo(r.principal, orgAEtaTask, { ownerOnly })).toEqual({ ok: true });
    }
  });
});

// ---------------------------------------------------------------------------
// The reserved fleet scope
// ---------------------------------------------------------------------------

describe("reserved fleet scope — a client can never claim it", () => {
  it("refuses an agent or person credential verified for the fleet scope", async () => {
    expect(
      await refusedReason(
        resolveActingPrincipal(
          { kind: "agent", agentId: "agent_fleet", verifiedOrgId: FLEET_SCOPE_ORG_ID },
          world(),
        ),
      ),
    ).toBe("reserved-fleet-scope");
    expect(
      await refusedReason(
        resolveActingPrincipal(
          { kind: "person", personId: "user_1", verifiedOrgId: FLEET_SCOPE_ORG_ID },
          world(),
        ),
      ),
    ).toBe("reserved-fleet-scope");
  });

  it("refuses a client-org service account acting for a fleet-stamped agent", async () => {
    expect(
      await refusedReason(
        resolveActingPrincipal(
          { kind: "service", serviceAccountId: "svc_a", actingForAgentId: "agent_fleet" },
          world(),
        ),
      ),
    ).toBe("acting-agent-other-organisation");
  });
});

// ---------------------------------------------------------------------------
// assertTargetBelongsTo
// ---------------------------------------------------------------------------

const agentA: ActingPrincipal = { principalId: "agent_a_eta", orgId: "org_a", kind: "agent" };
const rhoA: ActingPrincipal = { principalId: "agent_a_rho", orgId: "org_a", kind: "agent" };
const personA: ActingPrincipal = { principalId: "user_1", orgId: "org_a", kind: "person" };
const serviceA: ActingPrincipal = { principalId: "svc_a", orgId: "org_a", kind: "service" };
const fleet: ActingPrincipal = {
  principalId: "svc_fleet",
  orgId: FLEET_SCOPE_ORG_ID,
  kind: "fleet",
};

function reasonOf(r: ReturnType<typeof assertTargetBelongsTo>) {
  expect(r.ok).toBe(false);
  if (r.ok) return undefined;
  expect(r.refusal.code).toBe("RBAC_DENIED");
  return r.refusal.reason;
}

describe("assertTargetBelongsTo — stored IDs only", () => {
  it("own-org target allowed, foreign-org target refused", () => {
    expect(assertTargetBelongsTo(agentA, { orgId: "org_a" })).toEqual({ ok: true });
    expect(reasonOf(assertTargetBelongsTo(agentA, { orgId: "org_b" }))).toBe(
      "target-other-organisation",
    );
  });

  it("compares IDs byte for byte: no case folding, no trimming", () => {
    for (const orgId of ["ORG_A", " org_a", "org_a ", "org_a/"]) {
      expect(reasonOf(assertTargetBelongsTo(agentA, { orgId }))).toBe(
        "target-other-organisation",
      );
    }
  });

  it("owner-only: allowed for the owner, refused for another principal of the same org", () => {
    const task = { orgId: "org_a", ownerId: "agent_a_eta" };
    expect(assertTargetBelongsTo(agentA, task, { ownerOnly: true })).toEqual({ ok: true });
    expect(reasonOf(assertTargetBelongsTo(rhoA, task, { ownerOnly: true }))).toBe(
      "target-owner-mismatch",
    );
    expect(reasonOf(assertTargetBelongsTo(personA, task, { ownerOnly: true }))).toBe(
      "target-owner-mismatch",
    );
    // without ownerOnly the same-org principal is admitted (org-level door)
    expect(assertTargetBelongsTo(rhoA, task)).toEqual({ ok: true });
  });

  it("owner-only: a target with no stored owner is refused, never treated as 'anyone'", () => {
    for (const ownerId of [undefined, null, ""]) {
      expect(
        reasonOf(assertTargetBelongsTo(agentA, { orgId: "org_a", ownerId }, { ownerOnly: true })),
      ).toBe("target-owner-mismatch");
    }
  });

  it("an unstamped row is refused to every client principal", () => {
    for (const p of [agentA, personA, serviceA]) {
      for (const orgId of [undefined, null, ""]) {
        expect(reasonOf(assertTargetBelongsTo(p, { orgId, ownerId: p.principalId }))).toBe(
          "target-unstamped",
        );
      }
    }
  });

  it("an unstamped row is admitted to the fleet principal only (it is not a fleet row)", () => {
    expect(assertTargetBelongsTo(fleet, {})).toEqual({ ok: true });
    expect(assertTargetBelongsTo(fleet, { orgId: null })).toEqual({ ok: true });
  });

  it("a fleet-scope row: client refused, fleet allowed", () => {
    const fleetRow = { orgId: FLEET_SCOPE_ORG_ID };
    for (const p of [agentA, personA, serviceA]) {
      expect(reasonOf(assertTargetBelongsTo(p, fleetRow))).toBe("reserved-fleet-scope");
      expect(reasonOf(assertTargetBelongsTo(p, fleetRow, { fleetCrossOrg: true }))).toBe(
        "reserved-fleet-scope",
      );
    }
    expect(assertTargetBelongsTo(fleet, fleetRow)).toEqual({ ok: true });
  });

  it("fleet on a client row: refused by default, admitted only when the door declares a master export", () => {
    expect(reasonOf(assertTargetBelongsTo(fleet, { orgId: "org_b" }))).toBe(
      "target-other-organisation",
    );
    expect(assertTargetBelongsTo(fleet, { orgId: "org_b" }, { fleetCrossOrg: true })).toEqual({
      ok: true,
    });
    // the declaration widens nothing for a client principal
    expect(
      reasonOf(assertTargetBelongsTo(agentA, { orgId: "org_b" }, { fleetCrossOrg: true })),
    ).toBe("target-other-organisation");
  });

  it("owner-only binds the fleet principal too", () => {
    expect(
      reasonOf(
        assertTargetBelongsTo(
          fleet,
          { orgId: FLEET_SCOPE_ORG_ID, ownerId: "agent_fleet" },
          { ownerOnly: true },
        ),
      ),
    ).toBe("target-owner-mismatch");
  });

  it("refuses an absent principal, an absent target and a principal with empty IDs", () => {
    expect(reasonOf(assertTargetBelongsTo(null, { orgId: "org_a" }))).toBe("credential-invalid");
    expect(reasonOf(assertTargetBelongsTo(undefined, { orgId: "org_a" }))).toBe(
      "credential-invalid",
    );
    expect(reasonOf(assertTargetBelongsTo(agentA, null))).toBe("target-unstamped");
    expect(
      reasonOf(assertTargetBelongsTo({ ...agentA, principalId: "" }, { orgId: "org_a" })),
    ).toBe("credential-invalid");
    expect(reasonOf(assertTargetBelongsTo({ ...agentA, orgId: "" }, { orgId: "" }))).toBe(
      "credential-invalid",
    );
  });

  it("refuses a hand-built principal that claims the fleet scope without being fleet", () => {
    for (const kind of ["person", "service"] as const) {
      const forged: ActingPrincipal = { principalId: "x", orgId: FLEET_SCOPE_ORG_ID, kind };
      expect(reasonOf(assertTargetBelongsTo(forged, { orgId: FLEET_SCOPE_ORG_ID }))).toBe(
        "reserved-fleet-scope",
      );
    }
    // an agent in the fleet scope exists only through the fleet service account
    const directFleetAgent: ActingPrincipal = {
      principalId: "agent_fleet",
      orgId: FLEET_SCOPE_ORG_ID,
      kind: "agent",
    };
    expect(reasonOf(assertTargetBelongsTo(directFleetAgent, { orgId: FLEET_SCOPE_ORG_ID }))).toBe(
      "reserved-fleet-scope",
    );
    // and kind "fleet" outside the fleet scope is not fleet
    const fakeFleet: ActingPrincipal = { principalId: "svc_a", orgId: "org_a", kind: "fleet" };
    expect(reasonOf(assertTargetBelongsTo(fakeFleet, {}))).toBe("reserved-fleet-scope");
  });

  it("a fleet-stamped agent acting through the fleet service reaches fleet rows, not unstamped or client rows", () => {
    const fleetAgent: ActingPrincipal = {
      principalId: "agent_fleet",
      orgId: FLEET_SCOPE_ORG_ID,
      kind: "agent",
      viaServiceAccountId: "svc_fleet",
    };
    expect(assertTargetBelongsTo(fleetAgent, { orgId: FLEET_SCOPE_ORG_ID })).toEqual({ ok: true });
    expect(reasonOf(assertTargetBelongsTo(fleetAgent, {}))).toBe("target-unstamped");
    expect(
      reasonOf(assertTargetBelongsTo(fleetAgent, { orgId: "org_a" }, { fleetCrossOrg: true })),
    ).toBe("target-other-organisation");
  });

  it("carries the consumer's door on the refusal", () => {
    const r = assertTargetBelongsTo(agentA, { orgId: "org_b" }, { door: "tasks:deleteTask" });
    expect(!r.ok && r.refusal.door).toBe("tasks:deleteTask");
  });
});
