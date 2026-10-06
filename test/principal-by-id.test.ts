import { describe, expect, it, vi } from "vitest";
import {
  type ActingPrincipal,
  assertTargetBelongsTo,
  type OrganisationRow,
  type OrgKind,
  type PrincipalLookups,
  type PrincipalRow,
  resolveActingPrincipal,
} from "../src/index.js";

/**
 * The operator organisation of this test world. Its ID is ordinary data: the
 * package knows it is the fleet only because `orgKindOf` answers "operator".
 */
const OPERATOR = "org_operator";

/**
 * Two organisations, each with an agent displayed as "eta". The labels collide;
 * the IDs do not. Every admission below must be decided by the IDs.
 */
const AGENTS: Record<string, PrincipalRow & { name?: string }> = {
  agent_a_eta: { id: "agent_a_eta", orgId: "org_a", active: true, name: "eta" },
  agent_a_rho: { id: "agent_a_rho", orgId: "org_a", active: true, name: "rho" },
  agent_b_eta: { id: "agent_b_eta", orgId: "org_b", active: true, name: "eta" },
  agent_a_off: { id: "agent_a_off", orgId: "org_a", active: false, name: "off" },
  agent_fleet: { id: "agent_fleet", orgId: OPERATOR, active: true, name: "pi" },
  agent_unstamped: { id: "agent_unstamped", active: true, name: "ghost" },
  agent_off_org: { id: "agent_off_org", orgId: "org_off", active: true },
};
const PERSONS: Record<string, PrincipalRow> = {
  "user_1|org_a": { id: "user_1", orgId: "org_a", active: true },
  "user_1|org_b": { id: "user_1", orgId: "org_b", active: false },
  [`user_1|${OPERATOR}`]: { id: "user_1", orgId: OPERATOR, active: true },
};
const SERVICES: Record<string, PrincipalRow> = {
  svc_a: { id: "svc_a", orgId: "org_a", active: true },
  svc_fleet: { id: "svc_fleet", orgId: OPERATOR, active: true },
  svc_unstamped: { id: "svc_unstamped", active: true },
  svc_off: { id: "svc_off", orgId: "org_a", active: false },
};
const ORGS: Record<string, OrganisationRow> = {
  org_a: { id: "org_a", active: true },
  org_b: { id: "org_b", active: true },
  org_off: { id: "org_off", active: false },
  [OPERATOR]: { id: OPERATOR, active: true },
};
const KINDS: Record<string, OrgKind> = {
  org_a: "client",
  org_b: "client",
  org_off: "client",
  [OPERATOR]: "operator",
};
/** The adapter `assertTargetBelongsTo` reads the operator org from. */
const kinds = { orgKindOf: async (id: string) => KINDS[id] ?? null };

function world(overrides: Partial<PrincipalLookups> = {}) {
  const lookups = {
    agentById: vi.fn(async (id: string) => AGENTS[id] ?? null),
    personById: vi.fn(async (id: string, org: string) => PERSONS[`${id}|${org}`] ?? null),
    serviceAccountById: vi.fn(async (id: string) => SERVICES[id] ?? null),
    organisationById: vi.fn(async (id: string) => ORGS[id] ?? null),
    orgKindOf: vi.fn(async (id: string) => KINDS[id] ?? null),
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

  it("a service account of the operator org resolves to kind fleet, its org checked like any other", async () => {
    const lookups = world();
    const r = await resolveActingPrincipal(
      { kind: "service", serviceAccountId: "svc_fleet" },
      lookups,
    );
    expect(r).toEqual({
      ok: true,
      principal: { principalId: "svc_fleet", orgId: OPERATOR, kind: "fleet" },
    });
    expect(lookups.orgKindOf).toHaveBeenCalledWith(OPERATOR);
    expect(lookups.organisationById).toHaveBeenCalledWith(OPERATOR);
  });

  it("the fleet service acting for an operator-org agent resolves that agent in the operator org", async () => {
    const r = await resolveActingPrincipal(
      { kind: "service", serviceAccountId: "svc_fleet", actingForAgentId: "agent_fleet" },
      world(),
    );
    expect(r).toEqual({
      ok: true,
      principal: {
        principalId: "agent_fleet",
        orgId: OPERATOR,
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
        {
          organisationById: async (id) => ORGS[id] ?? null,
          orgKindOf: async (id) => KINDS[id] ?? null,
        },
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
      const foreign = await assertTargetBelongsTo(r.principal, orgBEtaTask, kinds, { ownerOnly });
      expect(foreign.ok).toBe(false);
      if (!foreign.ok) expect(foreign.refusal.reason).toBe("target-other-organisation");
      expect(await assertTargetBelongsTo(r.principal, orgAEtaTask, kinds, { ownerOnly })).toEqual({ ok: true });
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
          { kind: "agent", agentId: "agent_fleet", verifiedOrgId: OPERATOR },
          world(),
        ),
      ),
    ).toBe("reserved-fleet-scope");
    expect(
      await refusedReason(
        resolveActingPrincipal(
          { kind: "person", personId: "user_1", verifiedOrgId: OPERATOR },
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
  orgId: OPERATOR,
  kind: "fleet",
};

function reasonOf(r: Awaited<ReturnType<typeof assertTargetBelongsTo>>) {
  expect(r.ok).toBe(false);
  if (r.ok) return undefined;
  expect(r.refusal.code).toBe("RBAC_DENIED");
  return r.refusal.reason;
}

describe("assertTargetBelongsTo — stored IDs only", () => {
  it("own-org target allowed, foreign-org target refused", async () => {
    expect(await assertTargetBelongsTo(agentA, { orgId: "org_a" }, kinds)).toEqual({ ok: true });
    expect(reasonOf(await assertTargetBelongsTo(agentA, { orgId: "org_b" }, kinds))).toBe(
      "target-other-organisation",
    );
  });

  it("compares IDs byte for byte: no case folding, no trimming", async () => {
    for (const orgId of ["ORG_A", " org_a", "org_a ", "org_a/"]) {
      expect(reasonOf(await assertTargetBelongsTo(agentA, { orgId }, kinds))).toBe(
        "target-other-organisation",
      );
    }
  });

  it("owner-only: allowed for the owner, refused for another principal of the same org", async () => {
    const task = { orgId: "org_a", ownerId: "agent_a_eta" };
    expect(await assertTargetBelongsTo(agentA, task, kinds, { ownerOnly: true })).toEqual({ ok: true });
    expect(reasonOf(await assertTargetBelongsTo(rhoA, task, kinds, { ownerOnly: true }))).toBe(
      "target-owner-mismatch",
    );
    expect(reasonOf(await assertTargetBelongsTo(personA, task, kinds, { ownerOnly: true }))).toBe(
      "target-owner-mismatch",
    );
    // without ownerOnly the same-org principal is admitted (org-level door)
    expect(await assertTargetBelongsTo(rhoA, task, kinds)).toEqual({ ok: true });
  });

  it("owner-only: a target with no stored owner is refused, never treated as 'anyone'", async () => {
    for (const ownerId of [undefined, null, ""]) {
      expect(
        reasonOf(await assertTargetBelongsTo(agentA, { orgId: "org_a", ownerId }, kinds, { ownerOnly: true })),
      ).toBe("target-owner-mismatch");
    }
  });

  it("an unstamped row is refused to every client principal", async () => {
    for (const p of [agentA, personA, serviceA]) {
      for (const orgId of [undefined, null, ""]) {
        expect(reasonOf(await assertTargetBelongsTo(p, { orgId, ownerId: p.principalId }, kinds))).toBe(
          "target-unstamped",
        );
      }
    }
  });

  it("an unstamped row is refused to the fleet principal too: no right inferred from an absence", async () => {
    for (const orgId of [undefined, null, ""]) {
      for (const opts of [{}, { fleetCrossOrg: true }]) {
        expect(reasonOf(await assertTargetBelongsTo(fleet, { orgId }, kinds, opts))).toBe("target-unstamped");
      }
    }
    expect(reasonOf(await assertTargetBelongsTo(fleet, null, kinds))).toBe("target-unstamped");
    // a fleet row is reachable only when it carries the fleet scope explicitly
    expect(await assertTargetBelongsTo(fleet, { orgId: OPERATOR }, kinds)).toEqual({ ok: true });
  });

  it("a fleet-scope row: client refused, fleet allowed", async () => {
    const fleetRow = { orgId: OPERATOR };
    for (const p of [agentA, personA, serviceA]) {
      expect(reasonOf(await assertTargetBelongsTo(p, fleetRow, kinds))).toBe("reserved-fleet-scope");
      expect(reasonOf(await assertTargetBelongsTo(p, fleetRow, kinds, { fleetCrossOrg: true }))).toBe(
        "reserved-fleet-scope",
      );
    }
    expect(await assertTargetBelongsTo(fleet, fleetRow, kinds)).toEqual({ ok: true });
  });

  it("fleet on a client row: refused by default, admitted only when the door declares a master export", async () => {
    expect(reasonOf(await assertTargetBelongsTo(fleet, { orgId: "org_b" }, kinds))).toBe(
      "target-other-organisation",
    );
    expect(await assertTargetBelongsTo(fleet, { orgId: "org_b" }, kinds, { fleetCrossOrg: true })).toEqual({
      ok: true,
    });
    // the declaration widens nothing for a client principal
    expect(
      reasonOf(await assertTargetBelongsTo(agentA, { orgId: "org_b" }, kinds, { fleetCrossOrg: true })),
    ).toBe("target-other-organisation");
  });

  it("owner-only binds the fleet principal too", async () => {
    expect(
      reasonOf(
        await assertTargetBelongsTo(
          fleet,
          { orgId: OPERATOR, ownerId: "agent_fleet" },
          kinds,
          { ownerOnly: true },
        ),
      ),
    ).toBe("target-owner-mismatch");
  });

  it("refuses an absent principal, an absent target and a principal with empty IDs", async () => {
    expect(reasonOf(await assertTargetBelongsTo(null, { orgId: "org_a" }, kinds))).toBe("credential-invalid");
    expect(reasonOf(await assertTargetBelongsTo(undefined, { orgId: "org_a" }, kinds))).toBe(
      "credential-invalid",
    );
    expect(reasonOf(await assertTargetBelongsTo(agentA, null, kinds))).toBe("target-unstamped");
    expect(
      reasonOf(await assertTargetBelongsTo({ ...agentA, principalId: "" }, { orgId: "org_a" }, kinds)),
    ).toBe("credential-invalid");
    expect(reasonOf(await assertTargetBelongsTo({ ...agentA, orgId: "" }, { orgId: "" }, kinds))).toBe(
      "credential-invalid",
    );
  });

  it("refuses a hand-built principal that claims the fleet scope without being fleet", async () => {
    for (const kind of ["person", "service"] as const) {
      const forged: ActingPrincipal = { principalId: "x", orgId: OPERATOR, kind };
      expect(reasonOf(await assertTargetBelongsTo(forged, { orgId: OPERATOR }, kinds))).toBe(
        "reserved-fleet-scope",
      );
    }
    // an agent in the fleet scope exists only through the fleet service account
    const directFleetAgent: ActingPrincipal = {
      principalId: "agent_fleet",
      orgId: OPERATOR,
      kind: "agent",
    };
    expect(reasonOf(await assertTargetBelongsTo(directFleetAgent, { orgId: OPERATOR }, kinds))).toBe(
      "reserved-fleet-scope",
    );
    // and kind "fleet" outside the fleet scope is not fleet
    const fakeFleet: ActingPrincipal = { principalId: "svc_a", orgId: "org_a", kind: "fleet" };
    expect(reasonOf(await assertTargetBelongsTo(fakeFleet, {}, kinds))).toBe("reserved-fleet-scope");
  });

  it("a fleet-stamped agent acting through the fleet service reaches fleet rows, not unstamped or client rows", async () => {
    const fleetAgent: ActingPrincipal = {
      principalId: "agent_fleet",
      orgId: OPERATOR,
      kind: "agent",
      viaServiceAccountId: "svc_fleet",
    };
    expect(await assertTargetBelongsTo(fleetAgent, { orgId: OPERATOR }, kinds)).toEqual({ ok: true });
    expect(reasonOf(await assertTargetBelongsTo(fleetAgent, {}, kinds))).toBe("target-unstamped");
    expect(
      reasonOf(await assertTargetBelongsTo(fleetAgent, { orgId: "org_a" }, kinds, { fleetCrossOrg: true })),
    ).toBe("target-other-organisation");
  });

  it("carries the consumer's door on the refusal", async () => {
    const r = await assertTargetBelongsTo(agentA, { orgId: "org_b" }, kinds, { door: "tasks:deleteTask" });
    expect(!r.ok && r.refusal.door).toBe("tasks:deleteTask");
  });
});

// ---------------------------------------------------------------------------
// RULING 4: the fleet is the operator org, decided by the adapter from data
// ---------------------------------------------------------------------------

describe("RULING 4 — the fleet is the org the adapter calls operator", () => {
  const RETIRED_LITERAL = "vantageos:fleet";
  const operatorRow = { orgId: OPERATOR };

  async function resolvedFleet(): Promise<ActingPrincipal> {
    const r = await resolveActingPrincipal({ kind: "service", serviceAccountId: "svc_fleet" }, world());
    expect(r.ok).toBe(true);
    if (!r.ok) throw new Error("unreachable");
    return r.principal;
  }

  it("an operator-org principal, resolved from data, reaches an operator-stamped row", async () => {
    const principal = await resolvedFleet();
    expect(principal).toEqual({ principalId: "svc_fleet", orgId: OPERATOR, kind: "fleet" });
    expect(await assertTargetBelongsTo(principal, operatorRow, kinds)).toEqual({ ok: true });
  });

  it("a client principal is refused on an operator-stamped row, with or without fleetCrossOrg", async () => {
    for (const p of [agentA, personA, serviceA]) {
      for (const opts of [{}, { fleetCrossOrg: true }]) {
        expect(reasonOf(await assertTargetBelongsTo(p, operatorRow, kinds, opts))).toBe(
          "reserved-fleet-scope",
        );
      }
    }
  });

  it("an adapter answering null is not fleet: the service resolves as a plain service and the target is refused", async () => {
    const unknown = { orgKindOf: async () => null };
    const r = await resolveActingPrincipal(
      { kind: "service", serviceAccountId: "svc_fleet" },
      world(unknown),
    );
    expect(r).toEqual({
      ok: true,
      principal: { principalId: "svc_fleet", orgId: OPERATOR, kind: "service" },
    });
    // a principal claiming fleet on an org the adapter does not call operator
    expect(reasonOf(await assertTargetBelongsTo(fleet, operatorRow, unknown))).toBe(
      "reserved-fleet-scope",
    );
    // and nothing is widened for a cross-org export to an org nobody vouches for
    expect(
      reasonOf(await assertTargetBelongsTo(fleet, { orgId: "org_b" }, unknown, { fleetCrossOrg: true })),
    ).toBe("reserved-fleet-scope");
  });

  it("an adapter that answers anything but the exact kind is not fleet", async () => {
    for (const answer of ["Operator", "fleet", "master", true, 1, {}]) {
      // biome-ignore lint/suspicious/noExplicitAny: a malformed adapter answer is the probe
      const odd = { orgKindOf: async () => answer as any };
      expect(reasonOf(await assertTargetBelongsTo(fleet, operatorRow, odd))).toBe(
        "reserved-fleet-scope",
      );
    }
  });

  it("a fleet master export reaches a client row only when the adapter knows that org as a client", async () => {
    const principal = await resolvedFleet();
    expect(
      await assertTargetBelongsTo(principal, { orgId: "org_b" }, kinds, { fleetCrossOrg: true }),
    ).toEqual({ ok: true });
    expect(
      reasonOf(
        await assertTargetBelongsTo(principal, { orgId: "org_unknown" }, kinds, { fleetCrossOrg: true }),
      ),
    ).toBe("target-other-organisation");
  });

  it("a missing or throwing adapter refuses, on both resolution and target check", async () => {
    const throwing = {
      orgKindOf: async () => {
        throw new Error("db down secret-xyz");
      },
    };
    for (const lookups of [throwing, { orgKindOf: undefined }]) {
      expect(
        await refusedReason(
          resolveActingPrincipal({ kind: "service", serviceAccountId: "svc_fleet" }, world(lookups)),
        ),
      ).toBe("principal-lookup-failed");
      expect(
        await refusedReason(
          resolveActingPrincipal(
            { kind: "agent", agentId: "agent_a_eta", verifiedOrgId: "org_a" },
            world(lookups),
          ),
        ),
      ).toBe("principal-lookup-failed");
      const r = await assertTargetBelongsTo(agentA, { orgId: "org_a" }, lookups);
      expect(reasonOf(r)).toBe("principal-lookup-failed");
      expect(JSON.stringify(r)).not.toContain("secret-xyz");
    }
    // biome-ignore lint/suspicious/noExplicitAny: an absent adapter is the probe
    expect(reasonOf(await assertTargetBelongsTo(agentA, { orgId: "org_a" }, undefined as any))).toBe(
      "principal-lookup-failed",
    );
  });

  it("an unstamped row is refused to the operator principal and to a client alike", async () => {
    const principal = await resolvedFleet();
    for (const p of [principal, agentA]) {
      for (const orgId of [undefined, null, ""]) {
        expect(reasonOf(await assertTargetBelongsTo(p, { orgId }, kinds, { fleetCrossOrg: true }))).toBe(
          "target-unstamped",
        );
      }
    }
  });

  it("a literal 'vantageos:fleet' stamp is just an unknown org: refused to everyone", async () => {
    const principal = await resolvedFleet();
    const legacyRow = { orgId: RETIRED_LITERAL };
    for (const opts of [{}, { fleetCrossOrg: true }]) {
      expect((await assertTargetBelongsTo(principal, legacyRow, kinds, opts)).ok).toBe(false);
      expect((await assertTargetBelongsTo(agentA, legacyRow, kinds, opts)).ok).toBe(false);
    }
    // a principal stamped with the literal is not fleet either
    const literalFleet: ActingPrincipal = {
      principalId: "svc_x",
      orgId: RETIRED_LITERAL,
      kind: "fleet",
    };
    expect(reasonOf(await assertTargetBelongsTo(literalFleet, legacyRow, kinds))).toBe(
      "reserved-fleet-scope",
    );
    // and a service account stamped with it resolves to no mapped organisation
    const legacy = world({
      serviceAccountById: async (id) =>
        id === "svc_legacy" ? { id, orgId: RETIRED_LITERAL, active: true } : null,
    });
    expect(
      await refusedReason(resolveActingPrincipal({ kind: "service", serviceAccountId: "svc_legacy" }, legacy)),
    ).toBe("organisation-not-active");
  });

  it("the operator org must itself be mapped and active", async () => {
    expect(
      await refusedReason(
        resolveActingPrincipal(
          { kind: "service", serviceAccountId: "svc_fleet" },
          world({
            organisationById: async (id) => (id === OPERATOR ? { id, active: false } : (ORGS[id] ?? null)),
          }),
        ),
      ),
    ).toBe("organisation-not-active");
  });
});
