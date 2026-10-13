import { describe, expect, it } from "vitest";
import {
  type ActingPrincipal,
  assertAgentOwnedBy,
  resolveActingPrincipal,
  resolveCallerFromAgentCredential,
} from "../src/index.js";

/**
 * An agent bound by ID to its human owner.
 *
 * Domain census (derived from the code under test, src/principal-by-id.ts and
 * src/agent-caller.ts, not from memory):
 *   - credential owner: absent (parity with today) | present non-empty
 *     | present empty (credential-invalid)
 *   - agent row owner: equal | different | null | absent      -> agent-owner-mismatch unless equal
 *   - personById:  returns active row of the org | null | row of another org
 *                  | inactive row | malformed row (id differs)
 *                  | throws | is not supplied                  -> only the first admits
 *   - assertAgentOwnedBy principal: agent owned by the person | agent owned by
 *                  another | agent with no owner | non-agent kind | null
 *   - personId argument: matching | different | absent/empty
 */

const ORG_A = "org_aaa";
const ORG_B = "org_bbb";
const AGENT = "agent_1";
const OWNER = "user_owner";

type Row = Record<string, unknown> | null;

type World = {
  agent?: Row;
  owner?: Row;
  ownerThrows?: boolean;
  noPersonLookup?: boolean;
  orgs?: Record<string, unknown>;
};

function world(w: World = {}) {
  const calls: string[] = [];
  const personCalls: Array<[string, string]> = [];
  const orgs: Record<string, unknown> = w.orgs ?? {
    [ORG_A]: { id: ORG_A, label: "acme", active: true, allowedOrchestrators: [], scopes: [], orgKind: "client" },
    [ORG_B]: { id: ORG_B, label: "other", active: true, allowedOrchestrators: [], scopes: [], orgKind: "client" },
  };
  const agentRow: Row =
    "agent" in w ? (w.agent as Row) : { id: AGENT, orgId: ORG_A, active: true, ownerPersonId: OWNER };
  const ownerRow: Row = "owner" in w ? (w.owner as Row) : { id: OWNER, orgId: ORG_A, active: true };

  const principalLookups = {
    agentById: (id: string) => {
      calls.push("agentById");
      return id === AGENT ? agentRow : null;
    },
    ...(w.noPersonLookup
      ? {}
      : {
          personById: (personId: string, orgId: string) => {
            calls.push("personById");
            personCalls.push([personId, orgId]);
            if (w.ownerThrows) throw new Error("SECRET-DB-ERROR connection string leaked");
            return ownerRow;
          },
        }),
    organisationById: (id: string) => (orgs[id] ? { id, active: true } : null),
    orgKindOf: (id: string) => (orgs[id] as { orgKind?: string } | undefined)?.orgKind ?? null,
  };
  const orgLookups = {
    orgById: (id: string) => {
      calls.push("orgById");
      return orgs[id] ?? null;
    },
  };
  return { principalLookups, orgLookups, calls, personCalls };
}

function refusedOf(r: { ok: boolean } & Record<string, unknown>) {
  if (r.ok) throw new Error("expected a refusal");
  return (r as unknown as { refusal: { code: string; reason: string; door: string; detail: string } }).refusal;
}

const cred = (extra: Record<string, unknown> = {}) =>
  ({ kind: "agent", agentId: AGENT, verifiedOrgId: ORG_A, ...extra }) as never;

describe("resolveActingPrincipal: an agent with a presented owner", () => {
  it("(a) owner match: accepted, and the principal carries the proven owner", async () => {
    const w = world();
    const r = await resolveActingPrincipal(cred({ ownerPersonId: OWNER }), w.principalLookups);
    expect(r).toStrictEqual({
      ok: true,
      principal: { principalId: AGENT, orgId: ORG_A, kind: "agent", ownerPersonId: OWNER },
    });
    expect(w.personCalls).toEqual([[OWNER, ORG_A]]);
  });

  it("(b) the agent row's owner differs: refused agent-owner-mismatch, before any owner read", async () => {
    const w = world({ agent: { id: AGENT, orgId: ORG_A, active: true, ownerPersonId: "user_other" } });
    const r = await resolveActingPrincipal(cred({ ownerPersonId: OWNER }), w.principalLookups, "door-x");
    const f = refusedOf(r);
    expect(f.code).toBe("RBAC_DENIED");
    expect(f.reason).toBe("agent-owner-mismatch");
    expect(f.door).toBe("door-x");
    expect(w.personCalls).toEqual([]);
  });

  it("(b2) the agent row has a null owner or none: refused agent-owner-mismatch", async () => {
    for (const row of [
      { id: AGENT, orgId: ORG_A, active: true, ownerPersonId: null },
      { id: AGENT, orgId: ORG_A, active: true },
    ]) {
      const w = world({ agent: row });
      const r = await resolveActingPrincipal(cred({ ownerPersonId: OWNER }), w.principalLookups);
      expect(refusedOf(r).reason).toBe("agent-owner-mismatch");
    }
  });

  it("(b3) owner equality is byte for byte: case and whitespace differ", async () => {
    for (const stored of ["USER_OWNER", " user_owner", "user_owner "]) {
      const w = world({ agent: { id: AGENT, orgId: ORG_A, active: true, ownerPersonId: stored } });
      const r = await resolveActingPrincipal(cred({ ownerPersonId: OWNER }), w.principalLookups);
      expect(refusedOf(r).reason).toBe("agent-owner-mismatch");
    }
  });

  it("(c) owner not found: refused agent-owner-not-member, naming the case", async () => {
    const w = world({ owner: null });
    const f = refusedOf(await resolveActingPrincipal(cred({ ownerPersonId: OWNER }), w.principalLookups));
    expect(f.reason).toBe("agent-owner-not-member");
    expect(f.detail).toMatch(/not found/i);
  });

  it("(d) owner inactive: refused agent-owner-not-member, naming the case", async () => {
    const w = world({ owner: { id: OWNER, orgId: ORG_A, active: false } });
    const f = refusedOf(await resolveActingPrincipal(cred({ ownerPersonId: OWNER }), w.principalLookups));
    expect(f.reason).toBe("agent-owner-not-member");
    expect(f.detail).toMatch(/not active/i);
  });

  it("(e) owner of another organisation: refused agent-owner-not-member, naming the case", async () => {
    const w = world({ owner: { id: OWNER, orgId: ORG_B, active: true } });
    const f = refusedOf(await resolveActingPrincipal(cred({ ownerPersonId: OWNER }), w.principalLookups));
    expect(f.reason).toBe("agent-owner-not-member");
    expect(f.detail).toMatch(/another organisation/i);
  });

  it("(e2) owner unstamped or malformed: refused agent-owner-not-member", async () => {
    for (const owner of [
      { id: OWNER, active: true },
      { id: OWNER, orgId: null, active: true },
      { id: "someone_else", orgId: ORG_A, active: true },
      { id: OWNER, orgId: ORG_A },
    ]) {
      const w = world({ owner });
      const r = await resolveActingPrincipal(cred({ ownerPersonId: OWNER }), w.principalLookups);
      expect(refusedOf(r).reason).toBe("agent-owner-not-member");
    }
  });

  it("(f) the owner lookup throws: refused principal-lookup-failed, the error text never surfaced", async () => {
    const w = world({ ownerThrows: true });
    const f = refusedOf(await resolveActingPrincipal(cred({ ownerPersonId: OWNER }), w.principalLookups));
    expect(f.reason).toBe("principal-lookup-failed");
    expect(JSON.stringify(f)).not.toMatch(/SECRET|leaked|connection/);
  });

  it("(g) personById not supplied while an owner is presented: fails closed, never skips the check", async () => {
    const w = world({ noPersonLookup: true });
    const r = await resolveActingPrincipal(cred({ ownerPersonId: OWNER }), w.principalLookups);
    const f = refusedOf(r);
    expect(f.reason).toBe("principal-lookup-failed");
    expect(f.detail).toMatch(/no lookup was supplied/i);
  });

  it("(h) an empty ownerPersonId is not a credential", async () => {
    const w = world();
    const f = refusedOf(await resolveActingPrincipal(cred({ ownerPersonId: "" }), w.principalLookups));
    expect(f.reason).toBe("credential-invalid");
  });

  it("(i) the owner is proven only after the agent's own checks: a wrong-org agent is refused as today", async () => {
    const w = world({ agent: { id: AGENT, orgId: ORG_B, active: true, ownerPersonId: OWNER } });
    const f = refusedOf(await resolveActingPrincipal(cred({ ownerPersonId: OWNER }), w.principalLookups));
    expect(f.reason).toBe("other-organisation");
    expect(w.personCalls).toEqual([]);
  });
});

describe("resolveActingPrincipal: parity without ownerPersonId", () => {
  it("(j) no owner presented: the same result object as before, whatever the row stores", async () => {
    for (const agent of [
      { id: AGENT, orgId: ORG_A, active: true },
      { id: AGENT, orgId: ORG_A, active: true, ownerPersonId: OWNER },
      { id: AGENT, orgId: ORG_A, active: true, ownerPersonId: null },
    ]) {
      const w = world({ agent, noPersonLookup: true });
      const r = await resolveActingPrincipal(cred(), w.principalLookups);
      expect(r).toStrictEqual({ ok: true, principal: { principalId: AGENT, orgId: ORG_A, kind: "agent" } });
      if (r.ok) expect("ownerPersonId" in r.principal).toBe(false);
      expect(w.calls).not.toContain("personById");
    }
  });

  it("(k) an explicit undefined owner is the same as an absent one", async () => {
    const w = world({ noPersonLookup: true });
    const r = await resolveActingPrincipal(cred({ ownerPersonId: undefined }), w.principalLookups);
    expect(r).toStrictEqual({ ok: true, principal: { principalId: AGENT, orgId: ORG_A, kind: "agent" } });
  });

  it("(l) a name beside the ID is still refused whole", async () => {
    const w = world();
    const f = refusedOf(await resolveActingPrincipal(cred({ ownerName: "Laurent" }), w.principalLookups));
    expect(f.reason).toBe("credential-invalid");
  });
});

describe("resolveCallerFromAgentCredential", () => {
  it("(m) owner present: org, agent principal and the owner as a person of the same org", async () => {
    const w = world();
    const r = await resolveCallerFromAgentCredential(
      { agentId: AGENT, verifiedOrgId: ORG_A, ownerPersonId: OWNER },
      { orgLookups: w.orgLookups, principalLookups: w.principalLookups },
      { door: "tasks:list" },
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.org.id).toBe(ORG_A);
    expect(r.org.label).toBe("acme");
    expect(r.principal).toStrictEqual({ principalId: AGENT, orgId: ORG_A, kind: "agent", ownerPersonId: OWNER });
    expect(r.owner).toStrictEqual({ principalId: OWNER, orgId: ORG_A, kind: "person" });
  });

  it("(n) no ownerPersonId: owner is null and the principal carries none", async () => {
    const w = world({ noPersonLookup: true });
    const r = await resolveCallerFromAgentCredential(
      { agentId: AGENT, verifiedOrgId: ORG_A },
      { orgLookups: w.orgLookups, principalLookups: w.principalLookups },
      {},
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.owner).toBeNull();
    expect(r.principal).toStrictEqual({ principalId: AGENT, orgId: ORG_A, kind: "agent" });
  });

  it("(o) a refusal of the owner check comes back as { ok: false, refusal }", async () => {
    const w = world({ agent: { id: AGENT, orgId: ORG_A, active: true, ownerPersonId: "user_other" } });
    const r = await resolveCallerFromAgentCredential(
      { agentId: AGENT, verifiedOrgId: ORG_A, ownerPersonId: OWNER },
      { orgLookups: w.orgLookups, principalLookups: w.principalLookups },
      { door: "tasks:list" },
    );
    expect(r.ok).toBe(false);
    const f = refusedOf(r);
    expect(f.reason).toBe("agent-owner-mismatch");
    expect(f.door).toBe("tasks:list");
    expect("principal" in r).toBe(false);
  });

  it("(p) wrong organisation: an unmapped org is refused before the agent is read", async () => {
    const w = world();
    const r = await resolveCallerFromAgentCredential(
      { agentId: AGENT, verifiedOrgId: "org_zzz", ownerPersonId: OWNER },
      { orgLookups: w.orgLookups, principalLookups: w.principalLookups },
      {},
    );
    expect(refusedOf(r).reason).toBe("org-mapping-not-found");
    expect(w.calls).toEqual(["orgById"]);
  });

  it("(q) the agent belongs to another organisation than the credential: refused other-organisation", async () => {
    const w = world({ agent: { id: AGENT, orgId: ORG_B, active: true, ownerPersonId: OWNER } });
    const r = await resolveCallerFromAgentCredential(
      { agentId: AGENT, verifiedOrgId: ORG_A, ownerPersonId: OWNER },
      { orgLookups: w.orgLookups, principalLookups: w.principalLookups },
      {},
    );
    expect(refusedOf(r).reason).toBe("other-organisation");
  });

  it("(r) order: org by ID, then the agent by ID, then the owner", async () => {
    const w = world();
    await resolveCallerFromAgentCredential(
      { agentId: AGENT, verifiedOrgId: ORG_A, ownerPersonId: OWNER },
      { orgLookups: w.orgLookups, principalLookups: w.principalLookups },
      {},
    );
    expect(w.calls).toEqual(["orgById", "agentById", "personById"]);
  });

  it("(s) the door defaults to the function's own name", async () => {
    const w = world({ owner: null });
    const r = await resolveCallerFromAgentCredential(
      { agentId: AGENT, verifiedOrgId: ORG_A, ownerPersonId: OWNER },
      { orgLookups: w.orgLookups, principalLookups: w.principalLookups },
      {},
    );
    expect(refusedOf(r).door).toBe("resolveCallerFromAgentCredential");
  });

  it("(t) a name beside the IDs is refused credential-invalid, and nothing is read", async () => {
    const w = world();
    const r = await resolveCallerFromAgentCredential(
      { agentId: AGENT, verifiedOrgId: ORG_A, agentName: "eta" } as never,
      { orgLookups: w.orgLookups, principalLookups: w.principalLookups },
      {},
    );
    expect(refusedOf(r).reason).toBe("credential-invalid");
    expect(w.calls).toEqual([]);
  });

  it("(u) an absent credential is refused credential-invalid", async () => {
    const w = world();
    const r = await resolveCallerFromAgentCredential(
      null as never,
      { orgLookups: w.orgLookups, principalLookups: w.principalLookups },
      {},
    );
    expect(refusedOf(r).reason).toBe("credential-invalid");
  });
});

describe("assertAgentOwnedBy", () => {
  const agent = (extra: Partial<ActingPrincipal> = {}): ActingPrincipal => ({
    principalId: AGENT,
    orgId: ORG_A,
    kind: "agent",
    ownerPersonId: OWNER,
    ...extra,
  });

  it("(v) an agent owned by this person: accepted", () => {
    expect(assertAgentOwnedBy(agent(), OWNER)).toStrictEqual({ ok: true });
  });

  it("(w) an agent owned by another person: refused agent-not-owned, byte for byte", () => {
    for (const who of ["user_other", "USER_OWNER", "user_owner "]) {
      const f = refusedOf(assertAgentOwnedBy(agent(), who, { door: "d" }));
      expect(f.code).toBe("RBAC_DENIED");
      expect(f.reason).toBe("agent-not-owned");
      expect(f.door).toBe("d");
    }
  });

  it("(x) a non-agent principal is refused agent-not-owned, even when it carries the same owner ID", () => {
    for (const kind of ["person", "service", "fleet"] as const) {
      const p = { principalId: "x", orgId: ORG_A, kind, ownerPersonId: OWNER } as ActingPrincipal;
      expect(refusedOf(assertAgentOwnedBy(p, OWNER)).reason).toBe("agent-not-owned");
    }
  });

  it("(y) an agent with no proven owner is never owned: absent === absent is not a match", () => {
    const noOwner = agent({ ownerPersonId: undefined });
    for (const who of [undefined, "", OWNER]) {
      expect(refusedOf(assertAgentOwnedBy(noOwner, who as never)).reason).toBe("agent-not-owned");
    }
  });

  it("(z) an absent principal is refused agent-not-owned; the default door is the function's name", () => {
    const f = refusedOf(assertAgentOwnedBy(null, OWNER));
    expect(f.reason).toBe("agent-not-owned");
    expect(f.door).toBe("assertAgentOwnedBy");
  });
});
