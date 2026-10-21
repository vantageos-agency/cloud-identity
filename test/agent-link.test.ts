import { describe, expect, it } from "vitest";
import {
  type AgentLinkEvent,
  type StoredAgentLink,
  buildAgentLink,
  resolveAgentLink,
} from "../src/agent-link.js";

const NOW = 5_000_000;
const PERELLO = "org_perello";
const IRIS = "org_iris";
const PI = "agent_pi"; // an agent of PERELLO
const VICTOR = "agent_victor"; // an agent of IRIS
const THIRD_PERELLO = "agent_perello_other";
const THIRD_IRIS = "agent_iris_other";
const MARIE = "person_marie"; // admin of IRIS
const OPERATOR = "person_operator"; // admin of PERELLO
const IRIS_MEMBER = "person_iris_member"; // plain member of IRIS
const REASON = "pi and victor coordinate the HR onboarding";
const ADMIN_ROLES = ["org:admin"] as const;

type AgentRow = { id: string; orgId: string; active: boolean };
type MemberRow = { active: boolean; role: string | null; orgId: string };

/**
 * A scoped directory: every read is by the exact key it is given. There is no
 * fleet-wide or master reader, so a membership in one organisation can never
 * answer for another.
 */
function directory() {
  const agents = new Map<string, AgentRow>([
    [PI, { id: PI, orgId: PERELLO, active: true }],
    [VICTOR, { id: VICTOR, orgId: IRIS, active: true }],
    [THIRD_PERELLO, { id: THIRD_PERELLO, orgId: PERELLO, active: true }],
    [THIRD_IRIS, { id: THIRD_IRIS, orgId: IRIS, active: true }],
  ]);
  const members = new Map<string, MemberRow>([
    [`${MARIE}|${IRIS}`, { active: true, role: "org:admin", orgId: IRIS }],
    [`${OPERATOR}|${PERELLO}`, { active: true, role: "org:admin", orgId: PERELLO }],
    [`${IRIS_MEMBER}|${IRIS}`, { active: true, role: "org:member", orgId: IRIS }],
  ]);
  const membershipReads: Array<[string, string]> = [];
  return {
    agents,
    members,
    membershipReads,
    lookupAgent: async (agentId: string) => agents.get(agentId) ?? null,
    lookupMembership: async (personId: string, orgId: string) => {
      membershipReads.push([personId, orgId]);
      return members.get(`${personId}|${orgId}`) ?? null;
    },
  };
}

function linkRow(over: Partial<StoredAgentLink> = {}): StoredAgentLink {
  return {
    fromAgentId: PI,
    fromOrgId: PERELLO,
    toAgentId: VICTOR,
    toOrgId: IRIS,
    grantedBy: MARIE,
    grantedAt: NOW - 1000,
    revokedAt: null,
    reason: REASON,
    ...over,
  };
}

const buildInput = {
  fromAgentId: PI,
  fromOrgId: PERELLO,
  toAgentId: VICTOR,
  toOrgId: IRIS,
  grantedBy: MARIE,
  reason: REASON,
  now: NOW,
};

function buildWith(dir: ReturnType<typeof directory>, input = buildInput) {
  return buildAgentLink(input, {
    lookupAgent: dir.lookupAgent,
    lookupMembership: dir.lookupMembership,
    adminRoles: ADMIN_ROLES,
  });
}

function resolveWith(
  dir: ReturnType<typeof directory>,
  rows: StoredAgentLink[],
  from: { agentId: string; orgId: string },
  toAgentId: string,
  events: AgentLinkEvent[] = [],
) {
  return resolveAgentLink(
    { fromAgent: from, toAgentId, door: "tasks:create" },
    {
      lookupAgentLink: async (f: string, t: string) =>
        rows.find((r) => r.fromAgentId === f && r.toAgentId === t) ?? null,
      lookupAgent: dir.lookupAgent,
      lookupMembership: dir.lookupMembership,
      adminRoles: ADMIN_ROLES,
      now: () => NOW,
      onAgentLink: (e) => void events.push(e),
    },
  );
}

const PI_CALLER = { agentId: PI, orgId: PERELLO };
const VICTOR_CALLER = { agentId: VICTOR, orgId: IRIS };

describe("agent link: buildAgentLink", () => {
  it("builds the exact row for an admin of the TARGET organisation", async () => {
    const dir = directory();
    expect(await buildWith(dir)).toEqual({
      ok: true,
      link: {
        fromAgentId: PI,
        fromOrgId: PERELLO,
        toAgentId: VICTOR,
        toOrgId: IRIS,
        grantedBy: MARIE,
        grantedAt: NOW,
        revokedAt: null,
        reason: REASON,
      },
    });
    // the membership read is scoped to the target organisation only
    expect(dir.membershipReads).toEqual([[MARIE, IRIS]]);
  });

  it("refuses a grantor who is a member but not an admin of the target organisation", async () => {
    const r = await buildWith(directory(), { ...buildInput, grantedBy: IRIS_MEMBER });
    expect(r).toMatchObject({ ok: false, refusal: { code: "RBAC_DENIED", reason: "agent-link-grantor-not-admin" } });
  });

  it("refuses a grantor who is admin of the SOURCE organisation only", async () => {
    const dir = directory();
    const r = await buildWith(dir, { ...buildInput, grantedBy: OPERATOR });
    expect(r).toMatchObject({ ok: false, refusal: { code: "RBAC_DENIED", reason: "agent-link-grantor-not-admin" } });
    expect(dir.membershipReads).toEqual([[OPERATOR, IRIS]]);
  });

  it("refuses a grantor whose membership in the target organisation is inactive", async () => {
    const dir = directory();
    dir.members.set(`${MARIE}|${IRIS}`, { active: false, role: "org:admin", orgId: IRIS });
    expect(await buildWith(dir)).toMatchObject({ ok: false, refusal: { reason: "agent-link-grantor-not-admin" } });
  });

  it("refuses a link inside one organisation", async () => {
    const dir = directory();
    const r = await buildWith(dir, { ...buildInput, fromAgentId: THIRD_IRIS, fromOrgId: IRIS });
    expect(r).toMatchObject({ ok: false, refusal: { code: "RBAC_DENIED", reason: "agent-link-same-organisation" } });
  });

  it("refuses an inactive agent on either side", async () => {
    for (const id of [PI, VICTOR]) {
      const dir = directory();
      const row = dir.agents.get(id);
      if (row) dir.agents.set(id, { ...row, active: false });
      expect(await buildWith(dir)).toMatchObject({ ok: false, refusal: { reason: "agent-link-agent-unavailable" } });
    }
  });

  it("refuses an agent that belongs to another organisation than stated, or does not exist", async () => {
    const dir = directory();
    const wrongSource = await buildWith(dir, { ...buildInput, fromOrgId: "org_elsewhere" });
    expect(wrongSource).toMatchObject({ ok: false, refusal: { reason: "agent-link-agent-unavailable" } });
    const wrongTarget = await buildWith(dir, { ...buildInput, toAgentId: THIRD_PERELLO });
    expect(wrongTarget).toMatchObject({ ok: false, refusal: { reason: "agent-link-agent-unavailable" } });
    const missing = await buildWith(dir, { ...buildInput, toAgentId: "agent_ghost" });
    expect(missing).toMatchObject({ ok: false, refusal: { reason: "agent-link-agent-unavailable" } });
  });

  it("refuses a trivial reason, missing IDs, and an unconfigured admin role list", async () => {
    const cases: Array<Partial<typeof buildInput>> = [
      { reason: "too short" },
      { reason: "          " },
      { fromAgentId: "" },
      { fromOrgId: "" },
      { toAgentId: "" },
      { toOrgId: "" },
      { grantedBy: "" },
      { now: Number.NaN },
    ];
    for (const c of cases) {
      const r = await buildWith(directory(), { ...buildInput, ...c });
      expect(r).toMatchObject({ ok: false, refusal: { code: "RBAC_DENIED", reason: "agent-link-invalid" } });
    }
    const dir = directory();
    for (const adminRoles of [[], undefined] as const) {
      const r = await buildAgentLink(buildInput, {
        lookupAgent: dir.lookupAgent,
        lookupMembership: dir.lookupMembership,
        adminRoles: adminRoles as unknown as readonly string[],
      });
      expect(r).toMatchObject({ ok: false, refusal: { reason: "agent-link-invalid" } });
    }
  });

  it("reports a throwing lookup by kind only, never a grant", async () => {
    const dir = directory();
    const boom = async () => {
      throw new Error("db password=hunter2");
    };
    for (const deps of [
      { lookupAgent: boom, lookupMembership: dir.lookupMembership },
      { lookupAgent: dir.lookupAgent, lookupMembership: boom },
    ]) {
      const r = await buildAgentLink(buildInput, { ...deps, adminRoles: ADMIN_ROLES });
      expect(r).toMatchObject({ ok: false, refusal: { code: "RBAC_DENIED", reason: "agent-link-lookup-failed" } });
      if (!r.ok) expect(JSON.stringify(r.refusal)).not.toContain("hunter2");
    }
  });
});

describe("agent link: resolveAgentLink", () => {
  it("grants the exact pair and audits it", async () => {
    const dir = directory();
    const events: AgentLinkEvent[] = [];
    const r = await resolveWith(dir, [linkRow()], PI_CALLER, VICTOR, events);
    expect(r).toEqual({
      ok: true,
      toAgentId: VICTOR,
      toOrgId: IRIS,
      link: { reason: REASON, grantedBy: MARIE, grantedAt: NOW - 1000 },
    });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      outcome: "granted",
      fromAgentId: PI,
      fromOrgId: PERELLO,
      toAgentId: VICTOR,
      toOrgId: IRIS,
      door: "tasks:create",
      at: NOW,
    });
    // the grantor standing is read in the TARGET organisation
    expect(dir.membershipReads).toEqual([[MARIE, IRIS]]);
  });

  it("is directional: pi -> victor does not let victor reach pi", async () => {
    const r = await resolveWith(directory(), [linkRow()], VICTOR_CALLER, PI);
    expect(r).toMatchObject({ ok: false, refusal: { code: "RBAC_DENIED", reason: "agent-link-absent" } });
  });

  it("does not extend to a third agent of the same organisations", async () => {
    const dir = directory();
    const rows = [linkRow()];
    const otherTarget = await resolveWith(dir, rows, PI_CALLER, THIRD_IRIS);
    expect(otherTarget).toMatchObject({ ok: false, refusal: { reason: "agent-link-absent" } });
    const otherSource = await resolveWith(dir, rows, { agentId: THIRD_PERELLO, orgId: PERELLO }, VICTOR);
    expect(otherSource).toMatchObject({ ok: false, refusal: { reason: "agent-link-absent" } });
  });

  it("both ways: two rows, each granted by a person of its own target organisation", async () => {
    const dir = directory();
    const piToVictor = await buildWith(dir);
    const victorToPi = await buildWith(dir, {
      fromAgentId: VICTOR,
      fromOrgId: IRIS,
      toAgentId: PI,
      toOrgId: PERELLO,
      grantedBy: OPERATOR,
      reason: REASON,
      now: NOW,
    });
    if (!piToVictor.ok || !victorToPi.ok) throw new Error("both rows must build");
    const rows = [piToVictor.link, victorToPi.link];
    expect(await resolveWith(dir, rows, PI_CALLER, VICTOR)).toMatchObject({ ok: true, toOrgId: IRIS });
    expect(await resolveWith(dir, rows, VICTOR_CALLER, PI)).toMatchObject({ ok: true, toOrgId: PERELLO });
  });

  it("refuses after revocation", async () => {
    const r = await resolveWith(directory(), [linkRow({ revokedAt: NOW - 5 })], PI_CALLER, VICTOR);
    expect(r).toMatchObject({ ok: false, refusal: { code: "RBAC_DENIED", reason: "agent-link-revoked" } });
  });

  it("has no time bound: an old, unrevoked link still grants", async () => {
    const r = await resolveWith(directory(), [linkRow({ grantedAt: 1 })], PI_CALLER, VICTOR);
    expect(r.ok).toBe(true);
  });

  it("is voided when the grantor leaves the target organisation", async () => {
    const dir = directory();
    dir.members.delete(`${MARIE}|${IRIS}`);
    const r = await resolveWith(dir, [linkRow()], PI_CALLER, VICTOR);
    expect(r).toMatchObject({ ok: false, refusal: { code: "RBAC_DENIED", reason: "agent-link-grantor-void" } });
  });

  it("is voided when the grantor loses admin or the membership goes inactive", async () => {
    const demoted = directory();
    demoted.members.set(`${MARIE}|${IRIS}`, { active: true, role: "org:member", orgId: IRIS });
    expect(await resolveWith(demoted, [linkRow()], PI_CALLER, VICTOR)).toMatchObject({
      ok: false,
      refusal: { reason: "agent-link-grantor-void" },
    });
    const inactive = directory();
    inactive.members.set(`${MARIE}|${IRIS}`, { active: false, role: "org:admin", orgId: IRIS });
    expect(await resolveWith(inactive, [linkRow()], PI_CALLER, VICTOR)).toMatchObject({
      ok: false,
      refusal: { reason: "agent-link-grantor-void" },
    });
  });

  it("is not rescued by the grantor being admin of the SOURCE organisation", async () => {
    const dir = directory();
    dir.members.delete(`${MARIE}|${IRIS}`);
    dir.members.set(`${MARIE}|${PERELLO}`, { active: true, role: "org:admin", orgId: PERELLO });
    const r = await resolveWith(dir, [linkRow()], PI_CALLER, VICTOR);
    expect(r).toMatchObject({ ok: false, refusal: { reason: "agent-link-grantor-void" } });
  });

  it("refuses when the target agent is inactive, gone, or moved to another organisation", async () => {
    const inactive = directory();
    inactive.agents.set(VICTOR, { id: VICTOR, orgId: IRIS, active: false });
    const moved = directory();
    moved.agents.set(VICTOR, { id: VICTOR, orgId: "org_elsewhere", active: true });
    const gone = directory();
    gone.agents.delete(VICTOR);
    for (const dir of [inactive, moved, gone]) {
      const r = await resolveWith(dir, [linkRow()], PI_CALLER, VICTOR);
      expect(r).toMatchObject({ ok: false, refusal: { code: "RBAC_DENIED", reason: "agent-link-agent-unavailable" } });
    }
  });

  it("refuses a row for another pair, and a caller whose organisation is not the row's", async () => {
    const dir = directory();
    const loose = await resolveAgentLink(
      { fromAgent: PI_CALLER, toAgentId: VICTOR, door: "d" },
      {
        lookupAgentLink: async () => linkRow({ fromAgentId: THIRD_PERELLO, grantedBy: "person_secret_grantor" }),
        lookupAgent: dir.lookupAgent,
        lookupMembership: dir.lookupMembership,
        adminRoles: ADMIN_ROLES,
      },
    );
    expect(loose).toMatchObject({ ok: false, refusal: { reason: "agent-link-mismatch" } });
    const wrongOrg = await resolveWith(dir, [linkRow()], { agentId: PI, orgId: "org_elsewhere" }, VICTOR);
    expect(wrongOrg).toMatchObject({ ok: false, refusal: { reason: "agent-link-mismatch" } });
  });

  it("refuses a malformed stored row and malformed input", async () => {
    const dir = directory();
    const bad = { ...linkRow(), grantedAt: "yesterday" } as unknown as StoredAgentLink;
    expect(await resolveWith(dir, [bad], PI_CALLER, VICTOR)).toMatchObject({
      ok: false,
      refusal: { reason: "agent-link-invalid" },
    });
    const sameOrgRow = linkRow({ toOrgId: PERELLO });
    expect(await resolveWith(dir, [sameOrgRow], PI_CALLER, VICTOR)).toMatchObject({
      ok: false,
      refusal: { reason: "agent-link-invalid" },
    });
    expect(await resolveWith(dir, [linkRow()], PI_CALLER, "")).toMatchObject({
      ok: false,
      refusal: { reason: "agent-link-invalid" },
    });
    expect(await resolveWith(dir, [linkRow()], { agentId: "", orgId: PERELLO }, VICTOR)).toMatchObject({
      ok: false,
      refusal: { reason: "agent-link-invalid" },
    });
  });

  it("reports a throwing lookup by kind only, never a grant", async () => {
    const dir = directory();
    const boom = async () => {
      throw new TypeError("db password=hunter2");
    };
    const base = {
      lookupAgentLink: async () => linkRow(),
      lookupAgent: dir.lookupAgent,
      lookupMembership: dir.lookupMembership,
      adminRoles: ADMIN_ROLES,
    };
    for (const over of [{ lookupAgentLink: boom }, { lookupAgent: boom }, { lookupMembership: boom }]) {
      const r = await resolveAgentLink(
        { fromAgent: PI_CALLER, toAgentId: VICTOR, door: "d" },
        { ...base, ...over },
      );
      expect(r).toMatchObject({ ok: false, refusal: { code: "RBAC_DENIED", reason: "agent-link-lookup-failed" } });
      if (!r.ok) {
        const text = JSON.stringify(r.refusal);
        expect(text).not.toContain("hunter2");
        expect(text).toContain("TypeError");
      }
    }
  });

  it("audits every attempt and leaks no foreign ID or reason text in a refusal", async () => {
    const events: AgentLinkEvent[] = [];
    const dir = directory();
    const attempts: Array<Promise<unknown>> = [
      resolveWith(dir, [], PI_CALLER, VICTOR, events),
      resolveWith(dir, [linkRow({ revokedAt: 1 })], PI_CALLER, VICTOR, events),
      resolveWith(dir, [linkRow()], PI_CALLER, VICTOR, events),
    ];
    await Promise.all(attempts);
    expect(events.map((e) => e.outcome)).toEqual(["refused", "refused", "granted"]);
    expect(events[0]).toMatchObject({ outcome: "refused", reason: "agent-link-absent", fromAgentId: PI, toAgentId: VICTOR, door: "tasks:create" });

    const voided = directory();
    voided.members.delete(`${MARIE}|${IRIS}`);
    const revoked = await resolveWith(dir, [linkRow({ revokedAt: 1 })], PI_CALLER, VICTOR);
    const gone = await resolveWith(voided, [linkRow()], PI_CALLER, VICTOR);
    for (const r of [revoked, gone]) {
      expect(r.ok).toBe(false);
      if (!r.ok) {
        const text = JSON.stringify(r.refusal);
        for (const foreign of [MARIE, IRIS, REASON, "onboarding"]) expect(text).not.toContain(foreign);
      }
    }
  });

  it("a throwing audit sink flips neither a grant nor a refusal", async () => {
    const dir = directory();
    const deps = (rows: StoredAgentLink[]) => ({
      lookupAgentLink: async () => rows[0] ?? null,
      lookupAgent: dir.lookupAgent,
      lookupMembership: dir.lookupMembership,
      adminRoles: ADMIN_ROLES,
      onAgentLink: () => {
        throw new Error("sink down");
      },
    });
    const input = { fromAgent: PI_CALLER, toAgentId: VICTOR, door: "d" };
    expect((await resolveAgentLink(input, deps([linkRow()]))).ok).toBe(true);
    expect(await resolveAgentLink(input, deps([]))).toMatchObject({ ok: false, refusal: { reason: "agent-link-absent" } });
  });

  it("requires a configured admin role list: an empty one voids every link", async () => {
    const dir = directory();
    const r = await resolveAgentLink(
      { fromAgent: PI_CALLER, toAgentId: VICTOR, door: "d" },
      {
        lookupAgentLink: async () => linkRow(),
        lookupAgent: dir.lookupAgent,
        lookupMembership: dir.lookupMembership,
        adminRoles: [],
      },
    );
    expect(r.ok).toBe(false);
  });
});
