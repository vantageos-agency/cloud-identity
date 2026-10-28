import { describe, expect, it, vi } from "vitest";
import {
  type PersonalAgentRow,
  type PrincipalLookups,
  type PrincipalRow,
  resolvePersonalAgent,
} from "../src/index.js";

/**
 * resolvePersonalAgent: a PERSON caller in organisation O acts as the agent
 * that person designates when EXACTLY ONE active agent of O designates them.
 * Zero, or more than one, leaves the caller person-scoped. An agent of another
 * organisation is never selected. A lookup that throws is a refusal whose text
 * is never surfaced.
 */

const PERSON = "user_stephane";
const ORG = "org_a";

const AGENTS: Record<string, PrincipalRow> = {
  tele: { id: "tele", orgId: "org_a", active: true },
  tele2: { id: "tele2", orgId: "org_a", active: true },
  off: { id: "off", orgId: "org_a", active: false },
  foreign: { id: "foreign", orgId: "org_b", active: true },
};

const row = (id: string, over: Partial<PersonalAgentRow> = {}): PersonalAgentRow => ({
  ...(AGENTS[id] as PrincipalRow),
  personalAgentOf: PERSON,
  ...over,
});

function lookups(overrides: Partial<PrincipalLookups> = {}): PrincipalLookups {
  return {
    agentById: (id) => AGENTS[id] ?? null,
    organisationById: (id) => ({ id, active: true }),
    orgKindOf: () => "client",
    ...overrides,
  };
}

const run = (
  designated: PersonalAgentRow[] | (() => never),
  principalLookups: PrincipalLookups = lookups(),
  input = { personId: PERSON, orgId: ORG },
) =>
  resolvePersonalAgent(input, {
    designatedAgents: typeof designated === "function" ? designated : () => designated,
    principalLookups,
  });

describe("resolvePersonalAgent", () => {
  it("GREEN: exactly one active designated agent -> the person acts as that agent, by stored IDs", async () => {
    const r = await run([row("tele")]);
    expect(r).toEqual({
      ok: true,
      actingAs: "agent",
      principal: { principalId: "tele", orgId: "org_a", kind: "agent" },
    });
  });

  it("GREEN: no designation -> the person stays the person (reason none)", async () => {
    expect(await run([])).toEqual({ ok: true, actingAs: "person", reason: "none" });
  });

  it.each([null, undefined])("GREEN: a lookup answering %s is no designation", async (answer) => {
    const r = await resolvePersonalAgent(
      { personId: PERSON, orgId: ORG },
      { designatedAgents: () => answer, principalLookups: lookups() },
    );
    expect(r).toEqual({ ok: true, actingAs: "person", reason: "none" });
  });

  it("GREEN: two active designations -> ambiguous, the person stays the person", async () => {
    const r = await run([row("tele"), row("tele2")]);
    expect(r).toEqual({ ok: true, actingAs: "person", reason: "ambiguous" });
  });

  it("GREEN: one active and one inactive designation -> the active one (exactly one ACTIVE)", async () => {
    const r = await run([row("off"), row("tele")]);
    expect(r).toMatchObject({ ok: true, actingAs: "agent", principal: { principalId: "tele" } });
  });

  it("GREEN: the only designated agent is inactive -> the person stays the person (reason inactive)", async () => {
    expect(await run([row("off")])).toEqual({ ok: true, actingAs: "person", reason: "inactive" });
  });

  it("DENY: an agent of another organisation is never selected, and never counted toward ambiguity", async () => {
    expect(await run([row("foreign")])).toEqual({ ok: true, actingAs: "person", reason: "none" });
    const r = await run([row("foreign"), row("tele")]);
    expect(r).toMatchObject({ ok: true, actingAs: "agent", principal: { principalId: "tele", orgId: "org_a" } });
  });

  it("DENY: a row that does not designate THIS person is never selected (a loose lookup cannot choose)", async () => {
    const r = await run([row("tele", { personalAgentOf: "user_someone_else" })]);
    expect(r).toEqual({ ok: true, actingAs: "person", reason: "none" });
  });

  it("DENY: the lookup is asked by the stored person and organisation IDs only", async () => {
    const designatedAgents = vi.fn(() => [row("tele")]);
    await resolvePersonalAgent(
      { personId: PERSON, orgId: ORG },
      { designatedAgents, principalLookups: lookups() },
    );
    expect(designatedAgents).toHaveBeenCalledTimes(1);
    expect(designatedAgents).toHaveBeenCalledWith(PERSON, ORG);
  });

  it("REFUSED: the lookup throws -> principal-lookup-failed, its text never surfaced", async () => {
    const r = await run(() => {
      throw new Error("SECRET-DB-DETAIL deployment prod-123");
    });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.code).toBe("RBAC_DENIED");
    expect(r.refusal.reason).toBe("principal-lookup-failed");
    expect(JSON.stringify(r.refusal)).not.toContain("SECRET-DB-DETAIL");
  });

  it("REFUSED: no designation lookup supplied -> principal-lookup-failed (never defaults to person)", async () => {
    const r = await resolvePersonalAgent(
      { personId: PERSON, orgId: ORG },
      { principalLookups: lookups() } as never,
    );
    expect(r).toMatchObject({ ok: false, refusal: { reason: "principal-lookup-failed" } });
  });

  it("REFUSED: a malformed row among the designations -> principal-record-invalid (it could hide an ambiguity)", async () => {
    const r = await run([row("tele"), { id: "", personalAgentOf: PERSON } as never]);
    expect(r).toMatchObject({ ok: false, refusal: { reason: "principal-record-invalid" } });
  });

  it("REFUSED: the selected agent's organisation is not active -> organisation-not-active", async () => {
    const r = await run([row("tele")], lookups({ organisationById: () => ({ id: ORG, active: false }) }));
    expect(r).toMatchObject({ ok: false, refusal: { reason: "organisation-not-active" } });
  });

  it("REFUSED: the agent read by ID disagrees with the designation row (gone since) -> principal-not-found", async () => {
    const r = await run([row("tele")], lookups({ agentById: () => null }));
    expect(r).toMatchObject({ ok: false, refusal: { reason: "principal-not-found" } });
  });

  it.each([
    { personId: "", orgId: ORG },
    { personId: PERSON, orgId: "" },
  ])("REFUSED: an empty person or organisation ID (%o) is refused without a lookup", async (input) => {
    const designatedAgents = vi.fn(() => [row("tele")]);
    const r = await resolvePersonalAgent(input, { designatedAgents, principalLookups: lookups() });
    expect(r).toMatchObject({ ok: false, refusal: { reason: "credential-invalid" } });
    expect(designatedAgents).not.toHaveBeenCalled();
  });

  it("the refusal carries the consumer's door name", async () => {
    const r = await resolvePersonalAgent(
      { personId: "", orgId: ORG },
      { designatedAgents: () => [], principalLookups: lookups() },
      { door: "oauth:getAccessTokenByHash" },
    );
    expect(r).toMatchObject({ ok: false, refusal: { door: "oauth:getAccessTokenByHash" } });
  });
});
