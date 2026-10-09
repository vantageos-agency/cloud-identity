import { describe, expect, it } from "vitest";
import { type ActingPrincipal, filterTargetsBelongingTo, type OrgKind } from "../src/index.js";

/**
 * An ID-keyed row filter. A row is kept exactly when assertTargetBelongsTo
 * admits it; an unresolved principal or a failed lookup is a named refusal,
 * never an empty success; names never decide.
 */

const KINDS: Record<string, OrgKind> = { org_fleet: "operator", org_a: "client", org_b: "client" };
const lookups = { orgKindOf: (orgId: string) => KINDS[orgId] };

const AGENT_A: ActingPrincipal = { principalId: "a_1", orgId: "org_a", kind: "agent" };

type Row = { id: string; orgId?: string; ownerId?: string; createdBy?: string };

describe("filterTargetsBelongingTo", () => {
  it("keeps own-org rows", async () => {
    const rows: Row[] = [{ id: "r1", orgId: "org_a" }, { id: "r2", orgId: "org_a" }];
    const r = await filterTargetsBelongingTo(AGENT_A, rows, lookups);
    expect(r).toEqual({ ok: true, rows });
  });

  it("drops other-org rows", async () => {
    const r = await filterTargetsBelongingTo(
      AGENT_A,
      [{ id: "r1", orgId: "org_a" }, { id: "r2", orgId: "org_b" }, { id: "r3", orgId: "org_fleet" }, { id: "r4" }],
      lookups,
    );
    expect(r).toEqual({ ok: true, rows: [{ id: "r1", orgId: "org_a" }] });
  });

  it("an unresolved principal gets a named refusal, never an empty success", async () => {
    for (const p of [null, undefined, { principalId: "", orgId: "org_a", kind: "agent" } as ActingPrincipal]) {
      const r = await filterTargetsBelongingTo(p, [], lookups, { door: "tasks:list" });
      expect(r.ok).toBe(false);
      if (r.ok) throw new Error("expected a refusal");
      expect(r.refusal.code).toBe("RBAC_DENIED");
      expect(r.refusal.door).toBe("tasks:list");
    }
    const withRows = await filterTargetsBelongingTo(null, [{ id: "r1", orgId: "org_a" }], lookups);
    expect(withRows.ok).toBe(false);
  });

  it("the default door is named when none is given", async () => {
    const r = await filterTargetsBelongingTo(null, [], lookups);
    if (r.ok) throw new Error("expected a refusal");
    expect(r.refusal.door).toBe("filterTargetsBelongingTo");
  });

  it("a resolved principal with only foreign rows gets an empty success", async () => {
    const r = await filterTargetsBelongingTo(AGENT_A, [{ id: "r1", orgId: "org_b" }], lookups);
    expect(r).toEqual({ ok: true, rows: [] });
    expect(await filterTargetsBelongingTo(AGENT_A, [], lookups)).toEqual({ ok: true, rows: [] });
  });

  it("a same-NAME row in another org is dropped", async () => {
    const r = await filterTargetsBelongingTo(
      AGENT_A,
      [{ id: "r1", orgId: "org_b", createdBy: "eta" }, { id: "r2", orgId: "org_a", createdBy: "eta" }],
      lookups,
    );
    expect(r).toEqual({ ok: true, rows: [{ id: "r2", orgId: "org_a", createdBy: "eta" }] });
  });

  it("a lookup failure is a refusal, not a drop and not a pass", async () => {
    const throwing = { orgKindOf: () => { throw new Error("db down"); } };
    const r = await filterTargetsBelongingTo(AGENT_A, [{ id: "r1", orgId: "org_a" }], throwing, { door: "d" });
    if (r.ok) throw new Error("expected a refusal");
    expect(r.refusal.reason).toBe("principal-lookup-failed");
    expect(r.refusal.door).toBe("d");

    const onlyForeign = {
      orgKindOf: (orgId: string) => {
        if (orgId === "org_b") throw new Error("db down");
        return KINDS[orgId];
      },
    };
    const f = await filterTargetsBelongingTo(AGENT_A, [{ id: "r1", orgId: "org_a" }, { id: "r2", orgId: "org_b" }], onlyForeign);
    expect(f.ok).toBe(false);

    const missing = await filterTargetsBelongingTo(AGENT_A, [], {} as never);
    expect(missing.ok).toBe(false);
  });

  it("mixed input keeps its order", async () => {
    const rows: Row[] = [
      { id: "1", orgId: "org_a" },
      { id: "2", orgId: "org_b" },
      { id: "3", orgId: "org_a" },
      { id: "4" },
      { id: "5", orgId: "org_a" },
    ];
    const r = await filterTargetsBelongingTo(AGENT_A, rows, lookups);
    if (!r.ok) throw new Error("expected rows");
    expect(r.rows.map((x) => x.id)).toEqual(["1", "3", "5"]);
  });

  it("ownerOnly keeps only the principal's own rows", async () => {
    const r = await filterTargetsBelongingTo(
      AGENT_A,
      [{ id: "1", orgId: "org_a", ownerId: "a_1" }, { id: "2", orgId: "org_a", ownerId: "a_2" }],
      lookups,
      { ownerOnly: true },
    );
    if (!r.ok) throw new Error("expected rows");
    expect(r.rows.map((x) => x.id)).toEqual(["1"]);
  });
});
