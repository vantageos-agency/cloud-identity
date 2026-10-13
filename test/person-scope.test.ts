import { describe, expect, it } from "vitest";
import {
  type ActingPrincipal,
  filterTargetsBelongingTo,
  filterTargetsInPersonScope,
  type OrgKind,
  type PersonScope,
  type PersonScopeDeps,
} from "../src/index.js";

/**
 * A person-scope row filter, applied AFTER organisation isolation.
 *
 * Domain census (derived from the `PersonScope` union and the `rowScopeKeys`
 * return type in src/person-scope.ts, not from memory):
 *   - scope: null | undefined | { kind: "keys"; keys } | { kind: "all"; grantedBy }
 *            | any other value (unknown kind, malformed) -> refused loudly
 *   - keys:  non-empty set | empty set (refused)
 *   - grantedBy: non-empty string | empty / non-string (refused)
 *   - row keys: string | string[] (one or several) | undefined / null / "" / [] (dropped)
 *               | any other value -> refused loudly
 *   - scopeOf: returns | throws (refused, error kind only)
 */

const KINDS: Record<string, OrgKind> = { org_fleet: "operator", org_a: "client", org_b: "client" };
const orgKindOf = (orgId: string) => KINDS[orgId];

const PERSON_A: ActingPrincipal = { principalId: "p_1", orgId: "org_a", kind: "person" };

type Row = { id: string; orgId?: string; ownerId?: string; scopeKey?: string | string[] | null };

const keysOf = (...k: string[]): PersonScope => ({ kind: "keys", keys: new Set(k) });

function deps(scope: unknown, extra: Partial<PersonScopeDeps<Row>> = {}): PersonScopeDeps<Row> {
  return {
    orgKindOf,
    scopeOf: async () => scope as PersonScope,
    rowScopeKeys: (row: Row) => row.scopeKey as string | readonly string[] | undefined,
    ...extra,
  };
}

function refused(r: { ok: boolean } & Record<string, unknown>) {
  if (r.ok) throw new Error("expected a refusal");
  return (r as unknown as { refusal: { code: string; reason: string; door: string; detail: string } }).refusal;
}

describe("filterTargetsInPersonScope", () => {
  it("(a) drops rows outside the person's key set and keeps rows inside it", async () => {
    const rows: Row[] = [
      { id: "1", orgId: "org_a", scopeKey: "k_1" },
      { id: "2", orgId: "org_a", scopeKey: "k_2" },
      { id: "3", orgId: "org_a", scopeKey: "k_3" },
    ];
    const r = await filterTargetsInPersonScope(PERSON_A, rows, deps(keysOf("k_1", "k_3")));
    if (!r.ok) throw new Error("expected rows");
    expect(r.rows.map((x) => x.id)).toEqual(["1", "3"]);
  });

  it("(b) a row carrying several keys is kept when any one of them is in the set", async () => {
    const rows: Row[] = [
      { id: "1", orgId: "org_a", scopeKey: ["k_9", "k_2"] },
      { id: "2", orgId: "org_a", scopeKey: ["k_8", "k_9"] },
    ];
    const r = await filterTargetsInPersonScope(PERSON_A, rows, deps(keysOf("k_2")));
    if (!r.ok) throw new Error("expected rows");
    expect(r.rows.map((x) => x.id)).toEqual(["1"]);
  });

  it("(c) a row with no scope key is dropped, under a key set and under an explicit all-grant", async () => {
    const rows: Row[] = [
      { id: "undef", orgId: "org_a" },
      { id: "null", orgId: "org_a", scopeKey: null },
      { id: "empty-string", orgId: "org_a", scopeKey: "" },
      { id: "empty-array", orgId: "org_a", scopeKey: [] },
      { id: "keyed", orgId: "org_a", scopeKey: "k_1" },
    ];
    const r = await filterTargetsInPersonScope(PERSON_A, rows, deps(keysOf("k_1", "")));
    if (!r.ok) throw new Error("expected rows");
    expect(r.rows.map((x) => x.id)).toEqual(["keyed"]);

    const all = await filterTargetsInPersonScope(PERSON_A, rows, deps({ kind: "all", grantedBy: "role:manager" }));
    if (!all.ok) throw new Error("expected rows");
    expect(all.rows.map((x) => x.id)).toEqual(["keyed"]);
  });

  it("(d) an absent scope is a typed refusal with a stable code, even for an empty list", async () => {
    for (const scope of [null, undefined]) {
      for (const rows of [[{ id: "1", orgId: "org_a", scopeKey: "k_1" }], []] as Row[][]) {
        const r = await filterTargetsInPersonScope(PERSON_A, rows, deps(scope), { door: "rows:list" });
        const ref = refused(r);
        expect(ref.code).toBe("RBAC_DENIED");
        expect(ref.reason).toBe("person-scope-absent");
        expect(ref.door).toBe("rows:list");
      }
    }
  });

  it("the default door is named when none is given", async () => {
    const ref = refused(await filterTargetsInPersonScope(PERSON_A, [], deps(null)));
    expect(ref.door).toBe("filterTargetsInPersonScope");
  });

  it("(e) an empty key set is a refusal, never an empty success", async () => {
    const ref = refused(await filterTargetsInPersonScope(PERSON_A, [], deps(keysOf()), { door: "d" }));
    expect(ref.code).toBe("RBAC_DENIED");
    expect(ref.reason).toBe("person-scope-empty");
    expect(ref.door).toBe("d");
  });

  it("(f) an all-grant with a reason keeps every keyed org row; with an empty reason it is refused", async () => {
    const rows: Row[] = [
      { id: "1", orgId: "org_a", scopeKey: "k_1" },
      { id: "2", orgId: "org_b", scopeKey: "k_2" },
      { id: "3", orgId: "org_a", scopeKey: ["k_7"] },
    ];
    const r = await filterTargetsInPersonScope(PERSON_A, rows, deps({ kind: "all", grantedBy: "role:manager" }));
    if (!r.ok) throw new Error("expected rows");
    expect(r.rows.map((x) => x.id)).toEqual(["1", "3"]);

    for (const grantedBy of ["", "   ", undefined, 42]) {
      const ref = refused(await filterTargetsInPersonScope(PERSON_A, rows, deps({ kind: "all", grantedBy })));
      expect(ref.code).toBe("RBAC_DENIED");
      expect(ref.reason).toBe("person-scope-grant-unreasoned");
    }
  });

  it("an unknown scope kind or a malformed key set is refused loudly, never read as all", async () => {
    for (const scope of [
      { kind: "everything" },
      { kind: "keys" },
      { kind: "keys", keys: ["k_1"] },
      "all",
      true,
    ]) {
      const ref = refused(await filterTargetsInPersonScope(PERSON_A, [], deps(scope)));
      expect(ref.reason).toBe("person-scope-malformed");
    }
  });

  it("a row key of an unreadable form refuses the whole call, never a silent drop", async () => {
    for (const scopeKey of [42, { id: "k_1" }, ["k_1", 7]]) {
      const rows = [{ id: "1", orgId: "org_a", scopeKey }] as unknown as Row[];
      const ref = refused(await filterTargetsInPersonScope(PERSON_A, rows, deps(keysOf("k_1"))));
      expect(ref.reason).toBe("person-scope-malformed");
    }
  });

  it("(g) scopeOf throwing is a refusal naming only the error kind, never its message", async () => {
    class StoreDownError extends Error {
      constructor() {
        super("secret connection string postgres://u:pw@host");
        this.name = "StoreDownError";
      }
    }
    const throwing = deps(null, { scopeOf: async () => { throw new StoreDownError(); } });
    const ref = refused(await filterTargetsInPersonScope(PERSON_A, [], throwing, { door: "d" }));
    expect(ref.code).toBe("RBAC_DENIED");
    expect(ref.reason).toBe("person-scope-lookup-failed");
    expect(ref.door).toBe("d");
    expect(ref.detail).toContain("StoreDownError");
    expect(ref.detail).not.toContain("postgres");
    expect(ref.detail).not.toContain("secret");

    const syncThrow = deps(null, { scopeOf: () => { throw new TypeError("boom"); } });
    const s = refused(await filterTargetsInPersonScope(PERSON_A, [], syncThrow));
    expect(s.reason).toBe("person-scope-lookup-failed");
    expect(s.detail).toContain("TypeError");
    expect(s.detail).not.toContain("boom");

    const rowThrow = deps(keysOf("k_1"), { rowScopeKeys: () => { throw new RangeError("row secret"); } });
    const rr = refused(await filterTargetsInPersonScope(PERSON_A, [{ id: "1", orgId: "org_a", scopeKey: "k_1" }], rowThrow));
    expect(rr.reason).toBe("person-scope-lookup-failed");
    expect(rr.detail).toContain("RangeError");
    expect(rr.detail).not.toContain("row secret");
  });

  it("(h) organisation isolation applies first: another org's row is dropped even with an in-set key", async () => {
    const rows: Row[] = [
      { id: "own", orgId: "org_a", scopeKey: "k_1" },
      { id: "foreign", orgId: "org_b", scopeKey: "k_1" },
      { id: "fleet", orgId: "org_fleet", scopeKey: "k_1" },
      { id: "unstamped", scopeKey: "k_1" },
    ];
    const r = await filterTargetsInPersonScope(PERSON_A, rows, deps(keysOf("k_1")));
    if (!r.ok) throw new Error("expected rows");
    expect(r.rows.map((x) => x.id)).toEqual(["own"]);
  });

  it("(i) an organisation-level refusal is returned unchanged, and scopeOf is never consulted", async () => {
    let consulted = false;
    const d = deps(keysOf("k_1"), { scopeOf: async () => { consulted = true; return keysOf("k_1"); } });
    const opts = { door: "rows:list" };
    for (const principal of [null, undefined, { principalId: "", orgId: "org_a", kind: "person" } as ActingPrincipal]) {
      const direct = await filterTargetsBelongingTo(principal, [], { orgKindOf }, opts);
      const viaScope = await filterTargetsInPersonScope(principal, [], d, opts);
      expect(direct.ok).toBe(false);
      expect(viaScope).toEqual(direct);
    }
    const misconfigured = await filterTargetsInPersonScope(PERSON_A, [], d, { ...opts, fleetCrossOrg: true });
    expect(misconfigured).toEqual(await filterTargetsBelongingTo(PERSON_A, [], { orgKindOf }, { ...opts, fleetCrossOrg: true }));
    expect(consulted).toBe(false);
  });

  it("(j) a key differing only by case (or by surrounding space) is not matched", async () => {
    const rows: Row[] = [
      { id: "upper", orgId: "org_a", scopeKey: "K_1" },
      { id: "spaced", orgId: "org_a", scopeKey: " k_1" },
      { id: "exact", orgId: "org_a", scopeKey: "k_1" },
    ];
    const r = await filterTargetsInPersonScope(PERSON_A, rows, deps(keysOf("k_1")));
    if (!r.ok) throw new Error("expected rows");
    expect(r.rows.map((x) => x.id)).toEqual(["exact"]);
  });

  it("fleet and service principals still need a presented scope: no implicit all", async () => {
    const FLEET: ActingPrincipal = { principalId: "svc_fleet", orgId: "org_fleet", kind: "fleet" };
    const SERVICE: ActingPrincipal = { principalId: "svc_a", orgId: "org_a", kind: "service" };
    const rows: Row[] = [
      { id: "1", orgId: "org_a", scopeKey: "k_1" },
      { id: "2", orgId: "org_a", scopeKey: "k_2" },
    ];
    const f = refused(await filterTargetsInPersonScope(FLEET, rows, deps(null), { fleetCrossOrg: true }));
    expect(f.reason).toBe("person-scope-absent");
    const s = refused(await filterTargetsInPersonScope(SERVICE, rows, deps(undefined)));
    expect(s.reason).toBe("person-scope-absent");

    const cross = await filterTargetsInPersonScope(FLEET, rows, deps(keysOf("k_2")), { fleetCrossOrg: true });
    if (!cross.ok) throw new Error("expected rows");
    expect(cross.rows.map((x) => x.id)).toEqual(["2"]);
  });

  it("scopeOf receives the resolved principal, and the kept rows keep input order", async () => {
    const seen: ActingPrincipal[] = [];
    const rows: Row[] = [
      { id: "3", orgId: "org_a", scopeKey: "k_1" },
      { id: "1", orgId: "org_a", scopeKey: "k_2" },
      { id: "2", orgId: "org_a", scopeKey: "k_1" },
    ];
    const d = deps(null, { scopeOf: (p) => { seen.push(p); return keysOf("k_1", "k_2"); } });
    const r = await filterTargetsInPersonScope(PERSON_A, rows, d);
    if (!r.ok) throw new Error("expected rows");
    expect(r.rows.map((x) => x.id)).toEqual(["3", "1", "2"]);
    expect(seen).toEqual([PERSON_A]);
  });
});
