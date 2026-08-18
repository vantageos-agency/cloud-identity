import { describe, it, expect } from "vitest";
import {
  passesScopeFilter,
  scopeFilterList,
  scopeFilterGet,
  LEGACY_WILDCARD_CTX,
} from "../src/scope-filter.js";
import type { OAuthCtx } from "../src/types.js";

const masterCtx: OAuthCtx = {
  scope: "master",
  fromAllowList: ["*"],
  namespaceReadPrefixes: [],
  namespaceWritePrefixes: [],
};

const scopedCtx: OAuthCtx = {
  scope: "tenant",
  fromAllowList: ["alice"],
  namespaceReadPrefixes: ["orchestrator/alpha"],
  namespaceWritePrefixes: [],
};

describe("passesScopeFilter — master + legacy", () => {
  it("master scope passes any row in List", () => {
    expect(
      passesScopeFilter(masterCtx, {
        createdBy: "stranger",
        namespace: "anywhere",
      }),
    ).toBe(true);
  });

  it("master scope passes in Get path too", () => {
    const row = { createdBy: "stranger", namespace: "anywhere" };
    expect(scopeFilterGet(masterCtx, row)).toBe(row);
  });

  it("LEGACY_WILDCARD_CTX, requested explicitly, passes through as master-equivalent", () => {
    // 0.3.0: the old undefined-oauthCtx wildcard is no longer inferred from
    // an omitted argument. Callers that want it request it BY NAME.
    expect(
      passesScopeFilter(LEGACY_WILDCARD_CTX, {
        createdBy: "stranger",
        namespace: "anywhere",
      }),
    ).toBe(true);
  });
});

describe("passesScopeFilter — fromAllowList", () => {
  it("allows when row.createdBy is in fromAllowList", () => {
    expect(
      passesScopeFilter(scopedCtx, { createdBy: "alice", namespace: "x/y" }),
    ).toBe(true);
  });

  it("rejects when row.createdBy is NOT in fromAllowList and namespace not allowed", () => {
    expect(
      passesScopeFilter(scopedCtx, {
        createdBy: "bob",
        namespace: "orchestrator/beta",
      }),
    ).toBe(false);
  });

  it("empty fromAllowList has no effect (no allow via createdBy)", () => {
    const ctx: OAuthCtx = {
      scope: "tenant",
      fromAllowList: [],
      namespaceReadPrefixes: ["orchestrator/alpha"],
      namespaceWritePrefixes: [],
    };
    expect(
      passesScopeFilter(ctx, {
        createdBy: "alice",
        namespace: "orchestrator/alpha",
      }),
    ).toBe(true); // passes via namespace
    expect(
      passesScopeFilter(ctx, { createdBy: "alice", namespace: "other" }),
    ).toBe(false);
  });
});

describe("passesScopeFilter — namespacePrefix", () => {
  it("allows when namespace matches a read-prefix exactly", () => {
    expect(
      passesScopeFilter(scopedCtx, {
        createdBy: "bob",
        namespace: "orchestrator/alpha",
      }),
    ).toBe(true);
  });

  it("allows when namespace starts with prefix + '/'", () => {
    expect(
      passesScopeFilter(scopedCtx, {
        createdBy: "bob",
        namespace: "orchestrator/alpha/sub",
      }),
    ).toBe(true);
  });

  it("rejects substring matches that don't fall on '/' boundary", () => {
    expect(
      passesScopeFilter(scopedCtx, {
        createdBy: "bob",
        namespace: "orchestrator/alphabet",
      }),
    ).toBe(false);
  });

  it("empty namespaceReadPrefixes has no effect", () => {
    const ctx: OAuthCtx = {
      scope: "tenant",
      fromAllowList: ["alice"],
      namespaceReadPrefixes: [],
      namespaceWritePrefixes: [],
    };
    expect(
      passesScopeFilter(ctx, { createdBy: "alice", namespace: "anything" }),
    ).toBe(true);
    expect(
      passesScopeFilter(ctx, { createdBy: "bob", namespace: "anything" }),
    ).toBe(false);
  });

  it("both fields empty → deny-by-default for non-master", () => {
    const ctx: OAuthCtx = {
      scope: "tenant",
      fromAllowList: [],
      namespaceReadPrefixes: [],
      namespaceWritePrefixes: [],
    };
    expect(
      passesScopeFilter(ctx, { createdBy: "bob", namespace: "x" }),
    ).toBe(false);
  });
});

describe("passesScopeFilter — grantFields (0.5.0, grant-aware widening)", () => {
  // SCOPED identity under test: "alice" — fromAllowList=["alice"], NOT the
  // row's createdBy in any of these cases. Exercises the grant path in
  // isolation from the createdBy/namespace paths that 0.4.0 already covers.
  const aliceCtx: OAuthCtx = {
    scope: "tenant",
    fromAllowList: ["alice"],
    namespaceReadPrefixes: [],
    namespaceWritePrefixes: [],
  };

  it("grantee (named in a string grant field, e.g. mission pilot) reads — identity: alice", () => {
    const row = { createdBy: "bob", namespace: undefined, pilot: "alice" };
    expect(passesScopeFilter(aliceCtx, row, ["pilot"])).toBe(true);
  });

  it("non-grantee (named nowhere on the row) does NOT read — identity: alice", () => {
    const row = { createdBy: "bob", namespace: undefined, pilot: "carol" };
    expect(passesScopeFilter(aliceCtx, row, ["pilot"])).toBe(false);
  });

  it("grantee named inside an array grant field (e.g. mission agents) reads — identity: alice", () => {
    const row = { createdBy: "bob", namespace: undefined, agents: ["carol", "alice"] };
    expect(passesScopeFilter(aliceCtx, row, ["agents"])).toBe(true);
  });

  it("non-grantee absent from the array grant field does NOT read — identity: alice", () => {
    const row = { createdBy: "bob", namespace: undefined, agents: ["carol", "dave"] };
    expect(passesScopeFilter(aliceCtx, row, ["agents"])).toBe(false);
  });

  it("grantee named via a mandate-shaped grant field (fulfilledBy) reads — identity: alice", () => {
    const row = { createdBy: "bob", namespace: undefined, fulfilledBy: "alice" };
    expect(passesScopeFilter(aliceCtx, row, ["fulfilledBy"])).toBe(true);
  });

  it("non-grantee on a mandate-shaped row does NOT read — identity: alice", () => {
    const row = { createdBy: "bob", namespace: undefined, fulfilledBy: "dave" };
    expect(passesScopeFilter(aliceCtx, row, ["fulfilledBy"])).toBe(false);
  });

  it("regression: declaring NO grant fields is byte-identical to 0.4.0 behaviour — identity: alice", () => {
    const row = { createdBy: "bob", namespace: undefined, pilot: "alice" };
    // pilot="alice" would pass if declared, but it is NOT declared here —
    // omitting grantFields must reproduce the pre-0.5.0 createdBy/namespace-only
    // predicate exactly.
    expect(passesScopeFilter(aliceCtx, row)).toBe(false);
    expect(passesScopeFilter(aliceCtx, row, [])).toBe(false);
  });

  it("scopeFilterList threads grantFields through — identity: alice", () => {
    const rows = [
      { createdBy: "bob", namespace: undefined, pilot: "alice" },
      { createdBy: "carol", namespace: undefined, pilot: "dave" },
    ];
    expect(scopeFilterList(aliceCtx, rows, ["pilot"]).map((r) => r.createdBy)).toEqual(["bob"]);
    // No grantFields declared — neither row passes (dave/alice not in createdBy, no namespace).
    expect(scopeFilterList(aliceCtx, rows)).toEqual([]);
  });

  it("scopeFilterGet threads grantFields through — identity: alice", () => {
    const row = { createdBy: "bob", namespace: undefined, fulfilledBy: "alice" };
    expect(scopeFilterGet(aliceCtx, row, ["fulfilledBy"])).toEqual(row);
    expect(scopeFilterGet(aliceCtx, row)).toBeNull();
  });

  it("master scope still wildcards regardless of grantFields — identity: master", () => {
    const row = { createdBy: "bob", namespace: undefined, pilot: "someone-else" };
    expect(passesScopeFilter(masterCtx, row, ["pilot"])).toBe(true);
  });
});

describe("scopeFilterList + scopeFilterGet", () => {
  it("scopeFilterList drops cross-tenant rows", () => {
    const rows = [
      { createdBy: "alice", namespace: "x" },
      { createdBy: "bob", namespace: "orchestrator/alpha" },
      { createdBy: "carol", namespace: "orchestrator/beta" },
    ];
    const out = scopeFilterList(scopedCtx, rows);
    expect(out).toHaveLength(2);
    expect(out.map((r) => r.createdBy)).toEqual(["alice", "bob"]);
  });

  it("scopeFilterGet returns null when row is null", () => {
    expect(scopeFilterGet(scopedCtx, null)).toBeNull();
  });

  it("scopeFilterGet returns null on forbidden row (caller maps to 404)", () => {
    expect(
      scopeFilterGet(scopedCtx, {
        createdBy: "carol",
        namespace: "orchestrator/beta",
      }),
    ).toBeNull();
  });
});
