import { describe, it, expect } from "vitest";
import {
  passesScopeFilter,
  scopeFilterList,
  scopeFilterGet,
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

  it("undefined oauthCtx (legacy bearer) passes through as master-equivalent", () => {
    expect(
      passesScopeFilter(undefined, {
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
