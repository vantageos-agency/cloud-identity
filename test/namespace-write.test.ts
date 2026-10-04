import { describe, it, expect } from "vitest";
import {
  assertNamespaceWrite,
  namespaceMatchesPrefix,
  passesScopeFilter,
  IdentityRefusalError,
  LEGACY_WILDCARD_CTX,
  type OAuthCtx,
} from "../src/index.js";

const ctx = (write: string[], read: string[] = write): OAuthCtx => ({
  scope: "tenant",
  fromAllowList: ["alice"],
  namespaceReadPrefixes: read,
  namespaceWritePrefixes: write,
});

function refusalOf(fn: () => void) {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(IdentityRefusalError);
    return (e as IdentityRefusalError).refusal;
  }
  throw new Error("expected a refusal");
}

describe("assertNamespaceWrite", () => {
  it("serves the exact prefix and a '/' sub-namespace", () => {
    const c = ctx(["team/finance"]);
    expect(() => assertNamespaceWrite(c, "team/finance")).not.toThrow();
    expect(() => assertNamespaceWrite(c, "team/finance/q3")).not.toThrow();
  });

  it("refuses the boundary case: team/finance-archive is NOT under team/finance", () => {
    const r = refusalOf(() => assertNamespaceWrite(ctx(["team/finance"]), "team/finance-archive"));
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe("namespace-write-denied");
  });

  it("refuses a namespace outside every prefix, and a parent of a prefix", () => {
    const c = ctx(["team/finance", "team/ops"]);
    expect(() => assertNamespaceWrite(c, "team/legal")).toThrow(IdentityRefusalError);
    expect(() => assertNamespaceWrite(c, "team")).toThrow(IdentityRefusalError);
  });

  it("serves any of several prefixes", () => {
    const c = ctx(["team/finance", "team/ops"]);
    expect(() => assertNamespaceWrite(c, "team/ops/runbooks")).not.toThrow();
  });

  it("refuses EMPTY write prefixes for a non-master, even with read prefixes", () => {
    const r = refusalOf(() => assertNamespaceWrite(ctx([], ["team/finance"]), "team/finance"));
    expect(r.reason).toBe("no-write-prefixes");
  });

  it("READ prefixes never grant a write", () => {
    const c = ctx(["team/ops"], ["team/finance"]);
    expect(() => assertNamespaceWrite(c, "team/finance")).toThrow(IdentityRefusalError);
  });

  it("master scope passes any namespace, with or without prefixes", () => {
    expect(() => assertNamespaceWrite(LEGACY_WILDCARD_CTX, "anything/at/all")).not.toThrow();
    const m: OAuthCtx = { ...ctx([]), scope: "master" };
    expect(() => assertNamespaceWrite(m, "team/finance")).not.toThrow();
  });

  it("an empty-string prefix grants nothing", () => {
    expect(() => assertNamespaceWrite(ctx([""]), "team/finance")).toThrow(IdentityRefusalError);
    expect(() => assertNamespaceWrite(ctx([""]), "/x")).toThrow(IdentityRefusalError);
  });

  it("refuses an empty or non-string namespace", () => {
    for (const ns of ["", undefined, null, 5]) {
      const r = refusalOf(() => assertNamespaceWrite(ctx(["team/finance"]), ns as never));
      expect(r.reason).toBe("namespace-invalid");
    }
  });

  it("a nullish oauth context is a programming error, never a pass", () => {
    expect(() => assertNamespaceWrite(undefined as never, "team/finance")).toThrow(TypeError);
  });

  it("names the supplied door", () => {
    const r = refusalOf(() => assertNamespaceWrite(ctx(["a"]), "b", "memories:store"));
    expect(r.door).toBe("memories:store");
  });
});

describe("namespaceMatchesPrefix — the one boundary rule, shared with the read filter", () => {
  it("equality or prefix + '/'", () => {
    expect(namespaceMatchesPrefix("team/finance", "team/finance")).toBe(true);
    expect(namespaceMatchesPrefix("team/finance/x", "team/finance")).toBe(true);
    expect(namespaceMatchesPrefix("team/finance-archive", "team/finance")).toBe(false);
    expect(namespaceMatchesPrefix("team", "team/finance")).toBe(false);
  });

  it("the read filter agrees with it on the boundary case", () => {
    const c = ctx([], ["team/finance"]);
    expect(passesScopeFilter(c, { namespace: "team/finance-archive" })).toBe(false);
    expect(passesScopeFilter(c, { namespace: "team/finance/q3" })).toBe(true);
  });
});
