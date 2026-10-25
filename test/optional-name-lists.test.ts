import { resolve } from "node:path";
import ts from "typescript";
import { describe, expect, it } from "vitest";
import {
  assertNamespaceWrite,
  IdentityRefusalError,
  isMasterScope,
  isWildcardScope,
  orgMappingRowSchema,
  type OAuthCtx,
  passesScopeFilter,
  resolveOrgFromClaim,
  scopeFilterGet,
  scopeFilterList,
} from "../src/index.js";

/**
 * 0.24.0: neither name list is REQUIRED any more, so a consumer can remove
 * them and keep only IDs.
 *
 *   - `OAuthCtx.fromAllowList` is optional. An absent list names nobody: it
 *     grants no row by `createdBy` or by a declared grant field, and it never
 *     makes a caller master. Master is decided by the declared `scope`.
 *   - The legacy `"*"` entry in `fromAllowList` still makes a caller master
 *     (deprecated second signal). Consumers attach contexts whose `scope` is
 *     not "master" and whose list is a stored roster that may hold `"*"`;
 *     dropping the signal would withhold master from them.
 *   - `orgMappingRowSchema.allowedOrchestrators` is optional, and the row's ID
 *     roster `allowedAgentIds` is read and exposed when present.
 */

const REPO_ROOT = resolve(__dirname, "..");

const noNames = (over: Partial<OAuthCtx> = {}): OAuthCtx => ({
  scope: "tenant",
  namespaceReadPrefixes: ["team/a"],
  namespaceWritePrefixes: ["team/a"],
  ...over,
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

describe("OAuthCtx without fromAllowList: type level", () => {
  it("a context and a mapping row without the name lists type-check", () => {
    const fixture = resolve(REPO_ROOT, "test/fixtures/optional-name-lists.typecheck.ts");
    const program = ts.createProgram([fixture], {
      strict: true,
      target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.ESNext,
      moduleResolution: ts.ModuleResolutionKind.Bundler,
      skipLibCheck: true,
      noEmit: true,
    });
    const diagnostics = ts
      .getPreEmitDiagnostics(program)
      .map((d) => ts.flattenDiagnosticMessageText(d.messageText, "\n"));
    expect(diagnostics).toEqual([]);
  }, 60_000);
});

describe("OAuthCtx without fromAllowList: runtime", () => {
  it("a non-master context with no list is not master, and does not throw", () => {
    expect(isMasterScope(noNames())).toBe(false);
    expect(isWildcardScope(noNames())).toBe(false);
  });

  it("master is decided by the declared scope, with no list", () => {
    expect(isMasterScope(noNames({ scope: "master" }))).toBe(true);
    expect(passesScopeFilter(noNames({ scope: "master" }), { createdBy: "x", namespace: "y" })).toBe(true);
  });

  it("an absent list names nobody: no row by createdBy, none by a grant field", () => {
    const ctx = noNames();
    expect(passesScopeFilter(ctx, { createdBy: "alice", namespace: "elsewhere" })).toBe(false);
    expect(passesScopeFilter(ctx, { createdBy: "*", namespace: "elsewhere" })).toBe(false);
    expect(passesScopeFilter(ctx, { createdBy: "alice", agents: ["alice"] } as never, ["agents"])).toBe(false);
  });

  it("namespace read prefixes still serve the row", () => {
    const ctx = noNames();
    const row = { createdBy: "alice", namespace: "team/a/notes" };
    expect(passesScopeFilter(ctx, row)).toBe(true);
    expect(scopeFilterGet(ctx, row)).toBe(row);
    expect(scopeFilterList(ctx, [row, { createdBy: "alice", namespace: "team/b" }])).toEqual([row]);
  });

  it("assertNamespaceWrite decides on write prefixes, and refuses with a typed refusal", () => {
    expect(() => assertNamespaceWrite(noNames(), "team/a/x")).not.toThrow();
    const r = refusalOf(() => assertNamespaceWrite(noNames(), "team/b"));
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe("namespace-write-denied");
  });

  it("a null list is read as absent, not as a throw", () => {
    const ctx = noNames({ fromAllowList: null as unknown as string[] });
    expect(isMasterScope(ctx)).toBe(false);
    expect(passesScopeFilter(ctx, { createdBy: "alice" })).toBe(false);
  });
});

describe('the legacy "*" entry: deprecated second master signal, kept', () => {
  it('a non-master scope with "*" in its list is still master (no grant withheld)', () => {
    for (const scope of ["tenant", "team-member", undefined]) {
      const ctx: OAuthCtx = {
        scope,
        fromAllowList: ["*"],
        namespaceReadPrefixes: [],
        namespaceWritePrefixes: [],
      };
      expect(isMasterScope(ctx), String(scope)).toBe(true);
      expect(passesScopeFilter(ctx, { createdBy: "stranger", namespace: "anywhere" })).toBe(true);
      expect(() => assertNamespaceWrite(ctx, "anything/at/all")).not.toThrow();
    }
  });

  it('a non-master scope without "*" is not master (none widened)', () => {
    const ctx: OAuthCtx = {
      scope: "team-member",
      fromAllowList: ["alice", "**", " *"],
      namespaceReadPrefixes: [],
      namespaceWritePrefixes: [],
    };
    expect(isMasterScope(ctx)).toBe(false);
  });

  it("a list that is not an array is never read as names (a string is not a roster)", () => {
    const star = noNames({ fromAllowList: "*" as unknown as string[] });
    expect(isMasterScope(star)).toBe(false);
    const alice = noNames({ fromAllowList: "alice" as unknown as string[] });
    expect(passesScopeFilter(alice, { createdBy: "ali", namespace: "elsewhere" })).toBe(false);
    expect(passesScopeFilter(alice, { createdBy: "x", pilot: "lic" } as never, ["pilot"])).toBe(false);
  });
});

describe("mapping row without allowedOrchestrators", () => {
  const row = (over: Record<string, unknown> = {}) => {
    const base: Record<string, unknown> = {
      id: "org_a",
      label: "acme",
      active: true,
      scopes: ["read"],
      orgKind: "client",
      ...over,
    };
    for (const [k, v] of Object.entries(base)) if (v === undefined) delete base[k];
    return base;
  };
  const byId = (r: Record<string, unknown>) => ({ orgById: (id: string) => (id === "org_a" ? (r as never) : null) });

  it("the schema parses a row without the name roster", () => {
    expect(orgMappingRowSchema.safeParse(row()).success).toBe(true);
  });

  it("resolveOrgFromClaim resolves it, and the org carries no name roster key", async () => {
    const r = await resolveOrgFromClaim({ org_id: "org_a" }, byId(row()));
    expect(r).toEqual({
      ok: true,
      org: { id: "org_a", label: "acme", scopes: ["read"], orgKind: "client" },
    });
    if (!r.ok) throw new Error("expected ok");
    expect("allowedOrchestrators" in r.org).toBe(false);
    expect("allowedAgentIds" in r.org).toBe(false);
  });

  it("the ID roster is exposed when the row has it", async () => {
    const r = await resolveOrgFromClaim({ org_id: "org_a" }, byId(row({ allowedAgentIds: ["agent_1", "agent_2"] })));
    if (!r.ok) throw new Error("expected ok");
    expect(r.org.allowedAgentIds).toEqual(["agent_1", "agent_2"]);
    expect("allowedOrchestrators" in r.org).toBe(false);
  });

  it("an empty ID roster is exposed as empty, never dropped", async () => {
    const r = await resolveOrgFromClaim({ org_id: "org_a" }, byId(row({ allowedAgentIds: [] })));
    if (!r.ok) throw new Error("expected ok");
    expect(r.org.allowedAgentIds).toEqual([]);
  });

  it("a row with both rosters returns both, the name roster unchanged", async () => {
    const r = await resolveOrgFromClaim(
      { org_id: "org_a" },
      byId(row({ allowedOrchestrators: ["alpha"], allowedAgentIds: ["agent_1"] })),
    );
    expect(r).toEqual({
      ok: true,
      org: {
        id: "org_a",
        label: "acme",
        allowedOrchestrators: ["alpha"],
        allowedAgentIds: ["agent_1"],
        scopes: ["read"],
        orgKind: "client",
      },
    });
  });

  it("a malformed ID roster refuses the row (fail closed)", async () => {
    for (const bad of ["agent_1", [""], [1], null]) {
      const r = await resolveOrgFromClaim({ org_id: "org_a" }, byId(row({ allowedAgentIds: bad })));
      expect(r.ok, JSON.stringify(bad)).toBe(false);
      if (r.ok) continue;
      expect(r.refusal.reason).toBe("org-mapping-record-invalid");
    }
  });

  it("a malformed name roster, when present, still refuses the row", async () => {
    const r = await resolveOrgFromClaim({ org_id: "org_a" }, byId(row({ allowedOrchestrators: "alpha" })));
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.reason).toBe("org-mapping-record-invalid");
  });
});
