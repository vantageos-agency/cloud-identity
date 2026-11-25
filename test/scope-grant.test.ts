import { describe, expect, it } from "vitest";
import {
  assertScopeGrant,
  filterByScopeGrant,
  hasScopeGrant,
  IdentityRefusalError,
  resolveScopeGrant,
  type ScopePolicy,
} from "../src/index.js";

/**
 * A decision on a SET of token scopes (0.37.0): the token's scopes and a
 * required scope -> allow, or a typed refusal. The scope alphabet is the
 * consumer's data: a ladder (most privileged first, the `resolveMinRole`
 * convention), scopes OFF the ladder, and superscopes named by the caller.
 *
 * The policy below is the CRM's alphabet, used as the named scoped identity of
 * these tests: a token holding `["read"]` is the "crm-reader" token, a token
 * holding `["admin"]` the "crm-admin" token. Neither is a maintenance or
 * bypass identity; `cloud-admin` is only exercised where its own reach is the
 * subject.
 */
const CRM: ScopePolicy = {
  ladder: ["cloud-admin", "admin", "write", "read"],
  offLadder: ["workflow-trigger"],
  superscopes: ["cloud-admin"],
};
const READER = ["read"];
const ADMIN = ["admin"];

describe("resolveScopeGrant: a ladder rank implies the ranks below it", () => {
  it("allows the crm-admin token write and read through the ladder", () => {
    expect(resolveScopeGrant({ scopes: ADMIN, required: "write", policy: CRM })).toEqual({
      ok: true,
      required: "write",
      via: "ladder",
      grantedBy: "admin",
    });
    expect(hasScopeGrant(ADMIN, "read", CRM)).toBe(true);
  });

  it("allows an exact grant and says so", () => {
    expect(resolveScopeGrant({ scopes: READER, required: "read", policy: CRM })).toEqual({
      ok: true,
      required: "read",
      via: "exact",
      grantedBy: "read",
    });
  });

  it("refuses the crm-reader token every scope above read", () => {
    for (const required of ["write", "admin", "cloud-admin", "workflow-trigger"]) {
      const r = resolveScopeGrant({ scopes: READER, required, policy: CRM, door: "crm.tool" });
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.refusal).toMatchObject({
          code: "RBAC_DENIED",
          reason: "scope-not-granted",
          door: "crm.tool",
        });
      }
    }
  });
});

describe("resolveScopeGrant: an off-ladder scope is satisfied only by an exact grant or a named superscope", () => {
  it("refuses the crm-admin token workflow-trigger: no ladder rank implies an off-ladder scope", () => {
    expect(hasScopeGrant(ADMIN, "workflow-trigger", CRM)).toBe(false);
    expect(hasScopeGrant(["admin", "write", "read"], "workflow-trigger", CRM)).toBe(false);
  });

  it("allows an exact workflow-trigger grant, and that grant implies nothing on the ladder", () => {
    expect(hasScopeGrant(["workflow-trigger"], "workflow-trigger", CRM)).toBe(true);
    expect(hasScopeGrant(["workflow-trigger"], "read", CRM)).toBe(false);
  });

  it("the top ladder rank does not imply an off-ladder scope unless the caller names it a superscope", () => {
    const noSuper: ScopePolicy = { ladder: CRM.ladder, offLadder: CRM.offLadder };
    expect(hasScopeGrant(["cloud-admin"], "workflow-trigger", noSuper)).toBe(false);
    expect(resolveScopeGrant({ scopes: ["cloud-admin"], required: "workflow-trigger", policy: CRM })).toEqual({
      ok: true,
      required: "workflow-trigger",
      via: "superscope",
      grantedBy: "cloud-admin",
    });
  });
});

describe("resolveScopeGrant: an absence is never broader than a presentation", () => {
  it("an empty list, an unknown scope and an empty string grant nothing", () => {
    expect(hasScopeGrant([], "read", CRM)).toBe(false);
    expect(hasScopeGrant(["mcp:full"], "read", CRM)).toBe(false);
    expect(hasScopeGrant([""], "read", CRM)).toBe(false);
    expect(hasScopeGrant(["READ", " read"], "read", CRM)).toBe(false);
  });

  it("scopes that are not an array are refused as absent; a space-delimited string is not a list", () => {
    for (const scopes of [undefined, null, "read write", { 0: "read", length: 1 }, 7]) {
      const r = resolveScopeGrant({ scopes, required: "read", policy: CRM });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("scopes-absent");
    }
  });

  it("non-string entries are skipped, never coerced", () => {
    expect(hasScopeGrant([1, null, { toString: () => "read" }] as unknown[], "read", CRM)).toBe(false);
    expect(hasScopeGrant([1, "read"] as unknown[], "read", CRM)).toBe(true);
  });

  it("a required scope outside the alphabet is refused as unknown, never treated as satisfied", () => {
    for (const required of ["mcp:full", "", "constructor", "__proto__"]) {
      const r = resolveScopeGrant({ scopes: ["cloud-admin"], required, policy: CRM });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("scope-required-unknown");
    }
  });

  it("an invalid policy refuses everything, including the superscope", () => {
    const bad: ScopePolicy[] = [
      { ladder: [] },
      { ladder: ["read", "read"] },
      { ladder: ["read"], offLadder: ["read"] },
      { ladder: ["read"], superscopes: ["root"] },
      { ladder: ["read", ""] },
      null as unknown as ScopePolicy,
    ];
    for (const policy of bad) {
      const r = resolveScopeGrant({ scopes: ["read", "root"], required: "read", policy });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("scope-policy-invalid");
    }
  });

  it("a policy with only off-ladder scopes is valid: each is exact-match only", () => {
    const flat: ScopePolicy = { ladder: [], offLadder: ["a", "b"] };
    expect(hasScopeGrant(["a"], "a", flat)).toBe(true);
    expect(hasScopeGrant(["a"], "b", flat)).toBe(false);
  });
});

describe("assertScopeGrant", () => {
  it("returns the required scope when granted", () => {
    expect(assertScopeGrant({ scopes: ADMIN, required: "write", policy: CRM })).toBe("write");
  });

  it("throws IdentityRefusalError carrying the typed refusal when refused", () => {
    let caught: unknown;
    try {
      assertScopeGrant({ scopes: READER, required: "admin", policy: CRM, door: "crm.purge" });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(IdentityRefusalError);
    expect((caught as IdentityRefusalError).refusal).toMatchObject({
      code: "RBAC_DENIED",
      reason: "scope-not-granted",
      door: "crm.purge",
    });
  });
});

describe("filterByScopeGrant", () => {
  const tools = [
    { name: "list_deals", requiredScope: "read" },
    { name: "create_deal", requiredScope: "write" },
    { name: "purge", requiredScope: "admin" },
    { name: "trigger_workflow", requiredScope: "workflow-trigger" },
    { name: "typo", requiredScope: "raed" },
  ];
  const req = (t: { requiredScope: string }) => t.requiredScope;

  it("keeps exactly the items whose required scope is granted, in order", () => {
    expect(filterByScopeGrant(tools, ADMIN, CRM, req).map((t) => t.name)).toEqual([
      "list_deals",
      "create_deal",
      "purge",
    ]);
    expect(filterByScopeGrant(tools, READER, CRM, req).map((t) => t.name)).toEqual(["list_deals"]);
  });

  it("equals the per-item decision, and an item with an unknown required scope is never listed", () => {
    for (const scopes of [READER, ADMIN, ["cloud-admin"], ["workflow-trigger"], []]) {
      const listed = filterByScopeGrant(tools, scopes, CRM, req);
      expect(listed).toEqual(tools.filter((t) => hasScopeGrant(scopes, t.requiredScope, CRM)));
      expect(listed.some((t) => t.name === "typo")).toBe(false);
    }
  });

  it("absent scopes list nothing", () => {
    expect(filterByScopeGrant(tools, undefined, CRM, req)).toEqual([]);
  });
});
