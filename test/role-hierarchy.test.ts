import { describe, it, expect } from "vitest";
import {
  assertMinRole,
  resolveMinRole,
  IdentityRefusalError,
} from "../src/index.js";

// The order is the CALLER's data (most privileged first). The package ships none.
const ORDER = ["admin", "editor", "viewer"] as const;

describe("resolveMinRole / assertMinRole — role hierarchy with the order as data", () => {
  it("serves a role at the minimum", () => {
    const r = resolveMinRole({ role: "editor", minimum: "editor", order: ORDER });
    expect(r).toEqual({ ok: true, role: "editor" });
  });

  it("serves a role above the minimum", () => {
    expect(resolveMinRole({ role: "admin", minimum: "viewer", order: ORDER }).ok).toBe(true);
  });

  it("refuses a role below the minimum", () => {
    const r = resolveMinRole({ role: "viewer", minimum: "editor", order: ORDER });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal.code).toBe("RBAC_DENIED");
      expect(r.refusal.reason).toBe("role-below-minimum");
    }
  });

  it("refuses an unknown role, even one that looks high", () => {
    const r = resolveMinRole({ role: "superadmin", minimum: "viewer", order: ORDER });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal.reason).toBe("unknown-role");
  });

  it("refuses an absent role (null, undefined, empty)", () => {
    for (const role of [null, undefined, ""]) {
      const r = resolveMinRole({ role, minimum: "viewer", order: ORDER });
      expect(r.ok).toBe(false);
    }
  });

  it("refuses a minimum that is not in the order (configuration error never grants)", () => {
    const r = resolveMinRole({ role: "admin", minimum: "owner", order: ORDER });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal.reason).toBe("unknown-minimum-role");
  });

  it("refuses an empty or duplicated order", () => {
    for (const order of [[], ["admin", "admin", "viewer"]]) {
      const r = resolveMinRole({ role: "admin", minimum: "admin", order });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("invalid-role-order");
    }
  });

  it("does not trust prototype keys or case-folding: match is exact", () => {
    expect(resolveMinRole({ role: "Admin", minimum: "viewer", order: ORDER }).ok).toBe(false);
    expect(resolveMinRole({ role: "constructor", minimum: "viewer", order: ORDER }).ok).toBe(false);
  });

  it("assertMinRole returns the role when served", () => {
    expect(assertMinRole({ role: "admin", minimum: "editor", order: ORDER })).toBe("admin");
  });

  it("assertMinRole throws a typed IdentityRefusalError carrying the refusal and door", () => {
    try {
      assertMinRole({ role: "viewer", minimum: "admin", order: ORDER, door: "orgs:rename" });
      expect.unreachable();
    } catch (e) {
      expect(e).toBeInstanceOf(IdentityRefusalError);
      const err = e as IdentityRefusalError;
      expect(err.refusal.code).toBe("RBAC_DENIED");
      expect(err.refusal.reason).toBe("role-below-minimum");
      expect(err.refusal.door).toBe("orgs:rename");
      expect(err.message).toContain("RBAC_DENIED");
    }
  });
});
