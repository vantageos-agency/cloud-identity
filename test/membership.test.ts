import { describe, it, expect, vi } from "vitest";
import { resolveMembership, isRowInTenant } from "../src/index.js";

describe("resolveMembership — injected lookup, every failure is a refusal", () => {
  it("serves an active membership and passes subject+org to the lookup", async () => {
    const lookup = vi.fn(async () => ({ active: true, role: "editor" }));
    const r = await resolveMembership({ subject: "user_1", orgId: "org_a", lookup });
    expect(r).toEqual({
      ok: true,
      membership: { subject: "user_1", orgId: "org_a", role: "editor" },
    });
    expect(lookup).toHaveBeenCalledWith("user_1", "org_a");
  });

  it("an active membership without a role resolves with role null", async () => {
    const r = await resolveMembership({
      subject: "user_1",
      orgId: "org_a",
      lookup: async () => ({ active: true }),
    });
    expect(r.ok && r.membership.role).toBe(null);
  });

  it("refuses when the lookup throws or rejects (never a grant)", async () => {
    for (const lookup of [
      () => {
        throw new Error("db down");
      },
      async () => {
        throw new Error("db down");
      },
    ]) {
      const r = await resolveMembership({ subject: "u", orgId: "o", lookup });
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.refusal.code).toBe("RBAC_DENIED");
        expect(r.refusal.reason).toBe("membership-lookup-failed");
        // the underlying error text is not surfaced to the caller
        expect(JSON.stringify(r.refusal)).not.toContain("db down");
      }
    }
  });

  it("refuses a miss (null and undefined)", async () => {
    for (const miss of [null, undefined]) {
      const r = await resolveMembership({ subject: "u", orgId: "o", lookup: async () => miss });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("membership-not-found");
    }
  });

  it("refuses an inactive membership", async () => {
    const r = await resolveMembership({
      subject: "u",
      orgId: "o",
      lookup: async () => ({ active: false, role: "admin" }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal.reason).toBe("membership-inactive");
  });

  it("refuses a record that is not shaped like a membership (truthy but not active:true)", async () => {
    for (const rec of [{}, { active: "yes" }, { active: 1 }, "active", 5]) {
      const r = await resolveMembership({ subject: "u", orgId: "o", lookup: async () => rec as never });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("membership-record-invalid");
    }
  });

  it("refuses a record that names a different organisation (loose lookup)", async () => {
    const r = await resolveMembership({
      subject: "u",
      orgId: "org_a",
      lookup: async () => ({ active: true, orgId: "org_b" }),
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal.reason).toBe("other-organisation");
  });

  it("refuses empty subject or org WITHOUT calling the lookup", async () => {
    const lookup = vi.fn(async () => ({ active: true }));
    for (const [subject, orgId] of [["", "o"], ["u", ""], [undefined, "o"], ["u", null]]) {
      const r = await resolveMembership({ subject: subject as never, orgId: orgId as never, lookup });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("membership-invalid-input");
    }
    expect(lookup).not.toHaveBeenCalled();
  });

  it("throws a TypeError when lookup is not a function (consumer bug, not a caller refusal)", async () => {
    await expect(
      resolveMembership({ subject: "u", orgId: "o", lookup: undefined as never }),
    ).rejects.toThrow(TypeError);
  });
});

describe("isRowInTenant — strict equality, unstamped refused", () => {
  it("true for equal ids", () => {
    expect(isRowInTenant({ rowOrgId: "org_a", callerOrgId: "org_a" })).toBe(true);
  });
  it("false for another org", () => {
    expect(isRowInTenant({ rowOrgId: "org_a", callerOrgId: "org_b" })).toBe(false);
  });
  it("false for an unstamped row, even against an empty/absent caller org", () => {
    for (const rowOrgId of [undefined, null, ""]) {
      expect(isRowInTenant({ rowOrgId, callerOrgId: "org_a" })).toBe(false);
      expect(isRowInTenant({ rowOrgId, callerOrgId: rowOrgId })).toBe(false);
    }
  });
  it("false when the caller has no org", () => {
    for (const callerOrgId of [undefined, null, ""]) {
      expect(isRowInTenant({ rowOrgId: "org_a", callerOrgId })).toBe(false);
    }
  });
  it("is exact: no case folding, no trimming, no prefix", () => {
    expect(isRowInTenant({ rowOrgId: "Org_A", callerOrgId: "org_a" })).toBe(false);
    expect(isRowInTenant({ rowOrgId: "org_a ", callerOrgId: "org_a" })).toBe(false);
    expect(isRowInTenant({ rowOrgId: "org_ab", callerOrgId: "org_a" })).toBe(false);
  });
});
