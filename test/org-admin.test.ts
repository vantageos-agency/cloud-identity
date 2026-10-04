import { describe, it, expect } from "vitest";
import { requireOrgAdmin, IdentityRefusalError } from "../src/index.js";

const ADMINS = ["admin", "owner"] as const;

function refusalOf(fn: () => void) {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(IdentityRefusalError);
    return (e as IdentityRefusalError).refusal;
  }
  throw new Error("expected a refusal");
}

describe("requireOrgAdmin — proof bound to the caller's VERIFIED org", () => {
  it("serves an admin acting on its own verified org", () => {
    expect(() =>
      requireOrgAdmin({ verifiedOrgId: "org_a", targetOrgId: "org_a", role: "admin", adminRoles: ADMINS }),
    ).not.toThrow();
    expect(() =>
      requireOrgAdmin({ verifiedOrgId: "org_a", targetOrgId: "org_a", role: "owner", adminRoles: ADMINS }),
    ).not.toThrow();
  });

  it("refuses an admin of ANOTHER org acting on the target (cross-org)", () => {
    const r = refusalOf(() =>
      requireOrgAdmin({ verifiedOrgId: "org_a", targetOrgId: "org_b", role: "admin", adminRoles: ADMINS }),
    );
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe("other-organisation");
  });

  it("refuses a non-admin role in its own org", () => {
    const r = refusalOf(() =>
      requireOrgAdmin({ verifiedOrgId: "org_a", targetOrgId: "org_a", role: "viewer", adminRoles: ADMINS }),
    );
    expect(r.reason).toBe("role-not-admin");
  });

  it("refuses no role / empty adminRoles (fail closed)", () => {
    for (const role of [null, undefined, ""]) {
      expect(
        refusalOf(() =>
          requireOrgAdmin({ verifiedOrgId: "o", targetOrgId: "o", role, adminRoles: ADMINS }),
        ).reason,
      ).toBe("role-not-admin");
    }
    expect(
      refusalOf(() =>
        requireOrgAdmin({ verifiedOrgId: "o", targetOrgId: "o", role: "admin", adminRoles: [] }),
      ).reason,
    ).toBe("role-not-admin");
  });

  it("refuses when there is no verified org, even if target is also empty", () => {
    for (const verifiedOrgId of [undefined, null, ""]) {
      const r = refusalOf(() =>
        requireOrgAdmin({ verifiedOrgId, targetOrgId: verifiedOrgId as never, role: "admin", adminRoles: ADMINS }),
      );
      expect(r.reason).toBe("no-verified-organisation");
    }
  });

  it("refuses an empty/absent target", () => {
    const r = refusalOf(() =>
      requireOrgAdmin({ verifiedOrgId: "org_a", targetOrgId: "", role: "admin", adminRoles: ADMINS }),
    );
    expect(r.reason).toBe("other-organisation");
  });

  it("names the supplied door", () => {
    const r = refusalOf(() =>
      requireOrgAdmin({ verifiedOrgId: "a", targetOrgId: "b", role: "admin", adminRoles: ADMINS, door: "orgs:provision" }),
    );
    expect(r.door).toBe("orgs:provision");
  });
});
