import { describe, expect, it } from "vitest";
import { IdentityRefusalError, requireSubjectFromIdentity, requireTenantFromIdentity } from "../src/index.js";

const DOOR = "engine:queue.enqueue";

function refused(identity: Record<string, unknown> | null | undefined) {
  try {
    requireTenantFromIdentity(identity, { door: DOOR });
  } catch (error) {
    expect(error).toBeInstanceOf(IdentityRefusalError);
    return (error as IdentityRefusalError).refusal;
  }
  throw new Error("expected a refusal");
}

describe("requireTenantFromIdentity: a verified identity's organisation ID claim -> tenant ID", () => {
  it("returns the organisation ID carried by org_id", () => {
    expect(requireTenantFromIdentity({ subject: "user_1", org_id: "org_ABC123" }, { door: DOOR })).toBe(
      "org_ABC123",
    );
  });

  it("reads the same claim names as the package's other claim readers", () => {
    expect(requireTenantFromIdentity({ organizationId: "org_X1" }, { door: DOOR })).toBe("org_X1");
    expect(requireTenantFromIdentity({ orgId: "org_Y2" }, { door: DOOR })).toBe("org_Y2");
  });

  it("refuses when there is no identity at all", () => {
    expect(refused(null)).toMatchObject({ code: "RBAC_DENIED", reason: "no-verified-organisation", door: DOOR });
    expect(refused(undefined)).toMatchObject({ code: "RBAC_DENIED", reason: "no-verified-organisation" });
  });

  it("refuses an identity with no organisation claim", () => {
    expect(refused({ subject: "user_1" })).toMatchObject({ code: "RBAC_DENIED", reason: "no-verified-organisation" });
  });

  it("refuses a claim that is not a Clerk organisation ID (a slug, a name, an empty string, a non-string)", () => {
    for (const org_id of ["acme-hr", "Acme HR", "", "org_", 42, { id: "org_A" }]) {
      expect(refused({ org_id })).toMatchObject({ code: "RBAC_DENIED", reason: "no-verified-organisation" });
    }
  });

  it("never names the claim value in the refusal it returns to the caller", () => {
    const refusal = refused({ org_id: "acme-hr-secret-slug" });
    expect(refusal.detail).not.toContain("acme-hr-secret-slug");
  });
});

describe("requireSubjectFromIdentity: a verified identity's subject", () => {
  it("returns the subject", () => {
    expect(requireSubjectFromIdentity({ subject: "user_2abc", org_id: "org_A1" }, { door: DOOR })).toBe("user_2abc");
  });

  for (const [label, identity] of [
    ["no identity", null],
    ["undefined identity", undefined],
    ["no subject", { org_id: "org_A1" }],
    ["empty subject", { subject: "" }],
    ["non-string subject", { subject: 42 }],
  ] as const) {
    it(`refuses ${label}`, () => {
      try {
        requireSubjectFromIdentity(identity as Record<string, unknown> | null | undefined, { door: DOOR });
      } catch (error) {
        expect(error).toBeInstanceOf(IdentityRefusalError);
        expect((error as IdentityRefusalError).refusal).toMatchObject({
          code: "RBAC_DENIED",
          reason: "no-verified-subject",
          door: DOOR,
        });
        return;
      }
      throw new Error("expected a refusal");
    });
  }
});
