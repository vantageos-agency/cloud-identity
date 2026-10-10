import { describe, expect, it } from "vitest";
import { sameTenantStamp } from "../src/index.js";

/**
 * Do two stamps name the same tenant: the same organisation, or both the
 * fleet's (unstamped or the operator's)? Two IDs that differ are two tenants.
 */

const OPERATOR = { id: "org_op", label: "operator" } as const;
describe("sameTenantStamp", () => {
  it("is true for two unstamped rows (the fleet), and for unstamped against operator-stamped", () => {
    expect(sameTenantStamp({}, {}, OPERATOR)).toBe(true);
    expect(sameTenantStamp({}, {}, undefined)).toBe(true);
    expect(sameTenantStamp({}, { id: "org_op" }, OPERATOR)).toBe(true);
    expect(sameTenantStamp({ id: "org_op" }, {}, OPERATOR)).toBe(true);
  });

  it("is false for unstamped against an operator-stamped row when there is no single operator", () => {
    expect(sameTenantStamp({}, { id: "org_op" }, undefined)).toBe(false);
  });

  it("is false for the fleet against a client organisation", () => {
    expect(sameTenantStamp({}, { id: "org_c" }, OPERATOR)).toBe(false);
    expect(sameTenantStamp({ id: "org_c" }, { id: "org_op" }, OPERATOR)).toBe(false);
  });

  it("is true for the same client organisation, by ID, across a rename", () => {
    expect(
      sameTenantStamp({ id: "org_c", label: "old" }, { id: "org_c", label: "new" }, OPERATOR),
    ).toBe(true);
  });

  it("is false for two client IDs under one label", () => {
    expect(
      sameTenantStamp(
        { id: "org_c1", label: "acme" },
        { id: "org_c2", label: "acme" },
        OPERATOR
      ),
    ).toBe(false);
  });

  it("never compares the labels of two client stamps", () => {
    expect(sameTenantStamp({ label: "acme" }, { label: "acme" }, OPERATOR)).toBe(false);
  });

  it("is false for an empty-string stamp against anything", () => {
    expect(sameTenantStamp({ id: "" }, {}, OPERATOR)).toBe(false);
    expect(sameTenantStamp({ id: "" }, { id: "" }, OPERATOR)).toBe(false);
  });
});
