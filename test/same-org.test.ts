import { describe, expect, it } from "vitest";
import { sameOrg } from "../src/index.js";

/**
 * Do two references name the same organisation? Decided by the permanent org
 * ID. A label (a renamable slug) is never an identity: it is compared only
 * when the caller opts into the transitional fallback AND either side has no ID.
 */

const FALLBACK = { labelFallback: true } as const;

describe("sameOrg", () => {
  it("is true for the same ID, whatever the labels say (a renamed org)", () => {
    expect(sameOrg({ id: "org_a", label: "old" }, { id: "org_a", label: "new" })).toBe(true);
    expect(sameOrg({ id: "org_a" }, { id: "org_a", label: "new" }, FALLBACK)).toBe(true);
  });

  it("is false for two different IDs even when the labels are equal, fallback or not", () => {
    const a = { id: "org_a", label: "acme" };
    const b = { id: "org_b", label: "acme" };
    expect(sameOrg(a, b)).toBe(false);
    expect(sameOrg(a, b, FALLBACK)).toBe(false);
  });

  it("never compares labels by default", () => {
    expect(sameOrg({ label: "acme" }, { label: "acme" })).toBe(false);
    expect(sameOrg({ id: "org_a", label: "acme" }, { label: "acme" })).toBe(false);
  });

  it("compares labels only under the fallback, and only while either side has no ID", () => {
    expect(sameOrg({ label: "acme" }, { label: "acme" }, FALLBACK)).toBe(true);
    expect(sameOrg({ id: "org_a", label: "acme" }, { label: "acme" }, FALLBACK)).toBe(true);
    expect(sameOrg({ label: "acme" }, { id: "org_a", label: "acme" }, FALLBACK)).toBe(true);
    expect(sameOrg({ label: "acme" }, { label: "other" }, FALLBACK)).toBe(false);
  });

  it("is byte for byte: no case folding, no trimming, no wildcard", () => {
    expect(sameOrg({ id: "org_a" }, { id: "ORG_A" })).toBe(false);
    expect(sameOrg({ id: "org_a" }, { id: "org_a " })).toBe(false);
    expect(sameOrg({ id: "*" }, { id: "org_a" })).toBe(false);
    expect(sameOrg({ label: "Acme" }, { label: "acme" }, FALLBACK)).toBe(false);
  });

  it("refuses absence: unstamped is not a match, even against unstamped", () => {
    expect(sameOrg({}, {})).toBe(false);
    expect(sameOrg({}, {}, FALLBACK)).toBe(false);
    expect(sameOrg(null, null, FALLBACK)).toBe(false);
    expect(sameOrg(undefined, { id: "org_a" })).toBe(false);
    expect(sameOrg({ id: "org_a" }, null)).toBe(false);
    expect(sameOrg({ id: null, label: null }, { id: null, label: null }, FALLBACK)).toBe(false);
  });

  it("refuses empty strings as keys", () => {
    expect(sameOrg({ id: "" }, { id: "" })).toBe(false);
    expect(sameOrg({ label: "" }, { label: "" }, FALLBACK)).toBe(false);
  });
});
