import { describe, expect, it } from "vitest";
import * as root from "../src/index.js";
import * as orgById from "../src/org-by-id.js";

/**
 * Pins the exported function list of `./org-by-id`. The label-to-ID derivation
 * is exported ONLY under a name that says it belongs to the one-off backfill:
 * a request path must never resolve an organisation from a human label.
 */
const EXPECTED_FUNCTIONS = [
  "findOperatorOrg",
  "isFleetStamp",
  "resolveOrgFromClaim",
  "resolveOrgIdForLabelBackfillOnly",
  "sameOrg",
  "sameTenantStamp",
];

function functionsOf(mod: Record<string, unknown>): string[] {
  return Object.keys(mod)
    .filter((k) => typeof mod[k] === "function")
    .sort();
}

describe("org-by-id export pin", () => {
  it("./org-by-id exports exactly the expected functions", () => {
    expect(functionsOf(orgById)).toEqual(EXPECTED_FUNCTIONS);
  });

  it("the package root re-exports every one of them", () => {
    const rootFns = functionsOf(root);
    for (const fn of EXPECTED_FUNCTIONS) expect(rootFns).toContain(fn);
  });

  it("no label-resolving export exists under a name that does not say backfill-only", () => {
    for (const mod of [root, orgById] as Array<Record<string, unknown>>) {
      expect(mod).not.toHaveProperty("resolveOrgIdForLabel");
      const labelResolvers = Object.keys(mod).filter((k) => /ForLabel/.test(k));
      expect(labelResolvers).toEqual(["resolveOrgIdForLabelBackfillOnly"]);
    }
  });
});
