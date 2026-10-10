import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  isFleetStamp,
  resolveOrgFromClaim,
  sameOrg,
  sameTenantStamp,
} from "../src/index.js";

/**
 * An organisation is never resolved from its label on a request path. There is
 * no option that turns label matching on: a label-only input refuses, even when
 * a caller passes the retired `labelFallback` flag anyway (cast past the types).
 */
const RETIRED = { labelFallback: true } as never;
const row = { id: "org_a", label: "acme", active: true, allowedOrchestrators: [], scopes: [] };

describe("no label resolution: behaviour", () => {
  it("sameOrg: two label-only references are not the same org, flag or not", () => {
    expect(sameOrg({ label: "acme" }, { label: "acme" })).toBe(false);
    expect(sameOrg({ label: "acme" }, { label: "acme" }, RETIRED)).toBe(false);
    expect(sameOrg({ id: "org_a", label: "acme" }, { label: "acme" }, RETIRED)).toBe(false);
  });

  it("isFleetStamp / sameTenantStamp: a label-only stamp never matches the operator or another stamp", () => {
    const operator = { id: "org_op", label: "operator" };
    expect(isFleetStamp({ label: "operator" }, operator, RETIRED)).toBe(false);
    expect(sameTenantStamp({ label: "acme" }, { label: "acme" }, operator, RETIRED)).toBe(false);
  });

  it("resolveOrgFromClaim: a label-only credential is refused and the label adapter is never called", async () => {
    let labelCalls = 0;
    const lookups = {
      orgById: () => row,
      orgByLabel: () => {
        labelCalls += 1;
        return row;
      },
    };
    const r = await resolveOrgFromClaim({ org_slug: "acme" }, lookups, RETIRED);
    expect(r.ok).toBe(false);
    expect(!r.ok && r.refusal.reason).toBe("no-verified-organisation");
    const unknownId = await resolveOrgFromClaim(
      { org_id: "org_unknown", org_slug: "acme" },
      { ...lookups, orgById: () => null },
      RETIRED,
    );
    expect(!unknownId.ok && unknownId.refusal.reason).toBe("org-mapping-not-found");
    expect(labelCalls).toBe(0);
  });
});

describe("no label resolution: surface", () => {
  const src = readFileSync(new URL("../src/org-by-id.ts", import.meta.url), "utf8");

  it("the option does not exist in the source or on any exported type", () => {
    expect(src).not.toMatch(/labelFallback/);
    expect(src).not.toMatch(/OrgKeyOptions/);
  });

  it("the package README and index do not document or export it", () => {
    for (const f of ["../README.md", "../src/index.ts"]) {
      const text = readFileSync(new URL(f, import.meta.url), "utf8");
      expect(text).not.toMatch(/`labelFallback|labelFallback\?|labelFallback:/);
    }
  });

  it("a resolved org carries no label-source marker", async () => {
    const r = await resolveOrgFromClaim({ org_id: "org_a" }, { orgById: () => row });
    expect(r.ok && "source" in r.org).toBe(false);
  });
});
