import { describe, expect, it } from "vitest";
import { resolveOrgIdForLabelBackfillOnly } from "../src/index.js";

/**
 * Derive the permanent org ID from an org label (a slug), by the consumer's
 * stored mapping. For stamping a new row with the ID next to the label. It is
 * a derivation and not an authorization: it never invents an ID, and every
 * failure is a typed absence that cannot be taken for an ID.
 */

const mapping = (over: Record<string, unknown> = {}) => ({
  id: "org_a",
  label: "acme",
  active: true,
  allowedOrchestrators: ["*"],
  scopes: [],
  ...over,
});

describe("resolveOrgIdForLabelBackfillOnly", () => {
  it("returns the stored ID of the labelled org", async () => {
    const r = await resolveOrgIdForLabelBackfillOnly("acme", { orgByLabel: () => mapping() });
    expect(r).toEqual({ present: true, orgId: "org_a" });
  });

  it("is async-tolerant and passes the label byte for byte", async () => {
    const seen: string[] = [];
    await resolveOrgIdForLabelBackfillOnly("Acme ", {
      orgByLabel: async (label: string) => {
        seen.push(label);
        return null;
      },
    });
    expect(seen).toEqual(["Acme "]);
  });

  it("still answers for an inactive mapping: it is a derivation, not a grant", async () => {
    const r = await resolveOrgIdForLabelBackfillOnly("acme", { orgByLabel: () => mapping({ active: false }) });
    expect(r).toEqual({ present: true, orgId: "org_a" });
  });

  it("answers id-not-filled when the mapping has no ID yet, never inventing one", async () => {
    for (const id of [undefined, null]) {
      const r = await resolveOrgIdForLabelBackfillOnly("acme", { orgByLabel: () => mapping({ id }) });
      expect(r).toEqual({ present: false, absence: { code: "ORG_ID_ABSENT", reason: "id-not-filled" } });
    }
  });

  it("answers not-mapped on a miss", async () => {
    const r = await resolveOrgIdForLabelBackfillOnly("acme", { orgByLabel: () => null });
    expect(r).toEqual({ present: false, absence: { code: "ORG_ID_ABSENT", reason: "not-mapped" } });
  });

  it("answers no-label for an absent, empty or non-string label without calling the store", async () => {
    let calls = 0;
    const lookups = {
      orgByLabel: () => {
        calls += 1;
        return mapping();
      },
    };
    for (const label of [undefined, null, "", 7 as unknown as string]) {
      const r = await resolveOrgIdForLabelBackfillOnly(label, lookups);
      expect(r).toEqual({ present: false, absence: { code: "ORG_ID_ABSENT", reason: "no-label" } });
    }
    expect(calls).toBe(0);
  });

  it("answers lookup-failed for a missing or throwing adapter, without the error text", async () => {
    expect(await resolveOrgIdForLabelBackfillOnly("acme", {})).toEqual({
      present: false,
      absence: { code: "ORG_ID_ABSENT", reason: "lookup-failed" },
    });
    const r = await resolveOrgIdForLabelBackfillOnly("acme", {
      orgByLabel: () => {
        throw new Error("secret connection string");
      },
    });
    expect(r).toEqual({ present: false, absence: { code: "ORG_ID_ABSENT", reason: "lookup-failed" } });
    expect(JSON.stringify(r)).not.toContain("secret");
  });

  it("answers record-invalid for a malformed row or one under another label", async () => {
    for (const row of [{ id: "org_a" }, mapping({ label: "other" }), mapping({ id: "" })]) {
      const r = await resolveOrgIdForLabelBackfillOnly("acme", { orgByLabel: () => row });
      expect(r).toEqual({ present: false, absence: { code: "ORG_ID_ABSENT", reason: "record-invalid" } });
    }
  });
});
