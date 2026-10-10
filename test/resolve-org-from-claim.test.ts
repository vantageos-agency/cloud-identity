import { describe, expect, it } from "vitest";
import { resolveOrgFromClaim } from "../src/index.js";

/**
 * A verified credential's org_id claim -> the org's stored mapping row (roster
 * and scopes). The ID selects the row. A label (slug) claim never selects an
 * org unless the caller opts into the transitional fallback, and even then it
 * never overrides an ID the mapping already holds.
 */

const mapping = (over: Record<string, unknown> = {}) => ({
  id: "org_a",
  label: "acme",
  active: true,
  allowedOrchestrators: ["alpha", "beta"],
  scopes: ["read", "write"],
  orgKind: "client",
  ...over,
});

const byId = (rows: Record<string, unknown>) => ({
  orgById: (id: string) => rows[id] as never,
});

const FALLBACK = { labelFallback: true } as const;

function refusedWith(r: Awaited<ReturnType<typeof resolveOrgFromClaim>>) {
  expect(r.ok).toBe(false);
  if (r.ok) throw new Error("expected a refusal");
  return r.refusal;
}

describe("resolveOrgFromClaim: by ID", () => {
  it("resolves the mapping row selected by the org_id claim", async () => {
    const r = await resolveOrgFromClaim({ org_id: "org_a" }, byId({ org_a: mapping() }));
    expect(r).toEqual({
      ok: true,
      org: {
        id: "org_a",
        label: "acme",
        allowedOrchestrators: ["alpha", "beta"],
        scopes: ["read", "write"],
        orgKind: "client",
        source: "id",
      },
    });
  });

  it("reads the ID from org_id, organizationId or orgId, only when it is shaped like a Clerk org ID", async () => {
    const lookups = byId({ org_a: mapping() });
    for (const claims of [{ org_id: "org_a" }, { organizationId: "org_a" }, { orgId: "org_a" }]) {
      const r = await resolveOrgFromClaim(claims, lookups);
      expect(r.ok).toBe(true);
    }
    const slugInIdClaim = await resolveOrgFromClaim({ organizationId: "acme" }, lookups);
    expect(refusedWith(slugInIdClaim).reason).toBe("no-verified-organisation");
  });

  it("ignores a stale label: after a rename the ID still selects the org, under its CURRENT label", async () => {
    const r = await resolveOrgFromClaim(
      { org_id: "org_a", org_slug: "old-name" },
      byId({ org_a: mapping({ label: "new-name" }) }),
      FALLBACK,
    );
    expect(r.ok && r.org.label).toBe("new-name");
    expect(r.ok && r.org.source).toBe("id");
  });

  it("refuses when there is no claim at all", async () => {
    for (const claims of [undefined, null, {}, { org_id: "" }, { org_id: 7 }]) {
      const r = await resolveOrgFromClaim(claims as never, byId({ org_a: mapping() }));
      const refusal = refusedWith(r);
      expect(refusal.code).toBe("RBAC_DENIED");
      expect(refusal.reason).toBe("no-verified-organisation");
    }
  });

  it("refuses an ID no mapping holds, and by default does not try the label", async () => {
    let labelCalls = 0;
    const r = await resolveOrgFromClaim(
      { org_id: "org_zzz", org_slug: "acme" },
      {
        orgById: () => null,
        orgByLabel: () => {
          labelCalls += 1;
          return mapping();
        },
      },
    );
    expect(refusedWith(r).reason).toBe("org-mapping-not-found");
    expect(labelCalls).toBe(0);
  });

  it("refuses an inactive org", async () => {
    const r = await resolveOrgFromClaim({ org_id: "org_a" }, byId({ org_a: mapping({ active: false }) }));
    expect(refusedWith(r).reason).toBe("organisation-not-active");
  });

  it("refuses a row that does not repeat the ID asked for, or is malformed", async () => {
    const wrongId = await resolveOrgFromClaim({ org_id: "org_a" }, byId({ org_a: mapping({ id: "org_b" }) }));
    expect(refusedWith(wrongId).reason).toBe("org-mapping-record-invalid");
    const noRoster = await resolveOrgFromClaim(
      { org_id: "org_a" },
      byId({ org_a: { id: "org_a", label: "acme", active: true } }),
    );
    expect(refusedWith(noRoster).reason).toBe("org-mapping-record-invalid");
  });

  it("refuses a missing or throwing adapter, without surfacing its error text", async () => {
    const missing = await resolveOrgFromClaim({ org_id: "org_a" }, {});
    expect(refusedWith(missing).reason).toBe("org-mapping-lookup-failed");
    const throwing = await resolveOrgFromClaim(
      { org_id: "org_a" },
      {
        orgById: () => {
          throw new Error("secret connection string");
        },
      },
    );
    const refusal = refusedWith(throwing);
    expect(refusal.reason).toBe("org-mapping-lookup-failed");
    expect(JSON.stringify(refusal)).not.toContain("secret");
  });

  it("normalises the org kind: only exactly operator or client survive", async () => {
    const kind = async (orgKind: unknown) => {
      const r = await resolveOrgFromClaim({ org_id: "org_a" }, byId({ org_a: mapping({ orgKind }) }));
      return r.ok ? r.org.orgKind : "refused";
    };
    expect(await kind("operator")).toBe("operator");
    expect(await kind("client")).toBe("client");
    expect(await kind("Operator")).toBeNull();
    expect(await kind(undefined)).toBeNull();
  });

  it("names the door on every refusal", async () => {
    const r = await resolveOrgFromClaim({}, {}, { door: "tasks:list" });
    expect(refusedWith(r).door).toBe("tasks:list");
  });
});

describe("resolveOrgFromClaim: transitional label fallback", () => {
  it("does not resolve by label alone unless opted in", async () => {
    const r = await resolveOrgFromClaim({ org_slug: "acme" }, { orgByLabel: () => mapping() });
    expect(refusedWith(r).reason).toBe("no-verified-organisation");
  });

  it("resolves by label when the credential carries no ID and the fallback is on", async () => {
    const r = await resolveOrgFromClaim({ org_slug: "acme" }, { orgByLabel: () => mapping() }, FALLBACK);
    expect(r.ok && r.org.source).toBe("label");
    expect(r.ok && r.org.id).toBe("org_a");
  });

  it("reads the label from organizationSlug, org_slug, then the legacy id-spelled claims", async () => {
    const seen: string[] = [];
    const lookups = {
      orgByLabel: (label: string) => {
        seen.push(label);
        return mapping();
      },
    };
    await resolveOrgFromClaim({ organizationSlug: "a", org_slug: "b" }, lookups, FALLBACK);
    await resolveOrgFromClaim({ org_slug: "b", organizationId: "c" }, lookups, FALLBACK);
    await resolveOrgFromClaim({ organizationId: "c", org_id: "d" }, lookups, FALLBACK);
    expect(seen).toEqual(["a", "b", "c"]);
  });

  it("serves a label mapping that has no ID yet, even when the credential carries an unknown ID", async () => {
    const r = await resolveOrgFromClaim(
      { org_id: "org_new", org_slug: "acme" },
      { orgById: () => null, orgByLabel: () => mapping({ id: undefined }) },
      FALLBACK,
    );
    expect(r.ok && r.org.source).toBe("label");
    expect(r.ok && r.org.id).toBeUndefined();
  });

  it("refuses when the credential's ID contradicts the ID the labelled mapping holds", async () => {
    const r = await resolveOrgFromClaim(
      { org_id: "org_new", org_slug: "acme" },
      { orgById: () => null, orgByLabel: () => mapping({ id: "org_a" }) },
      FALLBACK,
    );
    expect(refusedWith(r).reason).toBe("org-id-contradicts-label");
  });

  it("refuses an unmapped label and an inactive labelled org", async () => {
    const miss = await resolveOrgFromClaim({ org_slug: "acme" }, { orgByLabel: () => null }, FALLBACK);
    expect(refusedWith(miss).reason).toBe("org-mapping-not-found");
    const off = await resolveOrgFromClaim(
      { org_slug: "acme" },
      { orgByLabel: () => mapping({ active: false }) },
      FALLBACK,
    );
    expect(refusedWith(off).reason).toBe("organisation-not-active");
  });

  it("refuses when the label adapter is missing or the label row is under another label", async () => {
    const missing = await resolveOrgFromClaim({ org_slug: "acme" }, {}, FALLBACK);
    expect(refusedWith(missing).reason).toBe("org-mapping-lookup-failed");
    const other = await resolveOrgFromClaim(
      { org_slug: "acme" },
      { orgByLabel: () => mapping({ label: "other" }) },
      FALLBACK,
    );
    expect(refusedWith(other).reason).toBe("org-mapping-record-invalid");
  });
});
