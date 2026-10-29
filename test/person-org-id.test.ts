/**
 * 0.29.0 — `resolvePersonPrincipal` can select the organisation by its
 * permanent ID. A token record may carry `orgId`; the deps may carry an
 * ID-keyed `lookupOrganisationById`.
 *
 * Decision order pinned here:
 *   - record has orgId AND deps have the ID lookup -> the ID path ONLY: a
 *     refusal or a miss on that path never falls back to the slug;
 *   - otherwise the legacy slug path, unchanged;
 *   - orgId and orgSlug that resolve to different organisations -> refused
 *     `other-organisation`.
 */

import { describe, it, expect } from "vitest";
import {
  resolvePersonPrincipal,
  type PersonTokenRecord,
} from "../src/person-principal.js";

const NOW = 1_800_000_000_000;
const DOOR = "tasks:create";

type Org = { id: string; isActive: boolean; slug: string };

const A: Org = { id: "org_A", isActive: true, slug: "org-a" };
const B: Org = { id: "org_B", isActive: true, slug: "org-b" };
const DORMANT: Org = { id: "org_D", isActive: false, slug: "org-dormant" };
const all = [A, B, DORMANT];

function deps(over: Record<string, unknown> = {}) {
  const bySlug: string[] = [];
  const byId: string[] = [];
  return {
    bySlug,
    byId,
    now: NOW,
    lookupOrganisation: async (slug: string) => {
      bySlug.push(slug);
      return all.find((o) => o.slug === slug) ?? null;
    },
    lookupOrganisationById: async (id: string) => {
      byId.push(id);
      return all.find((o) => o.id === id) ?? null;
    },
    organisationId: (o: Org) => o.id,
    ...over,
  };
}

const rec = (over: Record<string, unknown> = {}): PersonTokenRecord =>
  ({
    principal: "person",
    subject: "user_alice",
    orgSlug: "org-a",
    orgRole: "org:editor",
    expiresAt: NOW + 60_000,
    ...over,
  }) as PersonTokenRecord;

describe("resolvePersonPrincipal — organisation by ID (0.29.0)", () => {
  it("record has orgId and deps have the ID lookup: the ID path serves, the slug is not the selector", async () => {
    const d = deps();
    const r = await resolvePersonPrincipal(rec({ orgId: "org_A" }), d, DOOR);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.organisation).toEqual(A);
    expect(r.principal.orgId).toBe("org_A");
    expect(r.principal.orgSlug).toBe("org-a");
    expect(d.byId).toEqual(["org_A"]);
  });

  it("an ID-only record (no slug) is served by the ID path", async () => {
    const d = deps();
    const { orgSlug: _s, ...noSlug } = rec({ orgId: "org_A" }) as Record<string, unknown>;
    const r = await resolvePersonPrincipal(noSlug as PersonTokenRecord, d, DOOR);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.principal.orgId).toBe("org_A");
    expect(d.bySlug).toEqual([]);
  });

  it("no orgId on the record: the legacy slug path, ID lookup never called", async () => {
    const d = deps();
    const r = await resolvePersonPrincipal(rec(), d, DOOR);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.organisation).toEqual(A);
    expect("orgId" in r.principal).toBe(false);
    expect(d.byId).toEqual([]);
    expect(d.bySlug).toEqual(["org-a"]);
  });

  it("orgId on the record but no ID lookup in the deps: the slug path, unchanged", async () => {
    const d = deps({ lookupOrganisationById: undefined });
    const r = await resolvePersonPrincipal(rec({ orgId: "org_A" }), d, DOOR);
    expect(r.ok).toBe(true);
    expect(d.bySlug).toEqual(["org-a"]);
  });

  it("the ID path refusing (inactive org) does NOT fall back to the slug", async () => {
    const d = deps();
    const r = await resolvePersonPrincipal(
      rec({ orgId: "org_D", orgSlug: "org-a" }),
      d,
      DOOR,
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.reason).toBe("org-not-active");
    expect(d.byId).toEqual(["org_D"]);
  });

  it("the ID path finding nothing does NOT fall back to the slug (slug would have served)", async () => {
    const d = deps();
    const r = await resolvePersonPrincipal(
      rec({ orgId: "org_unknown", orgSlug: "org-a" }),
      d,
      DOOR,
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.reason).toBe("org-not-active");
    expect(d.bySlug).toEqual([]);
  });

  it("orgId and orgSlug resolving to different organisations are refused other-organisation", async () => {
    const d = deps();
    const r = await resolvePersonPrincipal(
      rec({ orgId: "org_A", orgSlug: "org-b" }),
      d,
      DOOR,
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.reason).toBe("other-organisation");
    expect(r.refusal.code).toBe("RBAC_DENIED");
    expect(r.refusal.door).toBe(DOOR);
  });

  it("a slug that resolves to nothing (label renamed away) does not refuse: the ID is authoritative", async () => {
    const d = deps();
    const r = await resolvePersonPrincipal(
      rec({ orgId: "org_A", orgSlug: "old-label" }),
      d,
      DOOR,
    );
    expect(r.ok).toBe(true);
  });

  it("both present and no way to read an organisation's ID from the slug row: refused, never guessed", async () => {
    const d = deps({ organisationId: undefined });
    const r = await resolvePersonPrincipal(
      rec({ orgId: "org_A", orgSlug: "org-a" }),
      d,
      DOOR,
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.reason).toBe("other-organisation");
  });

  it("an ID lookup that returns a row whose ID differs from the asked one is refused", async () => {
    const d = deps({ lookupOrganisationById: async () => B });
    const r = await resolvePersonPrincipal(rec({ orgId: "org_A" }), d, DOOR);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.reason).toBe("other-organisation");
  });

  it.each([
    ["empty", ""],
    ["number", 7],
    ["object", {}],
    ["array", ["org_A"]],
    ["boolean", true],
  ])("a malformed orgId (%s) makes the record malformed", async (_n, bad) => {
    const d = deps();
    const r = await resolvePersonPrincipal(rec({ orgId: bad }), d, DOOR);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.reason).toBe("person-token-not-live");
    expect(d.byId).toEqual([]);
    expect(d.bySlug).toEqual([]);
  });

  it("null or undefined orgId is allowed and means absent (slug path)", async () => {
    for (const v of [null, undefined]) {
      const d = deps();
      const r = await resolvePersonPrincipal(rec({ orgId: v }), d, DOOR);
      expect(r.ok).toBe(true);
      expect(d.byId).toEqual([]);
    }
  });

  it("a throwing ID lookup propagates like the slug lookup does and never falls back", async () => {
    const d = deps({
      lookupOrganisationById: async () => {
        throw new Error("boom");
      },
    });
    await expect(
      resolvePersonPrincipal(rec({ orgId: "org_A" }), d, DOOR),
    ).rejects.toThrow("boom");
    expect(d.bySlug).toEqual([]);
  });

  it("no lookup at all for the path taken: refused org-not-active, never served", async () => {
    const r = await resolvePersonPrincipal(
      rec(),
      { now: NOW },
      DOOR,
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.reason).toBe("org-not-active");
  });
});

import { resolvePersonTenantAccess, type PersonPrincipal } from "../src/person-principal.js";

describe("resolvePersonTenantAccess — by ID when the principal carries orgId (0.29.0)", () => {
  const idOnly: PersonPrincipal = {
    subject: "user_alice",
    orgSlug: "",
    orgId: "org_A",
    actor: "user:user_alice",
  };
  const both: PersonPrincipal = { ...idOnly, orgSlug: "org-a" };
  const legacy: PersonPrincipal = {
    subject: "user_alice",
    orgSlug: "org-a",
    actor: "user:user_alice",
  };
  const t = (principal: PersonPrincipal, rowOrgId: string | null | undefined) =>
    resolvePersonTenantAccess({ principal, rowOrgId, door: DOOR });

  it("an ID-only principal is admitted on its own organisation's row", () => {
    expect(t(idOnly, "org_A")).toEqual({ ok: true });
  });
  it("refused on another organisation's row", () => {
    const r = t(idOnly, "org_B");
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal.reason).toBe("other-organisation");
  });
  it("refused on a row that only carries a slug", () => {
    expect(t(idOnly, "org-a").ok).toBe(false);
  });
  it("a principal with orgId AND a slug never matches on the slug alone", () => {
    expect(t(both, "org-a").ok).toBe(false);
    expect(t(both, "org_A")).toEqual({ ok: true });
  });
  it("an unstamped row is refused for an ID principal", () => {
    for (const v of [undefined, null, ""]) expect(t(idOnly, v).ok).toBe(false);
  });
  it("a slug-only principal is unchanged", () => {
    expect(t(legacy, "org-a")).toEqual({ ok: true });
    expect(t(legacy, "org_A").ok).toBe(false);
  });
});
