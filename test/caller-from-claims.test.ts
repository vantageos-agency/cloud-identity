import { describe, expect, it } from "vitest";
import { resolveCallerFromClaims } from "../src/caller-from-claims.js";
import { resolveProvisioningLabel } from "../src/org-by-id.js";

const ORG_A = "org_aaa";
const ORG_B = "org_bbb";
const mappingA = { id: ORG_A, label: "acme", active: true, allowedOrchestrators: [], scopes: ["view-own-tasks"], orgKind: "client" };
const mappingOp = { id: ORG_B, label: "operator", active: true, allowedOrchestrators: [], scopes: [], orgKind: "operator" };

function deps(over: { personOrg?: string | null; mappings?: Record<string, unknown> } = {}) {
  const mappings: Record<string, unknown> = over.mappings ?? { [ORG_A]: mappingA, [ORG_B]: mappingOp };
  return {
    orgLookups: {
      orgById: (id: string) => mappings[id] ?? null,
      orgByLabel: (label: string) => Object.values(mappings).find((m) => (m as { label: string }).label === label) ?? null,
    },
    principalLookups: {
      personById: (personId: string, orgId: string) =>
        over.personOrg === null ? null : { id: personId, orgId: over.personOrg ?? orgId, active: true },
      organisationById: (id: string) => (mappings[id] ? { id, active: true } : null),
      orgKindOf: (id: string) => ((mappings[id] as { orgKind?: string } | undefined)?.orgKind ?? null),
    },
  };
}
const opts = { adminRoles: ["org:admin", "admin"], door: "withOrgScope" } as const;

describe("resolveCallerFromClaims", () => {
  it("a verified member: org by org_id, person principal, role, not admin", async () => {
    const r = await resolveCallerFromClaims({ subject: "user_1", org_id: ORG_A, org_role: "org:member" }, deps(), opts);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.subject).toBe("user_1");
    expect(r.actorName).toBe("user:user_1");
    expect(r.org.id).toBe(ORG_A);
    expect(r.org.label).toBe("acme");
    expect(r.principal.kind).toBe("person");
    expect(r.principal.orgId).toBe(ORG_A);
    expect(r.role).toBe("org:member");
    expect(r.isOrgAdmin).toBe(false);
  });

  it("an org:admin of the org is isOrgAdmin, its orgKind is carried", async () => {
    const r = await resolveCallerFromClaims({ subject: "user_2", org_id: ORG_B, org_role: "org:admin" }, deps(), opts);
    expect(r.ok && r.isOrgAdmin).toBe(true);
    expect(r.ok && r.org.orgKind).toBe("operator");
  });

  it("the role claim is read under its three spellings; none is null and never admin", async () => {
    for (const key of ["orgRole", "org_role", "organizationRole"]) {
      const r = await resolveCallerFromClaims({ subject: "u", org_id: ORG_A, [key]: "org:admin" }, deps(), opts);
      expect(r.ok && r.role).toBe("org:admin");
    }
    const none = await resolveCallerFromClaims({ subject: "u", org_id: ORG_A }, deps(), opts);
    expect(none.ok && none.role).toBe(null);
    expect(none.ok && none.isOrgAdmin).toBe(false);
  });

  it("no org claim at all: refused no-verified-organisation, claimsOrg false", async () => {
    const r = await resolveCallerFromClaims({ subject: "u" }, deps(), opts);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.reason).toBe("no-verified-organisation");
    expect(r.claimsOrg).toBe(false);
    expect(r.refusal.door).toBe("withOrgScope");
  });

  it("a slug claim without an org_id is refused and reported as claiming an org", async () => {
    const r = await resolveCallerFromClaims({ subject: "u", org_slug: "acme" }, deps(), opts);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.reason).toBe("no-verified-organisation");
    expect(r.claimsOrg).toBe(true);
  });

  it("an org_id no mapping holds is refused, claimsOrg true", async () => {
    const r = await resolveCallerFromClaims({ subject: "u", org_id: "org_zzz" }, deps(), opts);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.reason).toBe("org-mapping-not-found");
    expect(r.claimsOrg).toBe(true);
  });

  it("a person stored in another organisation is refused", async () => {
    const r = await resolveCallerFromClaims({ subject: "u", org_id: ORG_A }, deps({ personOrg: ORG_B }), opts);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.reason).toBe("other-organisation");
  });

  it("no subject, or no claims, is refused credential-invalid", async () => {
    for (const claims of [undefined, null, {}, { subject: "" }, { subject: 42, org_id: ORG_A }]) {
      const r = await resolveCallerFromClaims(claims as never, deps(), opts);
      expect(r.ok).toBe(false);
      if (r.ok) continue;
      expect(r.refusal.reason).toBe("credential-invalid");
    }
  });

  it("an empty adminRoles is a programming error, never a silent non-admin", async () => {
    await expect(
      resolveCallerFromClaims({ subject: "u", org_id: ORG_A }, deps(), { adminRoles: [], door: "x" }),
    ).rejects.toThrow(TypeError);
  });
});

describe("resolveProvisioningLabel", () => {
  it("a mapped label answers its ID and whether it is active", async () => {
    expect(await resolveProvisioningLabel("acme", deps().orgLookups)).toEqual({ kind: "mapped", orgId: ORG_A, active: true });
  });

  it("a label no mapping holds is unmapped (the create case)", async () => {
    expect(await resolveProvisioningLabel("new-co", deps().orgLookups)).toEqual({ kind: "unmapped" });
  });

  it("a mapping without its ID filled yet is mapped-without-id, never a guessed ID", async () => {
    const lookups = deps({ mappings: { x: { ...mappingA, id: null } } }).orgLookups;
    expect(await resolveProvisioningLabel("acme", lookups)).toEqual({ kind: "mapped-without-id", active: true });
  });

  it("no label, a failing store or a row for another label is unreadable", async () => {
    expect(await resolveProvisioningLabel("", deps().orgLookups)).toEqual({ kind: "unreadable", reason: "no-label" });
    expect(
      await resolveProvisioningLabel("acme", {
        orgByLabel: () => {
          throw new Error("down");
        },
      }),
    ).toEqual({ kind: "unreadable", reason: "lookup-failed" });
    expect(await resolveProvisioningLabel("acme", { orgByLabel: () => ({ ...mappingA, label: "other" }) })).toEqual({
      kind: "unreadable",
      reason: "record-invalid",
    });
  });
});
