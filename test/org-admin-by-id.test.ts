import { describe, expect, it } from "vitest";
import {
  type ActingPrincipal,
  assertOrgAdmin,
  type OrganisationRow,
  type OrgKind,
  type PrincipalLookups,
  type PrincipalRow,
  resolveActingPrincipal,
} from "../src/index.js";

/**
 * The org-admin proof, decided BY ID on a principal the package resolved.
 *
 * The role is a verified claim carried on the person credential
 * (`verifiedOrgRole`); the admission compares the principal's stored org ID
 * with the target org ID and the role with the consumer's admin roles. Every
 * absence refuses.
 */

const OPERATOR = "org_operator";
const ADMIN_ROLES = ["org:admin"] as const;

const PERSONS: Record<string, PrincipalRow> = {
  "user_1|org_a": { id: "user_1", orgId: "org_a", active: true },
  "user_1|org_b": { id: "user_1", orgId: "org_b", active: true },
  [`user_1|${OPERATOR}`]: { id: "user_1", orgId: OPERATOR, active: true },
};
const AGENTS: Record<string, PrincipalRow> = {
  agent_a: { id: "agent_a", orgId: "org_a", active: true },
};
const SERVICES: Record<string, PrincipalRow> = {
  svc_a: { id: "svc_a", orgId: "org_a", active: true },
  svc_fleet: { id: "svc_fleet", orgId: OPERATOR, active: true },
};
const ORGS: Record<string, OrganisationRow> = {
  org_a: { id: "org_a", active: true },
  org_b: { id: "org_b", active: true },
  [OPERATOR]: { id: OPERATOR, active: true },
};
const KINDS: Record<string, OrgKind> = { org_a: "client", org_b: "client", [OPERATOR]: "operator" };

const lookups: PrincipalLookups = {
  agentById: async (id) => AGENTS[id] ?? null,
  personById: async (id, org) => PERSONS[`${id}|${org}`] ?? null,
  serviceAccountById: async (id) => SERVICES[id] ?? null,
  organisationById: async (id) => ORGS[id] ?? null,
  orgKindOf: async (id) => KINDS[id] ?? null,
};

async function person(orgId: string, role?: string): Promise<ActingPrincipal> {
  const r = await resolveActingPrincipal(
    {
      kind: "person",
      personId: "user_1",
      verifiedOrgId: orgId,
      ...(role === undefined ? {} : { verifiedOrgRole: role }),
    },
    lookups,
  );
  if (!r.ok) throw new Error(`expected a principal, got ${r.refusal.reason}`);
  return r.principal;
}

function reasonOf(r: ReturnType<typeof assertOrgAdmin>) {
  expect(r.ok).toBe(false);
  if (r.ok) return undefined;
  expect(r.refusal.code).toBe("RBAC_DENIED");
  return r.refusal.reason;
}

describe("resolveActingPrincipal — the verified role rides the person credential", () => {
  it("copies verifiedOrgRole onto the person principal as orgRole", async () => {
    expect(await person("org_a", "org:admin")).toEqual({
      principalId: "user_1",
      orgId: "org_a",
      kind: "person",
      orgRole: "org:admin",
    });
  });

  it("a person credential without a role resolves exactly as in 0.11.0 (no orgRole key)", async () => {
    const p = await person("org_a");
    expect(p).toEqual({ principalId: "user_1", orgId: "org_a", kind: "person" });
    expect("orgRole" in p).toBe(false);
  });

  it("refuses an empty or non-string verifiedOrgRole whole", async () => {
    for (const verifiedOrgRole of ["", 7, ["org:admin"]]) {
      const r = await resolveActingPrincipal(
        { kind: "person", personId: "user_1", verifiedOrgId: "org_a", verifiedOrgRole } as never,
        lookups,
      );
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("credential-invalid");
    }
  });

  it("an agent or service credential carrying a role is refused whole (strict schemas)", async () => {
    for (const credential of [
      { kind: "agent", agentId: "agent_a", verifiedOrgId: "org_a", verifiedOrgRole: "org:admin" },
      { kind: "service", serviceAccountId: "svc_a", verifiedOrgRole: "org:admin" },
    ]) {
      const r = await resolveActingPrincipal(credential as never, lookups);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("credential-invalid");
    }
  });
});

describe("assertOrgAdmin — served", () => {
  it("an admin of org A acting on org A is served", async () => {
    expect(assertOrgAdmin(await person("org_a", "org:admin"), "org_a", { adminRoles: ADMIN_ROLES })).toEqual({
      ok: true,
    });
  });

  it("an admin of the operator org on the operator org is an ordinary org admin (RULING 5)", async () => {
    const p = await person(OPERATOR, "org:admin");
    expect(p.kind).toBe("person");
    expect(assertOrgAdmin(p, OPERATOR, { adminRoles: ADMIN_ROLES }).ok).toBe(true);
  });
});

describe("assertOrgAdmin — refused", () => {
  it("an admin of org A acting on org B is refused", async () => {
    const r = assertOrgAdmin(await person("org_a", "org:admin"), "org_b", { adminRoles: ADMIN_ROLES });
    expect(reasonOf(r)).toBe("target-other-organisation");
  });

  it("a member of org A is refused on org A", async () => {
    const r = assertOrgAdmin(await person("org_a", "org:member"), "org_a", { adminRoles: ADMIN_ROLES });
    expect(reasonOf(r)).toBe("role-not-admin");
  });

  it("an absent role is refused", async () => {
    const r = assertOrgAdmin(await person("org_a"), "org_a", { adminRoles: ADMIN_ROLES });
    expect(reasonOf(r)).toBe("role-not-admin");
  });

  it("compares the role byte for byte: no case folding, no prefix stripping", async () => {
    for (const role of ["ORG:ADMIN", "admin", " org:admin", "org:admin "]) {
      const r = assertOrgAdmin(await person("org_a", role), "org_a", { adminRoles: ADMIN_ROLES });
      expect(reasonOf(r)).toBe("role-not-admin");
    }
  });

  it("an empty or malformed adminRoles list admits nobody", async () => {
    const p = await person("org_a", "org:admin");
    for (const adminRoles of [[], [""], "org:admin", null, undefined, [7]]) {
      expect(reasonOf(assertOrgAdmin(p, "org_a", { adminRoles: adminRoles as never }))).toBe("role-not-admin");
    }
  });

  it("the service account follows the service rules: as itself it is never an org admin", async () => {
    for (const serviceAccountId of ["svc_a", "svc_fleet"]) {
      const r = await resolveActingPrincipal({ kind: "service", serviceAccountId }, lookups);
      if (!r.ok) throw new Error(r.refusal.reason);
      expect(["service", "fleet"]).toContain(r.principal.kind);
      const target = r.principal.orgId;
      expect(reasonOf(assertOrgAdmin(r.principal, target, { adminRoles: ADMIN_ROLES }))).toBe(
        "principal-not-a-person",
      );
    }
  });

  it("an agent, and a hand-built non-person principal carrying a role, are refused", async () => {
    const agent = await resolveActingPrincipal({ kind: "agent", agentId: "agent_a", verifiedOrgId: "org_a" }, lookups);
    if (!agent.ok) throw new Error(agent.refusal.reason);
    expect(reasonOf(assertOrgAdmin(agent.principal, "org_a", { adminRoles: ADMIN_ROLES }))).toBe(
      "principal-not-a-person",
    );
    for (const kind of ["agent", "service", "fleet"] as const) {
      const forged = { principalId: "x", orgId: "org_a", kind, orgRole: "org:admin" };
      expect(reasonOf(assertOrgAdmin(forged, "org_a", { adminRoles: ADMIN_ROLES }))).toBe(
        "principal-not-a-person",
      );
    }
  });

  it("an absent principal, a principal with empty IDs and an absent target are refused", async () => {
    for (const principal of [null, undefined, { principalId: "", orgId: "org_a", kind: "person" as const }]) {
      expect(reasonOf(assertOrgAdmin(principal, "org_a", { adminRoles: ADMIN_ROLES }))).toBe("credential-invalid");
    }
    const p = await person("org_a", "org:admin");
    for (const target of [null, undefined, ""]) {
      expect(reasonOf(assertOrgAdmin(p, target, { adminRoles: ADMIN_ROLES }))).toBe("target-unstamped");
    }
  });

  it("carries the consumer's door on the refusal", async () => {
    const r = assertOrgAdmin(await person("org_a", "org:member"), "org_a", {
      adminRoles: ADMIN_ROLES,
      door: "githubOwnerBinding:startBinding",
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal.door).toBe("githubOwnerBinding:startBinding");
  });
});
