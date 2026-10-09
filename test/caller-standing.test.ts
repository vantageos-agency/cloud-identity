import { describe, expect, it } from "vitest";
import {
  type OrganisationRow,
  type OrgKind,
  type PrincipalLookups,
  type PrincipalRow,
  resolveCallerStanding,
  validateMasterBearer,
} from "../src/index.js";

/**
 * Caller standing. Stage 1 composed resolveActingPrincipal + assertOrgAdmin by
 * hand: every case held except the signed-in session with no organisation,
 * which resolveActingPrincipal refuses exactly as it refuses garbage. So
 * resolveCallerStanding adds that case and delegates the rest.
 */

const OPERATOR = "org_operator";
const ADMIN_ROLES = ["org:admin"] as const;

const PERSONS: Record<string, PrincipalRow> = {
  "user_admin|org_a": { id: "user_admin", orgId: "org_a", active: true },
  "user_member|org_a": { id: "user_member", orgId: "org_a", active: true },
};
const SERVICES: Record<string, PrincipalRow> = {
  svc_fleet: { id: "svc_fleet", orgId: OPERATOR, active: true },
};
const ORGS: Record<string, OrganisationRow> = {
  org_a: { id: "org_a", active: true },
  [OPERATOR]: { id: OPERATOR, active: true },
};
const KINDS: Record<string, OrgKind> = { org_a: "client", [OPERATOR]: "operator" };

const lookups: PrincipalLookups = {
  personById: async (id, org) => PERSONS[`${id}|${org}`] ?? null,
  serviceAccountById: async (id) => SERVICES[id] ?? null,
  organisationById: async (id) => ORGS[id] ?? null,
  orgKindOf: async (id) => KINDS[id] ?? null,
};

async function derive(credential: unknown) {
  return resolveCallerStanding(credential as never, lookups, { adminRoles: ADMIN_ROLES });
}

describe("resolveCallerStanding", () => {
  it("a master token (validated) then the fleet service account gives fleet", async () => {
    expect((await validateMasterBearer("Bearer s3cret", "s3cret")).ok).toBe(true);
    expect((await derive({ kind: "service", serviceAccountId: "svc_fleet" })).standing).toBe("fleet");
  });

  it("a fleet service-account agent credential gives fleet", async () => {
    expect((await derive({ kind: "service", serviceAccountId: "svc_fleet" })).standing).toBe("fleet");
  });

  it("an admin session gives admin", async () => {
    const c = { kind: "person", personId: "user_admin", verifiedOrgId: "org_a", verifiedOrgRole: "org:admin" };
    expect((await derive(c)).standing).toBe("admin");
  });

  it("a member session gives member", async () => {
    const c = { kind: "person", personId: "user_member", verifiedOrgId: "org_a", verifiedOrgRole: "org:member" };
    expect((await derive(c)).standing).toBe("member");
  });

  it("a signed-in session with no organisation gives pre-org, distinct from anonymous", async () => {
    const pre = await derive({ kind: "person-no-org", personId: "user_member" });
    const anon = await derive(null);
    expect(pre).toEqual({ standing: "pre-org", personId: "user_member" });
    expect(anon.standing).toBe("anonymous");
    expect(pre.standing).not.toBe(anon.standing);
  });

  it("a person credential merely missing its organisation is garbled, not pre-org", async () => {
    for (const c of [{ kind: "person", personId: "user_member" }, { kind: "person-no-org" }, { kind: "person-no-org", personId: "u", verifiedOrgId: "org_a" }]) {
      expect((await derive(c)).standing).toBe("anonymous");
    }
  });

  it("returns the principal for admin, member and fleet", async () => {
    const admin = await derive({ kind: "person", personId: "user_admin", verifiedOrgId: "org_a", verifiedOrgRole: "org:admin" });
    expect(admin).toEqual({ standing: "admin", principal: { principalId: "user_admin", orgId: "org_a", kind: "person", orgRole: "org:admin" } });
    const fleet = await derive({ kind: "service", serviceAccountId: "svc_fleet" });
    expect(fleet).toEqual({ standing: "fleet", principal: { principalId: "svc_fleet", orgId: OPERATOR, kind: "fleet" } });
  });

  it("an unknown or inactive person is refused, never member", async () => {
    const r = await derive({ kind: "person", personId: "ghost", verifiedOrgId: "org_a", verifiedOrgRole: "org:admin" });
    expect(r.standing).toBe("anonymous");
  });

  it("an empty adminRoles list makes nobody admin", async () => {
    const r = await resolveCallerStanding(
      { kind: "person", personId: "user_admin", verifiedOrgId: "org_a", verifiedOrgRole: "org:admin" },
      lookups,
      { adminRoles: [] },
    );
    expect(r.standing).toBe("member");
  });

  it("a missing credential is refused", async () => {
    for (const c of [null, undefined]) {
      const r = await derive(c);
      expect(r.standing).toBe("anonymous");
      expect(r.refusal?.code).toBe("RBAC_DENIED");
    }
  });

  it("a garbled credential is refused", async () => {
    for (const c of ["x", 7, {}, { kind: "person" }, { kind: "fleet" }, { kind: "person", personId: "", verifiedOrgId: "org_a" }]) {
      const r = await derive(c);
      expect(r.standing).toBe("anonymous");
      expect(r.refusal?.code).toBe("RBAC_DENIED");
    }
  });
});
