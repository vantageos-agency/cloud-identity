/**
 * 0.9.0 — the person principal: a verified sign-in (person + organisation) as
 * pure data, the own-name actor rule, the tenant compare and the writer-role
 * assertion.
 *
 * Every pole runs as an ORDINARY non-master person of organisation A. Nothing
 * here authenticates through a master or bypass path, and no input carries a
 * master flag.
 *
 *   1. person of org A acting as itself in A      -> SERVED
 *   2. names an agent without that agent's proof  -> REFUSED
 *   3. names another user                         -> REFUSED
 *   4. reads / writes a row of org B              -> REFUSED
 *   5. writer role: viewer refused, editor served
 */

import { describe, it, expect } from "vitest";
import {
  PERSON_ACTOR_PREFIX,
  PersonRefusalError,
  checkPersonCallShape,
  isPersonActorName,
  personActorName,
  requireWriterRole,
  resolvePersonActingName,
  resolvePersonPrincipal,
  resolvePersonTenantAccess,
  resolveWriterRole,
  type PersonPrincipal,
  type PersonTokenRecord,
} from "../src/person-principal.js";

const NOW = 1_800_000_000_000;
const DOOR = "tasks:create";

const tokenOfA: PersonTokenRecord = {
  principal: "person",
  subject: "user_alice",
  orgSlug: "org-a",
  orgRole: "org:editor",
  expiresAt: NOW + 60_000,
};

const orgs: Record<string, { isActive: boolean; scopes: string[] }> = {
  "org-a": { isActive: true, scopes: ["tasks"] },
  "org-b": { isActive: true, scopes: ["tasks"] },
  "org-dormant": { isActive: false, scopes: [] },
};

function deps() {
  const looked: string[] = [];
  return {
    looked,
    now: NOW,
    lookupOrganisation: async (slug: string) => {
      looked.push(slug);
      return orgs[slug] ?? null;
    },
  };
}

async function principalOfA(): Promise<PersonPrincipal> {
  const r = await resolvePersonPrincipal(tokenOfA, deps(), DOOR);
  if (!r.ok) throw new Error(`fixture refused: ${r.refusal.reason}`);
  return r.principal;
}

describe("resolvePersonPrincipal", () => {
  it("SERVED: a live person token of org A resolves to org A, its role and its own actor name", async () => {
    const d = deps();
    const r = await resolvePersonPrincipal(tokenOfA, d, DOOR);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.principal).toEqual({
      subject: "user_alice",
      orgSlug: "org-a",
      orgRole: "org:editor",
      actor: "user:user_alice",
    });
    expect(r.organisation).toEqual({ isActive: true, scopes: ["tasks"] });
    // The organisation consulted is the TOKEN's own, never another.
    expect(d.looked).toEqual(["org-a"]);
  });

  it("REFUSED: expired, revoked, not a person token, no organisation, org inactive or unknown", async () => {
    const cases: Array<[string, PersonTokenRecord, string]> = [
      ["expired", { ...tokenOfA, expiresAt: NOW - 1 }, "person-token-not-live"],
      ["revoked", { ...tokenOfA, revokedAt: NOW - 5 }, "person-token-not-live"],
      ["seat token", { ...tokenOfA, principal: undefined }, "not-a-person-token"],
      ["other principal kind", { ...tokenOfA, principal: "service" }, "not-a-person-token"],
      ["no organisation", { ...tokenOfA, orgSlug: undefined }, "person-token-no-org"],
      ["inactive organisation", { ...tokenOfA, orgSlug: "org-dormant" }, "org-not-active"],
      ["unmapped organisation", { ...tokenOfA, orgSlug: "org-zzz" }, "org-not-active"],
    ];
    for (const [label, token, reason] of cases) {
      const r = await resolvePersonPrincipal(token, deps(), DOOR);
      expect(r.ok, label).toBe(false);
      if (r.ok) continue;
      expect(r.refusal.code, label).toBe("RBAC_DENIED");
      expect(r.refusal.reason, label).toBe(reason);
      expect(r.refusal.door, label).toBe(DOOR);
    }
  });

  it("REFUSED: a malformed record is refused, never defaulted", async () => {
    const r = await resolvePersonPrincipal(
      { ...tokenOfA, subject: "" } as PersonTokenRecord,
      deps(),
      DOOR,
    );
    expect(r.ok).toBe(false);
  });

  it("a role is carried only when the token has one (no silent default)", async () => {
    const r = await resolvePersonPrincipal(
      { ...tokenOfA, orgRole: undefined },
      deps(),
      DOOR,
    );
    expect(r.ok && "orgRole" in r.principal).toBe(false);
  });
});

describe("own-name actor rule", () => {
  it("the actor name is user:<subject>, and that spelling is reserved", () => {
    expect(PERSON_ACTOR_PREFIX).toBe("user:");
    expect(personActorName("user_alice")).toBe("user:user_alice");
    expect(isPersonActorName("USER:someone")).toBe(true);
    expect(isPersonActorName(" user:x")).toBe(true);
    expect(isPersonActorName("sigma")).toBe(false);
  });

  it("SERVED pole 1: omitting the name, or restating its own, acts as itself", async () => {
    const principal = await principalOfA();
    for (const claimedName of [undefined, null, "user:user_alice", " USER:USER_ALICE "]) {
      const r = resolvePersonActingName({ principal, claimedName, door: DOOR });
      expect(r).toEqual({ ok: true, actingAs: "person", actor: "user:user_alice" });
    }
  });

  it("REFUSED pole 2: naming an agent without that agent's credential", async () => {
    const principal = await principalOfA();
    const r = resolvePersonActingName({ principal, claimedName: "sigma", door: DOOR });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.code).toBe("AGENT_CREDENTIAL_REQUIRED");
    expect(r.refusal.reason).toBe("agent-credential-required");
    expect(r.refusal.claimed).toBe("sigma");
  });

  it("naming an agent WITH its own verified credential acts as that agent; a different credential is refused", async () => {
    const principal = await principalOfA();
    const ok = resolvePersonActingName({
      principal,
      claimedName: "Sigma",
      agentCredential: { agentName: "sigma" },
      door: DOOR,
    });
    expect(ok).toEqual({ ok: true, actingAs: "agent", actor: "sigma" });
    const bad = resolvePersonActingName({
      principal,
      claimedName: "eta",
      agentCredential: { agentName: "sigma" },
      door: DOOR,
    });
    expect(bad.ok).toBe(false);
    if (!bad.ok) expect(bad.refusal.code).toBe("AGENT_IDENTITY_MISMATCH");
  });

  it("REFUSED pole 3: naming another user, with or without an agent credential", async () => {
    const principal = await principalOfA();
    for (const agentCredential of [undefined, { agentName: "sigma" }]) {
      const r = resolvePersonActingName({
        principal,
        claimedName: "user:user_bob",
        agentCredential,
        door: DOOR,
      });
      expect(r.ok).toBe(false);
      if (r.ok) continue;
      expect(r.refusal.code).toBe("PERSON_ACTS_AS_ITSELF");
      expect(r.refusal.reason).toBe("person-acts-as-itself");
      expect(r.refusal.self).toBe("user:user_alice");
    }
  });

  it("the Convex-door shape: a person's call carries no acting name and no agent proof", () => {
    expect(checkPersonCallShape({ door: DOOR })).toBeNull();
    const named = checkPersonCallShape({ door: DOOR, actingName: "user:user_alice" });
    expect(named?.code).toBe("PERSON_ACTS_AS_ITSELF");
    const proof = checkPersonCallShape({ door: DOOR, agentProof: true });
    expect(proof?.code).toBe("RBAC_DENIED");
    expect(proof?.reason).toBe("agent-proof-on-person-path");
  });
});

describe("tenant compare", () => {
  it("SERVED: a row of org A; REFUSED pole 4: a row of org B, an unstamped row, an empty stamp", async () => {
    const principal = await principalOfA();
    expect(resolvePersonTenantAccess({ principal, rowOrgId: "org-a", door: DOOR })).toEqual({ ok: true });
    for (const rowOrgId of ["org-b", undefined, null, ""]) {
      const r = resolvePersonTenantAccess({ principal, rowOrgId, door: DOOR });
      expect(r.ok, String(rowOrgId)).toBe(false);
      if (!r.ok) {
        expect(r.refusal.code).toBe("RBAC_DENIED");
        expect(r.refusal.reason).toBe("other-organisation");
      }
    }
  });

  it("a principal of org B reaching org B's own rows is served (the compare is symmetric, not a deny-all)", async () => {
    const r = await resolvePersonPrincipal({ ...tokenOfA, orgSlug: "org-b" }, deps(), DOOR);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(resolvePersonTenantAccess({ principal: r.principal, rowOrgId: "org-b", door: DOOR })).toEqual({ ok: true });
    expect(resolvePersonTenantAccess({ principal: r.principal, rowOrgId: "org-a", door: DOOR }).ok).toBe(false);
  });
});

describe("writer role", () => {
  const writers = ["org:admin", "org:editor"];

  it("SERVED: an editor; REFUSED: a viewer", () => {
    expect(resolveWriterRole({ role: "org:editor", writerRoles: writers, door: DOOR, orgSlug: "org-a" })).toEqual({ ok: true });
    const v = resolveWriterRole({ role: "org:viewer", writerRoles: writers, door: DOOR, orgSlug: "org-a" });
    expect(v.ok).toBe(false);
    if (!v.ok) {
      expect(v.refusal.code).toBe("RBAC_DENIED");
      expect(v.refusal.reason).toBe("role-not-writer");
      expect(v.refusal.role).toBe("org:viewer");
      expect(v.refusal.orgSlug).toBe("org-a");
    }
  });

  it("fails closed: no role, no list and an empty list never mean 'all roles'", () => {
    expect(resolveWriterRole({ role: undefined, writerRoles: writers, door: DOOR, orgSlug: "org-a" }).ok).toBe(false);
    expect(resolveWriterRole({ role: null, writerRoles: writers, door: DOOR, orgSlug: "org-a" }).ok).toBe(false);
    expect(resolveWriterRole({ role: "org:admin", writerRoles: [], door: DOOR, orgSlug: "org-a" }).ok).toBe(false);
  });

  it("the throwing form carries the same typed refusal", () => {
    expect(() => requireWriterRole({ role: "org:editor", writerRoles: writers, door: DOOR, orgSlug: "org-a" })).not.toThrow();
    try {
      requireWriterRole({ role: "org:viewer", writerRoles: writers, door: DOOR, orgSlug: "org-a" });
      expect.unreachable("must throw");
    } catch (e) {
      expect(e).toBeInstanceOf(PersonRefusalError);
      expect((e as PersonRefusalError).refusal.reason).toBe("role-not-writer");
    }
  });
});
