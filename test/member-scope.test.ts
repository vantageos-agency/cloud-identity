/**
 * 0.30.0 — `memberScopeFrom` / `memberScopeOfPerson`: the ordinary member
 * scope of a resolved organisation and a verified principal, built by the
 * package so a consumer assembles nothing itself.
 *
 * The fields are those a consumer's org-scope object carries for a member:
 * userId, orgSlug (the label), orgClerkId (the permanent ID), the two rosters,
 * scopes, fleetWide false, isMaster false, orgRole when the principal has one.
 */

import { describe, it, expect } from "vitest";
import { memberScopeFrom, memberScopeOfPerson } from "../src/member-scope.js";
import { scopeStanding } from "../src/scope-standing.js";
import type { ResolvedOrg } from "../src/org-by-id.js";

const ORG: ResolvedOrg = {
  id: "org_A",
  label: "acme-hr",
  allowedOrchestrators: ["alpha"],
  allowedAgentIds: ["agent_1", "agent_2"],
  scopes: ["tasks:read", "tasks:write"],
  orgKind: "client",
};
const DOOR = "tasks:create";

describe("memberScopeFrom — pole: a well-formed org and actor build the member scope", () => {
  it("builds exactly the member scope fields, copied verbatim from the row", () => {
    const r = memberScopeFrom(ORG, { userId: "user_1", orgRole: "org:admin" }, { door: DOOR });
    expect(r).toEqual({
      ok: true,
      scope: {
        userId: "user_1",
        orgSlug: "acme-hr",
        orgClerkId: "org_A",
        allowedOrchestrators: ["alpha"],
        allowedAgentIds: ["agent_1", "agent_2"],
        fleetWide: false,
        scopes: ["tasks:read", "tasks:write"],
        isMaster: false,
        orgRole: "org:admin",
      },
    });
  });

  it("is a 'member' standing for scopeStanding", () => {
    const r = memberScopeFrom(ORG, { userId: "user_1" }, { door: DOOR });
    expect(r.ok && scopeStanding(r.scope)).toBe("member");
  });

  it("omits orgRole when the actor has none (never defaulted)", () => {
    const r = memberScopeFrom(ORG, { userId: "user_1" }, { door: DOOR });
    expect(r.ok && "orgRole" in r.scope).toBe(false);
  });

  it("an absent roster is an empty list: nothing admitted, never everyone", () => {
    const bare: ResolvedOrg = { id: "org_B", label: "b", scopes: [], orgKind: null };
    const r = memberScopeFrom(bare, { userId: "u" }, { door: DOOR });
    expect(r.ok && r.scope.allowedAgentIds).toEqual([]);
    expect(r.ok && r.scope.allowedOrchestrators).toEqual([]);
  });

  it("copies the lists: mutating the scope does not mutate the resolved org", () => {
    const r = memberScopeFrom(ORG, { userId: "u" }, { door: DOOR });
    if (!r.ok) throw new Error("expected ok");
    r.scope.allowedAgentIds.push("intruder");
    r.scope.scopes.push("admin");
    expect(ORG.allowedAgentIds).toEqual(["agent_1", "agent_2"]);
    expect(ORG.scopes).toEqual(["tasks:read", "tasks:write"]);
  });

  it("the actor's org id, when it matches the org, is accepted", () => {
    const r = memberScopeFrom(ORG, { userId: "u", orgId: "org_A" }, { door: DOOR });
    expect(r.ok).toBe(true);
  });
});

describe("memberScopeFrom — pole: refusals, fail closed, door carried", () => {
  it("refuses an actor of another organisation (by ID, never by label)", () => {
    const r = memberScopeFrom(ORG, { userId: "u", orgId: "org_OTHER" }, { door: DOOR });
    expect(r).toMatchObject({
      ok: false,
      refusal: { code: "RBAC_DENIED", reason: "other-organisation", door: DOOR },
    });
  });

  it("refuses an empty actor orgId rather than treating it as absent", () => {
    const r = memberScopeFrom(ORG, { userId: "u", orgId: "" }, { door: DOOR });
    expect(r).toMatchObject({ ok: false, refusal: { reason: "other-organisation" } });
  });

  it("refuses a missing or empty user id (no-verified-subject)", () => {
    for (const userId of ["", undefined as unknown as string]) {
      const r = memberScopeFrom(ORG, { userId }, { door: DOOR });
      expect(r).toMatchObject({ ok: false, refusal: { reason: "no-verified-subject", door: DOOR } });
    }
  });

  it("refuses an org with no permanent ID or no label (org-mapping-record-invalid)", () => {
    for (const org of [{ ...ORG, id: "" }, { ...ORG, label: "" }, null, undefined]) {
      const r = memberScopeFrom(org as unknown as ResolvedOrg, { userId: "u" }, { door: DOOR });
      expect(r).toMatchObject({ ok: false, refusal: { reason: "org-mapping-record-invalid" } });
    }
  });

  it("refuses a malformed roster rather than guessing", () => {
    const bad = { ...ORG, allowedAgentIds: "agent_1" } as unknown as ResolvedOrg;
    const r = memberScopeFrom(bad, { userId: "u" }, { door: DOOR });
    expect(r).toMatchObject({ ok: false, refusal: { reason: "org-mapping-record-invalid" } });
  });

  it("uses the default door name when none is given", () => {
    const r = memberScopeFrom(ORG, { userId: "" });
    expect(r).toMatchObject({ ok: false, refusal: { door: "memberScopeFrom" } });
  });
});

describe("memberScopeOfPerson — a PersonPrincipal is the actor", () => {
  const person = { subject: "user_9", orgSlug: "acme-hr", orgId: "org_A", orgRole: "org:editor", actor: "user:user_9" };

  it("maps subject to userId and carries orgRole", () => {
    const r = memberScopeOfPerson(ORG, person, { door: DOOR });
    expect(r.ok && r.scope.userId).toBe("user_9");
    expect(r.ok && r.scope.orgRole).toBe("org:editor");
    expect(r.ok && scopeStanding(r.scope)).toBe("member");
  });

  it("a principal whose orgId names another organisation is refused", () => {
    const r = memberScopeOfPerson(ORG, { ...person, orgId: "org_Z" }, { door: DOOR });
    expect(r).toMatchObject({ ok: false, refusal: { reason: "other-organisation" } });
  });

  it("a legacy principal with no orgId is built from the org it was resolved against", () => {
    const { orgId: _omit, ...legacy } = person;
    const r = memberScopeOfPerson(ORG, legacy, { door: DOOR });
    expect(r.ok && r.scope.orgClerkId).toBe("org_A");
  });

  it("a principal with an empty subject is refused", () => {
    const r = memberScopeOfPerson(ORG, { ...person, subject: "" }, { door: DOOR });
    expect(r).toMatchObject({ ok: false, refusal: { reason: "no-verified-subject" } });
  });
});
