import { describe, expect, it } from "vitest";
import { IdentityRefusalError } from "../src/identity-refusal.js";
import {
  hasFleetRead,
  requireFleetStanding,
  requireStanding,
  scopeStanding,
} from "../src/scope-standing.js";

// The resolved scope shape a consumer's org-scope resolver returns (VantagePeers
// `withOrgScope`): every master branch sets `fleetWide` and `masterSource`.
const service = { isMaster: true, fleetWide: true, masterSource: "service-account", orgSlug: null };
const internal = { isMaster: true, fleetWide: true, masterSource: "internal", orgSlug: null };
const operatorAdmin = { isMaster: true, fleetWide: true, masterSource: "operator-admin", orgSlug: null };
const memberById = { isMaster: false, fleetWide: false, orgSlug: "acme", orgClerkId: "org_123" };
const memberBySlug = { isMaster: false, fleetWide: false, orgSlug: "acme" };
const anonymous = { isMaster: false, fleetWide: false, orgSlug: null };
const refusedFlag = { isMaster: false, fleetWide: false, orgSlug: null, refused: true };

describe("scopeStanding", () => {
  it("service account and internal opt-in are fleet", () => {
    expect(scopeStanding(service)).toBe("fleet");
    expect(scopeStanding(internal)).toBe("fleet");
  });

  it("the operator's org:admin human is operator-admin, not fleet", () => {
    expect(scopeStanding(operatorAdmin)).toBe("operator-admin");
  });

  it("a non-master scope with an organisation is member (by id or, during expand, by slug)", () => {
    expect(scopeStanding(memberById)).toBe("member");
    expect(scopeStanding(memberBySlug)).toBe("member");
  });

  it("no organisation, the refused flag, or a missing field is refused", () => {
    expect(scopeStanding(anonymous)).toBe("refused");
    expect(scopeStanding(refusedFlag)).toBe("refused");
    expect(scopeStanding({ ...memberById, refused: true })).toBe("refused");
    expect(scopeStanding({ fleetWide: true, masterSource: "service-account" })).toBe("refused");
  });

  it("a malformed or self-contradicting scope is refused, never fleet", () => {
    for (const bad of [
      undefined,
      null,
      "master",
      42,
      [],
      { isMaster: "true", fleetWide: true, masterSource: "service-account" },
      { isMaster: true, fleetWide: false, masterSource: "service-account" },
      { isMaster: true, masterSource: "service-account" },
      { isMaster: true, fleetWide: true },
      { isMaster: true, fleetWide: true, masterSource: "root" },
      { isMaster: false, fleetWide: true, orgSlug: "acme" },
      { isMaster: false, fleetWide: false, orgSlug: "acme", masterSource: "internal" },
      { isMaster: false, fleetWide: false, orgSlug: "" },
      { isMaster: false, fleetWide: false, orgSlug: null, orgClerkId: "" },
    ]) {
      expect(scopeStanding(bad)).toBe("refused");
    }
  });
});

describe("hasFleetRead", () => {
  it("is true for fleet and operator-admin only (the reading meaning of isMaster)", () => {
    expect(hasFleetRead(service)).toBe(true);
    expect(hasFleetRead(internal)).toBe(true);
    expect(hasFleetRead(operatorAdmin)).toBe(true);
    expect(hasFleetRead(memberById)).toBe(false);
    expect(hasFleetRead(anonymous)).toBe(false);
    expect(hasFleetRead({ isMaster: true })).toBe(false);
  });
});

describe("requireStanding / requireFleetStanding", () => {
  it("returns the standing when it is allowed", () => {
    expect(requireFleetStanding(service, "secrets.read")).toBe("fleet");
    expect(requireStanding(operatorAdmin, "fleet.list", ["fleet", "operator-admin"])).toBe(
      "operator-admin",
    );
    expect(requireStanding(memberById, "tasks.list", ["member", "fleet"])).toBe("member");
  });

  it("throws RBAC_DENIED naming the door when the standing is not allowed", () => {
    const attempt = () => requireFleetStanding(operatorAdmin, "secrets.read");
    expect(attempt).toThrow(IdentityRefusalError);
    try {
      attempt();
    } catch (e) {
      const err = e as IdentityRefusalError;
      expect(err.refusal.code).toBe("RBAC_DENIED");
      expect(err.refusal.reason).toBe("standing-not-allowed");
      expect(err.refusal.door).toBe("secrets.read");
      expect(err.refusal.detail).toContain("operator-admin");
    }
  });

  it("a refused or malformed scope is refused with scope-not-resolved, whatever is allowed", () => {
    for (const bad of [undefined, anonymous, refusedFlag, { isMaster: true }]) {
      try {
        requireStanding(bad, "tasks.list", ["fleet", "operator-admin", "member"]);
        expect.unreachable("must throw");
      } catch (e) {
        const err = e as IdentityRefusalError;
        expect(err).toBeInstanceOf(IdentityRefusalError);
        expect(err.refusal.code).toBe("RBAC_DENIED");
        expect(err.refusal.reason).toBe("scope-not-resolved");
        expect(err.refusal.door).toBe("tasks.list");
      }
    }
  });

  it("an empty allowed list is a programming error, never a pass", () => {
    expect(() => requireStanding(service, "x", [])).toThrow(TypeError);
  });
});
