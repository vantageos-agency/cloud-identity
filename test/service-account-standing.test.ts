import { describe, expect, it } from "vitest";
import { IdentityRefusalError } from "../src/identity-refusal.js";
import { isServiceAccountScope, requireServiceAccountStanding } from "../src/scope-standing.js";

// "fleet" covers two grants: the fleet's own service account and the internal
// opt-in (no credential at all). Doors that must be the service account itself
// (a verified actor, an agent credential, a recipient of the fleet's own
// traffic) refuse the internal opt-in.
const service = { isMaster: true, fleetWide: true, masterSource: "service-account", orgSlug: null };
const internal = { isMaster: true, fleetWide: true, masterSource: "internal", orgSlug: null };
const operatorAdmin = { isMaster: true, fleetWide: true, masterSource: "operator-admin", orgSlug: null };
const member = { isMaster: false, fleetWide: false, orgSlug: "acme", orgClerkId: "org_123" };

describe("isServiceAccountScope", () => {
  it("is true for the service account only", () => {
    expect(isServiceAccountScope(service)).toBe(true);
  });

  it("is false for the internal opt-in, the operator admin and a member", () => {
    expect(isServiceAccountScope(internal)).toBe(false);
    expect(isServiceAccountScope(operatorAdmin)).toBe(false);
    expect(isServiceAccountScope(member)).toBe(false);
  });

  it("is false for a self-contradicting scope that names the service account", () => {
    expect(isServiceAccountScope({ ...service, fleetWide: false })).toBe(false);
    expect(isServiceAccountScope({ ...service, isMaster: false, fleetWide: false })).toBe(false);
    expect(isServiceAccountScope(null)).toBe(false);
  });
});

describe("requireServiceAccountStanding", () => {
  it("returns for the service account", () => {
    expect(() => requireServiceAccountStanding(service, "door")).not.toThrow();
  });

  it("refuses the internal opt-in with standing-not-allowed, naming the door", () => {
    try {
      requireServiceAccountStanding(internal, "verifiedActor");
      throw new Error("expected a refusal");
    } catch (e) {
      expect(e).toBeInstanceOf(IdentityRefusalError);
      const r = (e as IdentityRefusalError).refusal;
      expect(r.code).toBe("RBAC_DENIED");
      expect(r.reason).toBe("standing-not-allowed");
      expect(r.door).toBe("verifiedActor");
    }
  });

  it("refuses an unresolved scope with scope-not-resolved", () => {
    try {
      requireServiceAccountStanding({ isMaster: true }, "door");
      throw new Error("expected a refusal");
    } catch (e) {
      expect((e as IdentityRefusalError).refusal.reason).toBe("scope-not-resolved");
    }
  });

  it("refuses the operator admin and a member", () => {
    expect(() => requireServiceAccountStanding(operatorAdmin, "door")).toThrow(IdentityRefusalError);
    expect(() => requireServiceAccountStanding(member, "door")).toThrow(IdentityRefusalError);
  });
});
