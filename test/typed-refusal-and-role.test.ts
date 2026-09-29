/**
 * 0.6.0 — the non-throwing sibling of `requireTenantId`, and the role
 * assertion. Four poles, each with its grant pole:
 *
 *   1. no organization  -> a TYPED ABSENCE, not an exception
 *   2. that absence is NOT the value of a scoped caller with an empty set
 *   3. the role assertion ADMITS a verified holder of the role
 *   4. the role assertion REFUSES a verified member who lacks the role
 *
 * No pole here authenticates through a master or bypass path: every caller
 * is a plain session/bearer/self-host input, and pole 4 runs as an ORDINARY
 * verified member of an organization, not as an anonymous caller.
 */

import { describe, it, expect } from "vitest";
import {
  requireTenantId,
  resolveTenantIdOrAbsent,
  type TenantSource,
} from "../src/org-guard.js";
import {
  requireHumanRole,
  resolveHumanRoleOrRefusal,
  type ClerkSessionLike,
} from "../src/human-path.js";

const noOrgSources: Array<[string, TenantSource]> = [
  ["session null", { kind: "session", identity: null }],
  ["session undefined", { kind: "session", identity: undefined }],
  ["session without orgId", { kind: "session", identity: {} }],
  ["session with empty orgId", { kind: "session", identity: { orgId: "" } }],
  [
    "bearer with empty workspaceId",
    { kind: "bearer", context: { userId: "u", workspaceId: "", roles: [] } as never },
  ],
  ["self-host with no tenantId", { kind: "self-host", tenantId: undefined }],
  ["self-host with empty tenantId", { kind: "self-host", tenantId: "" }],
];

const scopedSource: TenantSource = {
  kind: "session",
  identity: { orgId: "tenant-opaque-1" },
};

// A minimal public read, the way a consuming product writes one.
function readRows(source: TenantSource, table: Array<{ tenant: string }>) {
  const r = resolveTenantIdOrAbsent(source);
  if (!r.present) return r; // the refusal, said as itself
  return table.filter((row) => row.tenant === r.tenantId);
}

describe("POLE 1 — no organization yields a typed absence, not an exception", () => {
  for (const [label, source] of noOrgSources) {
    it(`${label}: returns { present:false, absence } and does not throw`, () => {
      let result: ReturnType<typeof resolveTenantIdOrAbsent> | undefined;
      expect(() => {
        result = resolveTenantIdOrAbsent(source);
      }).not.toThrow();
      expect(result?.present).toBe(false);
      if (result && !result.present) {
        expect(result.absence.code).toBe("TENANT_ABSENT");
        expect(typeof result.absence.reason).toBe("string");
      }
    });

    it(`${label}: requireTenantId still THROWS (unchanged)`, () => {
      expect(() => requireTenantId(source)).toThrow(/^(Unauthenticated|No active organization|No workspace|No tenant id)/);
    });
  }

  it("GRANT: a scoped session is served its tenant id", () => {
    expect(resolveTenantIdOrAbsent(scopedSource)).toEqual({
      present: true,
      tenantId: "tenant-opaque-1",
    });
  });

  it("GRANT: a scoped bearer and a configured self-host are served", () => {
    expect(
      resolveTenantIdOrAbsent({
        kind: "bearer",
        context: { userId: "u", workspaceId: "ws-9", roles: [] } as never,
      }),
    ).toEqual({ present: true, tenantId: "ws-9" });
    expect(
      resolveTenantIdOrAbsent({ kind: "self-host", tenantId: "solo" }),
    ).toEqual({ present: true, tenantId: "solo" });
  });

  it("GRANT: the present id equals what requireTenantId returns", () => {
    const r = resolveTenantIdOrAbsent(scopedSource);
    expect(r.present && r.tenantId).toBe(requireTenantId(scopedSource));
  });

  it("the tenant id is opaque: returned byte-for-byte, never normalized", () => {
    const odd = "Org Name/With Spaces-and-CASE";
    const r = resolveTenantIdOrAbsent({ kind: "session", identity: { orgId: odd } });
    expect(r).toEqual({ present: true, tenantId: odd });
  });
});

describe("POLE 2 — the absence is distinguishable from an empty result", () => {
  it("no-organization caller and scoped caller over an EMPTY table differ in value", () => {
    const refused = readRows({ kind: "session", identity: null }, []);
    const absent = readRows(scopedSource, []);
    expect(refused).not.toEqual(absent);
    expect(JSON.stringify(refused)).not.toBe(JSON.stringify(absent));
    expect(Array.isArray(absent)).toBe(true);
    expect(Array.isArray(refused)).toBe(false);
  });

  it("the typed absence is not itself an empty value of any kind", () => {
    const r = resolveTenantIdOrAbsent({ kind: "session", identity: null });
    expect(r).not.toEqual([]);
    expect(r).not.toEqual({});
    expect(r).not.toBeNull();
    expect(r).not.toBeUndefined();
    expect(Object.keys(r).length).toBeGreaterThan(0);
  });

  it("GRANT: a scoped caller over a POPULATED table is served its rows", () => {
    const rows = [{ tenant: "tenant-opaque-1" }, { tenant: "other" }];
    expect(readRows(scopedSource, rows)).toEqual([{ tenant: "tenant-opaque-1" }]);
  });
});

const admin: ClerkSessionLike = { orgId: "o1", userId: "u1", orgRole: "org:admin" };
const member: ClerkSessionLike = { orgId: "o1", userId: "u2", orgRole: "org:member" };

describe("POLE 3 — the role assertion admits a verified holder of the role", () => {
  it("requireHumanRole returns the resolved identity for an admin", () => {
    expect(requireHumanRole(admin, "admin")).toEqual({
      tenant: "o1",
      subject: "u1",
      role: "admin",
    });
  });

  it("resolveHumanRoleOrRefusal admits an admin", () => {
    expect(resolveHumanRoleOrRefusal(admin, "admin")).toEqual({
      admitted: true,
      identity: { tenant: "o1", subject: "u1", role: "admin" },
    });
  });

  it("an any-of list admits a holder of one listed role", () => {
    expect(requireHumanRole(admin, ["owner", "admin"]).role).toBe("admin");
  });
});

describe("POLE 4 — the role assertion refuses a verified member lacking the role", () => {
  it("requireHumanRole throws for an ordinary member asked for admin", () => {
    expect(() => requireHumanRole(member, "admin")).toThrow(/^Role refused/);
  });

  it("resolveHumanRoleOrRefusal returns a typed refusal, not an exception", () => {
    const r = resolveHumanRoleOrRefusal(member, "admin");
    expect(r.admitted).toBe(false);
    if (!r.admitted) {
      expect(r.refusal.code).toBe("ROLE_REFUSED");
      expect(r.refusal.reason).toBe("role-not-held");
    }
  });

  it("the member is a real verified member: admitted for the role it DOES hold", () => {
    expect(requireHumanRole(member, "member").role).toBe("member");
    expect(resolveHumanRoleOrRefusal(member, "member").admitted).toBe(true);
  });

  it("the role is read from the verified session, never from a supplied field", () => {
    const forged = { ...member, role: "admin" } as unknown as ClerkSessionLike;
    expect(resolveHumanRoleOrRefusal(forged, "admin").admitted).toBe(false);
    expect(() => requireHumanRole(forged, "admin")).toThrow(/^Role refused/);
  });

  it("roles match exactly: owner does not silently satisfy admin", () => {
    const owner: ClerkSessionLike = { orgId: "o1", userId: "u3", orgRole: "org:owner" };
    expect(resolveHumanRoleOrRefusal(owner, "admin").admitted).toBe(false);
    expect(resolveHumanRoleOrRefusal(owner, ["owner", "admin"]).admitted).toBe(true);
  });

  it("an empty required list admits nobody", () => {
    expect(resolveHumanRoleOrRefusal(admin, []).admitted).toBe(false);
    expect(() => requireHumanRole(admin, [])).toThrow(/^Role refused/);
  });

  const malformed: Array<[string, ClerkSessionLike | null | undefined, string]> = [
    ["no session", null, "no-session"],
    ["no organization", { userId: "u", orgRole: "org:admin" }, "no-organization"],
    ["no user id", { orgId: "o", orgRole: "org:admin" }, "no-verified-role"],
    ["no role", { orgId: "o", userId: "u" }, "no-verified-role"],
    ["unrecognized role", { orgId: "o", userId: "u", orgRole: "org:god" }, "no-verified-role"],
  ];
  for (const [label, session, reason] of malformed) {
    it(`parity — ${label}: both forms refuse, non-throwing names "${reason}"`, () => {
      expect(() => requireHumanRole(session, "admin")).toThrow(
        /^(Unauthenticated|No active organization|No user id|No organization role|Unrecognized organization role)/,
      );
      const r = resolveHumanRoleOrRefusal(session, "admin");
      expect(r.admitted).toBe(false);
      if (!r.admitted) expect(r.refusal.reason).toBe(reason);
    });
  }
});
