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
  normalizeVerifiedHumanSession,
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

});

// ---------------------------------------------------------------------------
// The tenant id is OPAQUE — pinned on EVERY served path, and on BOTH siblings.
//
// The fixture carries EDGE WHITESPACE (two leading spaces, a trailing tab)
// for one reason: a fixture with no edges cannot fail on the property this
// pole names. An earlier version used "Org Name/With Spaces-and-CASE", and
// splicing `.trim()` onto the served id left the whole suite green — the
// guard against normalising an opaque identifier did not guard it. With the
// edges below, the same mutation goes RED on all four paths.
//
// A tenant id is an OPAQUE key: trimming, lower-casing or otherwise touching
// it silently changes WHICH TENANT a caller resolves to.
// ---------------------------------------------------------------------------

const OPAQUE_TENANT_ID = "  Org Name/With Spaces-and-CASE\t";

/**
 * Each served path, twice: once through the THROWING export shipped on main
 * (`requireTenantId` / `requireHumanRole`) and once through the non-throwing
 * sibling added here. A pole covering only the new export leaves the shipped
 * one unguarded.
 */
const servedPaths: Array<{
  label: string;
  throwing: () => string;
  typed: () => string;
}> = [
  {
    label: "session",
    throwing: () =>
      requireTenantId({ kind: "session", identity: { orgId: OPAQUE_TENANT_ID } }),
    typed: () => {
      const r = resolveTenantIdOrAbsent({
        kind: "session",
        identity: { orgId: OPAQUE_TENANT_ID },
      });
      if (!r.present) throw new Error("fixture must be served, not refused");
      return r.tenantId;
    },
  },
  {
    label: "bearer",
    throwing: () =>
      requireTenantId({
        kind: "bearer",
        context: { userId: "u", workspaceId: OPAQUE_TENANT_ID, roles: [] } as never,
      }),
    typed: () => {
      const r = resolveTenantIdOrAbsent({
        kind: "bearer",
        context: { userId: "u", workspaceId: OPAQUE_TENANT_ID, roles: [] } as never,
      });
      if (!r.present) throw new Error("fixture must be served, not refused");
      return r.tenantId;
    },
  },
  {
    label: "self-host",
    throwing: () =>
      requireTenantId({ kind: "self-host", tenantId: OPAQUE_TENANT_ID }),
    typed: () => {
      const r = resolveTenantIdOrAbsent({
        kind: "self-host",
        tenantId: OPAQUE_TENANT_ID,
      });
      if (!r.present) throw new Error("fixture must be served, not refused");
      return r.tenantId;
    },
  },
  {
    label: "role.identity.tenant",
    throwing: () =>
      requireHumanRole(
        { orgId: OPAQUE_TENANT_ID, userId: "u1", orgRole: "org:admin" },
        "admin",
      ).tenant,
    typed: () => {
      const r = resolveHumanRoleOrRefusal(
        { orgId: OPAQUE_TENANT_ID, userId: "u1", orgRole: "org:admin" },
        "admin",
      );
      if (!r.admitted) throw new Error("fixture must be admitted, not refused");
      return r.identity.tenant;
    },
  },
];

describe("OPACITY — the tenant id is served byte-for-byte, never normalized", () => {
  it("the fixture itself has edges that a normalisation would visibly alter", () => {
    // If this ever fails, the fixture was weakened and every pole below
    // became decoration again.
    expect(OPAQUE_TENANT_ID).not.toBe(OPAQUE_TENANT_ID.trim());
    expect(OPAQUE_TENANT_ID).not.toBe(OPAQUE_TENANT_ID.toLowerCase());
    expect(OPAQUE_TENANT_ID.startsWith("  ")).toBe(true);
    expect(OPAQUE_TENANT_ID.endsWith("\t")).toBe(true);
  });

  for (const { label, throwing, typed } of servedPaths) {
    it(`${label}: the THROWING sibling returns the id byte-for-byte`, () => {
      const served = throwing();
      // Compared against the literal fixture, never a normalised copy of it.
      expect(served).toBe(OPAQUE_TENANT_ID);
      expect(served.length).toBe(OPAQUE_TENANT_ID.length);
      expect(
        Buffer.from(served, "utf8").equals(Buffer.from(OPAQUE_TENANT_ID, "utf8")),
      ).toBe(true);
    });

    it(`${label}: the TYPED sibling returns the id byte-for-byte`, () => {
      const served = typed();
      expect(served).toBe(OPAQUE_TENANT_ID);
      expect(served.length).toBe(OPAQUE_TENANT_ID.length);
      expect(
        Buffer.from(served, "utf8").equals(Buffer.from(OPAQUE_TENANT_ID, "utf8")),
      ).toBe(true);
    });

    it(`${label}: both siblings agree, byte for byte`, () => {
      expect(typed()).toBe(throwing());
    });
  }
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

// ---------------------------------------------------------------------------
// A prototype key is not a role.
//
// The Clerk-role map was a plain object literal, so `MAP["toString"]` did not
// miss — it reached `Object.prototype` and returned a FUNCTION, which is
// truthy. `normalizeVerifiedHumanSession` therefore returned `role` as a
// function instead of refusing, and `__proto__` behaved the same way. The map
// is now prototype-less, so a lookup that is not an own key MISSES.
//
// This is pinned by CLASS (any inherited key), never by a list of bad names:
// a deny-list would have to be extended every time the prototype grows.
// ---------------------------------------------------------------------------

const prototypeKeys = [
  "toString",
  "constructor",
  "valueOf",
  "hasOwnProperty",
  "isPrototypeOf",
  "__proto__",
];

describe("POLE 5 — an inherited prototype key is refused, never resolved", () => {
  for (const key of prototypeKeys) {
    it(`orgRole "${key}" is refused as unrecognized by both forms`, () => {
      const session: ClerkSessionLike = {
        orgId: "o1",
        userId: "u1",
        orgRole: key,
      };
      expect(() => normalizeVerifiedHumanSession(session)).toThrow(
        /^Unrecognized organization role/,
      );
      expect(() => requireHumanRole(session, "admin")).toThrow(
        /^Unrecognized organization role/,
      );
      const r = resolveHumanRoleOrRefusal(session, [
        "owner",
        "admin",
        "member",
        "client",
      ]);
      expect(r.admitted).toBe(false);
      if (!r.admitted) expect(r.refusal.reason).toBe("no-verified-role");
    });
  }

  it("no inherited key ever resolves to a non-string role", () => {
    for (const key of prototypeKeys) {
      let served: unknown = "<threw>";
      try {
        served = normalizeVerifiedHumanSession({
          orgId: "o1",
          userId: "u1",
          orgRole: key,
        }).role;
      } catch {
        // refusing is the expected outcome; the assertion below covers the
        // case where it did NOT refuse.
      }
      expect(typeof served).not.toBe("function");
      expect(typeof served).not.toBe("object");
      expect(served).toBe("<threw>");
    }
  });

  it("GRANT: the eight own keys still resolve, unchanged", () => {
    const own: Array<[string, string]> = [
      ["org:owner", "owner"],
      ["owner", "owner"],
      ["org:admin", "admin"],
      ["admin", "admin"],
      ["org:member", "member"],
      ["member", "member"],
      ["org:client", "client"],
      ["client", "client"],
    ];
    for (const [presented, expected] of own) {
      expect(
        normalizeVerifiedHumanSession({
          orgId: "o1",
          userId: "u1",
          orgRole: presented,
        }).role,
      ).toBe(expected);
    }
  });

  it("the refusal message still enumerates the eight own keys", () => {
    expect(() =>
      normalizeVerifiedHumanSession({
        orgId: "o1",
        userId: "u1",
        orgRole: "org:god",
      }),
    ).toThrow(
      "Unrecognized organization role \"org:god\": expected one of org:owner, owner, org:admin, admin, org:member, member, org:client, client.",
    );
  });
});
