import { describe, expect, it } from "vitest";
import {
  type AuthorizedTokenClaims,
  type RefreshTokenRecord,
  type RefreshTokenStore,
  REFRESH_TOKEN_TTL_MS,
  buildDiscoveryDocument,
  exchangeRefreshToken,
  issueRefreshToken,
  oauthErrorFor,
  sha256Hex,
} from "../src/index.js";
import type { AuthorizeRefusalReason } from "../src/index.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const NOW = 1_800_000_000_000;
const RESOURCE = "https://mcp.example.test/mcp";
const CLIENT = "https://client.example.test/meta.json";

const CLAIMS: AuthorizedTokenClaims = {
  sub: "user_1",
  org_id: "org_1",
  org_slug: "acme",
  org_role: "org:member",
  aud: RESOURCE,
  client_id: CLIENT,
  scope: "openid email",
};

/**
 * A test-local store honouring the contract: digest-keyed, `consume` marks a
 * record used in one synchronous step (atomic in a single-threaded fake), and
 * `revokeFamily` marks every record of the family used.
 */
function fakeStore() {
  const records = new Map<string, RefreshTokenRecord>();
  const used = new Set<string>();
  const store: RefreshTokenStore = {
    async put(record) {
      records.set(record.tokenHash, record);
    },
    async consume(tokenHash) {
      const record = records.get(tokenHash);
      if (!record) return { status: "unknown" };
      if (used.has(tokenHash)) {
        return { status: "already-used", familyId: record.familyId };
      }
      used.add(tokenHash);
      return { status: "ok", record };
    },
    async revokeFamily(familyId) {
      for (const r of records.values()) {
        if (r.familyId === familyId) used.add(r.tokenHash);
      }
    },
  };
  return { store, records, used };
}

const allow = async (claims: AuthorizedTokenClaims) => ({
  ok: true as const,
  claims,
});

async function issued(refreshStore: RefreshTokenStore, now = NOW) {
  return issueRefreshToken(CLAIMS, { refreshStore, now: () => now });
}

function reasonOf(r: { ok: boolean; refusal?: { reason: string } }) {
  return r.ok ? "ok" : r.refusal?.reason;
}

// ---------------------------------------------------------------------------
// issueRefreshToken
// ---------------------------------------------------------------------------

describe("issueRefreshToken", () => {
  it("stores only the sha256 digest, never the raw token", async () => {
    const { store, records } = fakeStore();
    const { refreshToken, expiresAt } = await issued(store);
    const digest = await sha256Hex(refreshToken);
    expect(records.size).toBe(1);
    const rec = records.get(digest)!;
    expect(rec.tokenHash).toBe(digest);
    expect(JSON.stringify(rec)).not.toContain(refreshToken);
    expect(rec.claims).toEqual(CLAIMS);
    expect(rec.issuedAt).toBe(NOW);
    expect(rec.expiresAt).toBe(NOW + REFRESH_TOKEN_TTL_MS);
    expect(expiresAt).toBe(rec.expiresAt);
  });

  it("is opaque, base64url, at least 32 random bytes, and distinct per call", async () => {
    const { store } = fakeStore();
    const a = await issued(store);
    const b = await issued(store);
    expect(a.refreshToken).toMatch(/^[A-Za-z0-9_-]{43,}$/);
    expect(a.refreshToken).not.toBe(b.refreshToken);
  });

  it("defaults the TTL to 30 days and honours ttlMs", async () => {
    expect(REFRESH_TOKEN_TTL_MS).toBe(30 * 24 * 60 * 60 * 1000);
    const { store, records } = fakeStore();
    await issueRefreshToken(CLAIMS, {
      refreshStore: store,
      now: () => NOW,
      ttlMs: 1000,
    });
    expect([...records.values()][0]!.expiresAt).toBe(NOW + 1000);
  });

  it("starts a new family per issue unless one is given", async () => {
    const { store, records } = fakeStore();
    await issued(store);
    await issued(store);
    await issueRefreshToken(CLAIMS, { refreshStore: store, familyId: "fam-x" });
    const families = [...records.values()].map((r) => r.familyId);
    expect(families[0]).not.toBe(families[1]);
    expect(families[2]).toBe("fam-x");
  });
});

// ---------------------------------------------------------------------------
// exchangeRefreshToken
// ---------------------------------------------------------------------------

describe("exchangeRefreshToken", () => {
  const input = (refreshToken: string) => ({ refreshToken, clientId: CLIENT });

  it("rotates: returns the claims and a different token in the same family; the old one is consumed", async () => {
    const { store, records, used } = fakeStore();
    const first = await issued(store);
    const r = await exchangeRefreshToken(input(first.refreshToken), {
      refreshStore: store,
      now: () => NOW + 1000,
      reauthorize: allow,
    });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.claims).toEqual(CLAIMS);
    expect(r.refreshToken).not.toBe(first.refreshToken);
    expect(r.expiresAt).toBe(NOW + 1000 + REFRESH_TOKEN_TTL_MS);
    const oldRec = records.get(await sha256Hex(first.refreshToken))!;
    const newRec = records.get(await sha256Hex(r.refreshToken))!;
    expect(newRec.familyId).toBe(oldRec.familyId);
    expect(used.has(oldRec.tokenHash)).toBe(true);
    expect(used.has(newRec.tokenHash)).toBe(false);
    expect(JSON.stringify(newRec)).not.toContain(r.refreshToken);
  });

  it("the rotated token can itself be exchanged", async () => {
    const { store } = fakeStore();
    const first = await issued(store);
    const deps = { refreshStore: store, now: () => NOW, reauthorize: allow };
    const a = await exchangeRefreshToken(input(first.refreshToken), deps);
    if (!a.ok) throw new Error("setup");
    const b = await exchangeRefreshToken(input(a.refreshToken), deps);
    expect(b.ok).toBe(true);
  });

  it("replaying the old token is refresh-reused and revokes the family: the rotated token is then refused", async () => {
    const { store } = fakeStore();
    const first = await issued(store);
    const deps = { refreshStore: store, now: () => NOW, reauthorize: allow };
    const a = await exchangeRefreshToken(input(first.refreshToken), deps);
    if (!a.ok) throw new Error("setup");
    const replay = await exchangeRefreshToken(input(first.refreshToken), deps);
    expect(reasonOf(replay)).toBe("refresh-reused");
    const rotated = await exchangeRefreshToken(input(a.refreshToken), deps);
    expect(rotated.ok).toBe(false);
  });

  it("refuses refresh-reused even when revokeFamily throws", async () => {
    const { store } = fakeStore();
    const first = await issued(store);
    const deps = { now: () => NOW, reauthorize: allow };
    await exchangeRefreshToken(input(first.refreshToken), {
      ...deps,
      refreshStore: store,
    });
    const broken: RefreshTokenStore = {
      ...store,
      revokeFamily: async () => {
        throw new Error("down");
      },
    };
    const replay = await exchangeRefreshToken(input(first.refreshToken), {
      ...deps,
      refreshStore: broken,
    });
    expect(reasonOf(replay)).toBe("refresh-reused");
  });

  it("an unknown token is refresh-unknown", async () => {
    const { store } = fakeStore();
    const r = await exchangeRefreshToken(input("nope"), {
      refreshStore: store,
      reauthorize: allow,
    });
    expect(reasonOf(r)).toBe("refresh-unknown");
  });

  it("an empty or non-string token is refresh-unknown and never reaches the store", async () => {
    let calls = 0;
    const store: RefreshTokenStore = {
      put: async () => {},
      consume: async () => {
        calls++;
        return { status: "unknown" };
      },
      revokeFamily: async () => {},
    };
    for (const bad of ["", undefined as unknown as string, 42 as unknown as string]) {
      const r = await exchangeRefreshToken(
        { refreshToken: bad, clientId: CLIENT },
        { refreshStore: store, reauthorize: allow },
      );
      expect(reasonOf(r)).toBe("refresh-unknown");
    }
    expect(calls).toBe(0);
  });

  it("an expired token is refresh-expired", async () => {
    const { store } = fakeStore();
    const first = await issued(store);
    const r = await exchangeRefreshToken(input(first.refreshToken), {
      refreshStore: store,
      now: () => NOW + REFRESH_TOKEN_TTL_MS,
      reauthorize: allow,
    });
    expect(reasonOf(r)).toBe("refresh-expired");
  });

  it("another client's token is client-mismatch", async () => {
    const { store } = fakeStore();
    const first = await issued(store);
    const r = await exchangeRefreshToken(
      { refreshToken: first.refreshToken, clientId: "https://other.example.test/m.json" },
      { refreshStore: store, now: () => NOW, reauthorize: allow },
    );
    expect(reasonOf(r)).toBe("client-mismatch");
  });

  it("a resource other than the bound audience is resource-mismatch; the bound one passes", async () => {
    const { store } = fakeStore();
    const first = await issued(store);
    const deps = { refreshStore: store, now: () => NOW, reauthorize: allow };
    const bad = await exchangeRefreshToken(
      { ...input(first.refreshToken), resource: "https://evil.example.test/mcp" },
      deps,
    );
    expect(reasonOf(bad)).toBe("resource-mismatch");
    const second = await issued(store);
    const good = await exchangeRefreshToken(
      { ...input(second.refreshToken), resource: RESOURCE },
      deps,
    );
    expect(good.ok).toBe(true);
  });

  it("a store that throws is refresh-store-unavailable", async () => {
    const store: RefreshTokenStore = {
      put: async () => {},
      consume: async () => {
        throw new Error("down");
      },
      revokeFamily: async () => {},
    };
    const r = await exchangeRefreshToken(input("tok"), {
      refreshStore: store,
      reauthorize: allow,
    });
    expect(reasonOf(r)).toBe("refresh-store-unavailable");
  });

  it("reauthorize {ok:false} is refresh-reauthorization-failed and revokes the family", async () => {
    const { store, records, used } = fakeStore();
    const first = await issued(store);
    const r = await exchangeRefreshToken(input(first.refreshToken), {
      refreshStore: store,
      now: () => NOW,
      reauthorize: async () => ({ ok: false }),
    });
    expect(reasonOf(r)).toBe("refresh-reauthorization-failed");
    expect([...records.keys()].every((h) => used.has(h))).toBe(true);
  });

  it("a reauthorize that throws refuses with refresh-reauthorization-failed", async () => {
    const { store } = fakeStore();
    const first = await issued(store);
    const r = await exchangeRefreshToken(input(first.refreshToken), {
      refreshStore: store,
      now: () => NOW,
      reauthorize: async () => {
        throw new Error("clerk down");
      },
    });
    expect(reasonOf(r)).toBe("refresh-reauthorization-failed");
  });

  it("reauthorize receives the stored claims; a changed role is carried into the result and the new record", async () => {
    const { store, records } = fakeStore();
    const first = await issued(store);
    let seen: AuthorizedTokenClaims | undefined;
    const r = await exchangeRefreshToken(input(first.refreshToken), {
      refreshStore: store,
      now: () => NOW,
      reauthorize: async (claims) => {
        seen = claims;
        return { ok: true, claims: { ...claims, org_role: "org:admin" } };
      },
    });
    expect(seen).toEqual(CLAIMS);
    if (!r.ok) throw new Error("expected ok");
    expect(r.claims.org_role).toBe("org:admin");
    expect(records.get(await sha256Hex(r.refreshToken))!.claims.org_role).toBe(
      "org:admin",
    );
  });
});

// ---------------------------------------------------------------------------
// discovery + error mapping
// ---------------------------------------------------------------------------

describe("discovery and oauthErrorFor", () => {
  const cfg = {
    issuer: "https://mcp.example.test",
    authorizationEndpoint: "https://mcp.example.test/authorize",
    tokenEndpoint: "https://mcp.example.test/token",
    jwksUri: "https://mcp.example.test/jwks",
    userinfoEndpoint: "https://mcp.example.test/userinfo",
  };

  it("default grant_types_supported is unchanged", () => {
    const r = buildDiscoveryDocument(cfg);
    if (!r.ok) throw new Error("expected ok");
    expect(r.document.grant_types_supported).toEqual(["authorization_code"]);
  });

  it("refreshTokens: false is the default; true adds refresh_token", () => {
    const off = buildDiscoveryDocument({ ...cfg, refreshTokens: false });
    const on = buildDiscoveryDocument({ ...cfg, refreshTokens: true });
    if (!off.ok || !on.ok) throw new Error("expected ok");
    expect(off.document.grant_types_supported).toEqual(["authorization_code"]);
    expect(on.document.grant_types_supported).toEqual([
      "authorization_code",
      "refresh_token",
    ]);
  });

  const refusal = (reason: AuthorizeRefusalReason) =>
    ({ code: "AUTHORIZE_REFUSED", reason }) as const;

  it.each([
    "refresh-unknown",
    "refresh-reused",
    "refresh-expired",
    "refresh-reauthorization-failed",
  ] as const)("%s maps to invalid_grant 400", (reason) => {
    expect(oauthErrorFor(refusal(reason))).toEqual({
      error: "invalid_grant",
      status: 400,
    });
  });

  it("refresh-store-unavailable maps like code-store-unavailable", () => {
    expect(oauthErrorFor(refusal("refresh-store-unavailable"))).toEqual(
      oauthErrorFor(refusal("code-store-unavailable")),
    );
    expect(oauthErrorFor(refusal("refresh-store-unavailable")).status).toBe(503);
  });
});
