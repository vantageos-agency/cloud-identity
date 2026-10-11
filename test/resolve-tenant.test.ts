import { beforeAll, describe, expect, it } from "vitest";
import {
  resolveTenantFromAccessToken,
  type McpResourceServerConfig,
  type ClerkJwks,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Fixtures: keys are generated in-process; nothing is read from disk or env.
// ---------------------------------------------------------------------------

const ISSUER = "https://mcp.example.test";
const OTHER_ISSUER = "https://evil.example.test";
const AUDIENCE = "https://mcp.example.test/mcp";
const OTHER_AUDIENCE = "https://other.example.test/mcp";
const PRM_URL = "https://mcp.example.test/.well-known/oauth-protected-resource";
const NOW = 1_800_000_000_000;
const NOW_S = NOW / 1000;

const b64u = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64uJson = (v: unknown) => b64u(new TextEncoder().encode(JSON.stringify(v)));

let keyA: CryptoKeyPair;
let keyB: CryptoKeyPair;
let jwks: ClerkJwks;

const genKey = () =>
  crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  );

async function mint(claims: Record<string, unknown> = {}, key: CryptoKey = keyA.privateKey): Promise<string> {
  const h = b64uJson({ alg: "RS256", kid: "k1", typ: "at+jwt" });
  const p = b64uJson({
    iss: ISSUER,
    aud: AUDIENCE,
    sub: "user_1",
    org_id: "org_ABC123",
    org_slug: "acme",
    org_role: "org:admin",
    exp: NOW_S + 300,
    nbf: NOW_S - 10,
    ...claims,
  });
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, new TextEncoder().encode(`${h}.${p}`));
  return `${h}.${p}.${b64u(new Uint8Array(sig))}`;
}

beforeAll(async () => {
  keyA = await genKey();
  keyB = await genKey();
  const pub = (await crypto.subtle.exportKey("jwk", keyA.publicKey)) as { n: string; e: string };
  jwks = { keys: [{ kty: "RSA", kid: "k1", n: pub.n, e: pub.e, alg: "RS256", use: "sig" }] };
});

const cfg = (over: Partial<McpResourceServerConfig> = {}): McpResourceServerConfig => ({
  realm: "mcp",
  resourceMetadataUrl: PRM_URL,
  jwks,
  issuer: ISSUER,
  audience: AUDIENCE,
  ...over,
});
const bearer = (t: string) => `Bearer ${t}`;

describe("resolveTenantFromAccessToken: a verified token resolves to principal and org", () => {
  it("returns the principal and the org id of a verified access token", async () => {
    const out = await resolveTenantFromAccessToken(bearer(await mint()), cfg(), NOW);
    expect(out).toEqual({
      ok: true,
      orgId: "org_ABC123",
      principal: { subject: "user_1", actorName: "user:user_1", role: "org:admin" },
    });
  });

  it("a verified token with no role claim still resolves, role is null", async () => {
    const out = await resolveTenantFromAccessToken(bearer(await mint({ org_role: undefined })), cfg(), NOW);
    expect(out).toMatchObject({ ok: true, principal: { role: null } });
  });
});

describe("resolveTenantFromAccessToken: an unverified token never yields a tenant", () => {
  const cases: Array<[string, () => Promise<string | undefined>, Partial<McpResourceServerConfig>]> = [
    ["forged (signed by another key)", async () => bearer(await mint({}, keyB.privateKey)), {}],
    ["expired", async () => bearer(await mint({ exp: NOW_S - 3600 })), {}],
    ["wrong audience", async () => bearer(await mint({ aud: OTHER_AUDIENCE })), {}],
    ["wrong issuer", async () => bearer(await mint({ iss: OTHER_ISSUER })), {}],
  ];
  for (const [label, header, over] of cases) {
    it(`${label}: refused with token-invalid, a 401 challenge, no orgId, no principal`, async () => {
      const out = await resolveTenantFromAccessToken(await header(), cfg(over), NOW);
      expect(out).toMatchObject({ ok: false, status: 401, refusal: { code: "CREDENTIAL_REFUSED", reason: "token-invalid" } });
      expect(out).not.toHaveProperty("orgId");
      expect(out).not.toHaveProperty("principal");
      expect((out as { headers: Record<string, string> }).headers["WWW-Authenticate"]).toContain("resource_metadata");
    });
  }

  it("a forged token naming a victim's org is refused, the claim is never read", async () => {
    const out = await resolveTenantFromAccessToken(bearer(await mint({ org_id: "org_VICTIM" }, keyB.privateKey)), cfg(), NOW);
    expect(out.ok).toBe(false);
    expect(out).not.toHaveProperty("orgId");
  });

  it("no Authorization header: refused with bearer-missing", async () => {
    const out = await resolveTenantFromAccessToken(undefined, cfg(), NOW);
    expect(out).toMatchObject({ ok: false, status: 401, refusal: { reason: "bearer-missing" } });
  });

  it("a malformed header: refused with bearer-malformed", async () => {
    const out = await resolveTenantFromAccessToken("Basic abc", cfg(), NOW);
    expect(out).toMatchObject({ ok: false, status: 401, refusal: { reason: "bearer-malformed" } });
  });

  it("an unreachable key set: 503 jwks-unavailable, an outage is not a bad credential", async () => {
    const out = await resolveTenantFromAccessToken(
      bearer(await mint()),
      cfg({ jwks: async () => { throw new Error("down"); } }),
      NOW,
    );
    expect(out).toMatchObject({ ok: false, status: 503, refusal: { reason: "jwks-unavailable" } });
  });
});

describe("resolveTenantFromAccessToken: the org claim", () => {
  for (const [label, claims] of [
    ["absent", { org_id: undefined }],
    ["empty", { org_id: "" }],
    ["not a string", { org_id: 42 }],
    ["not shaped like an org id", { org_id: "acme" }],
  ] as const) {
    it(`a verified token whose org_id is ${label} fails typed with no-verified-organisation`, async () => {
      const out = await resolveTenantFromAccessToken(bearer(await mint(claims)), cfg(), NOW);
      expect(out).toMatchObject({
        ok: false,
        status: 403,
        refusal: { code: "RBAC_DENIED", reason: "no-verified-organisation" },
      });
      expect(out).not.toHaveProperty("orgId");
    });
  }

  it("a slug alone never rescues a missing org id", async () => {
    const out = await resolveTenantFromAccessToken(bearer(await mint({ org_id: undefined, org_slug: "org_ABC123" })), cfg(), NOW);
    expect(out).toMatchObject({ ok: false, refusal: { reason: "no-verified-organisation" } });
  });

  it("the door is carried on every refusal", async () => {
    const out = await resolveTenantFromAccessToken(bearer(await mint({ org_id: undefined })), cfg({ door: "tenancy" }), NOW);
    expect(out).toMatchObject({ ok: false, refusal: { door: "tenancy" } });
  });

  it("the token never appears in a result", async () => {
    const t = await mint({ org_id: undefined });
    expect(JSON.stringify(await resolveTenantFromAccessToken(bearer(t), cfg(), NOW))).not.toContain(t);
  });
});
