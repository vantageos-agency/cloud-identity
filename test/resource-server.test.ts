import { beforeAll, describe, expect, it } from "vitest";
import {
  buildProtectedResourceMetadata,
  deriveClerkDiscoveryUrls,
  unauthorizedChallenge,
  verifyMcpAccessToken,
  type McpResourceServerConfig,
} from "../src/resource-server.js";
import type { ClerkJwks } from "../src/clerk-session.js";

// ---------------------------------------------------------------------------
// Fixtures: keys are generated in-process; nothing is read from disk or env.
// ---------------------------------------------------------------------------

const ISSUER = "https://tenant-a.clerk.accounts.dev";
const OTHER_ISSUER = "https://tenant-b.clerk.accounts.dev";
const AUDIENCE = "https://mcp.tenant-a.example.com/mcp";
const OTHER_AUDIENCE = "https://mcp.tenant-b.example.com/mcp";
const PRM_URL = "https://mcp.tenant-a.example.com/.well-known/oauth-protected-resource";
const NOW = 1_800_000_000_000;
const NOW_S = NOW / 1000;

const b64u = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const b64uJson = (v: unknown) => b64u(new TextEncoder().encode(JSON.stringify(v)));

let keyA: CryptoKeyPair;
let keyB: CryptoKeyPair;
let jwks: ClerkJwks;

async function genKey(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
}

async function mint(
  claims: Record<string, unknown> = {},
  header: Record<string, unknown> = {},
  key: CryptoKey = keyA.privateKey,
): Promise<string> {
  const h = b64uJson({ alg: "RS256", kid: "k1", typ: "JWT", ...header });
  const p = b64uJson({
    iss: ISSUER,
    aud: AUDIENCE,
    sub: "user_1",
    exp: NOW_S + 300,
    nbf: NOW_S - 10,
    ...claims,
  });
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(`${h}.${p}`),
  );
  return `${h}.${p}.${b64u(new Uint8Array(sig))}`;
}

beforeAll(async () => {
  keyA = await genKey();
  keyB = await genKey();
  const pub = (await crypto.subtle.exportKey("jwk", keyA.publicKey)) as {
    n: string;
    e: string;
  };
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

// ---------------------------------------------------------------------------
// RFC 9728 Protected Resource Metadata
// ---------------------------------------------------------------------------

describe("buildProtectedResourceMetadata", () => {
  it("builds the RFC 9728 document with header bearer transport by default", () => {
    expect(
      buildProtectedResourceMetadata({
        resource: "https://mcp.tenant-a.example.com",
        authorizationServers: [ISSUER],
      }),
    ).toEqual({
      resource: "https://mcp.tenant-a.example.com",
      authorization_servers: [ISSUER],
      bearer_methods_supported: ["header"],
    });
  });

  it("carries the optional fields when given", () => {
    const doc = buildProtectedResourceMetadata({
      resource: AUDIENCE,
      authorizationServers: [ISSUER],
      scopesSupported: ["mcp:read", "mcp:write"],
      resourceName: "Tenant A MCP",
      resourceDocumentation: "https://docs.example.com/mcp",
      bearerMethodsSupported: ["header"],
    });
    expect(doc.scopes_supported).toEqual(["mcp:read", "mcp:write"]);
    expect(doc.resource_name).toBe("Tenant A MCP");
    expect(doc.resource_documentation).toBe("https://docs.example.com/mcp");
  });

  it("omits optional fields that were not given", () => {
    const doc = buildProtectedResourceMetadata({
      resource: AUDIENCE,
      authorizationServers: [ISSUER],
    });
    expect(Object.keys(doc).sort()).toEqual([
      "authorization_servers",
      "bearer_methods_supported",
      "resource",
    ]);
  });

  it("does not alias the caller's arrays", () => {
    const servers = [ISSUER];
    const doc = buildProtectedResourceMetadata({
      resource: AUDIENCE,
      authorizationServers: servers,
    });
    servers.push("https://evil.example.com");
    expect(doc.authorization_servers).toEqual([ISSUER]);
  });

  it.each([
    ["empty resource", { resource: "", authorizationServers: [ISSUER] }],
    ["relative resource", { resource: "/mcp", authorizationServers: [ISSUER] }],
    ["resource with a fragment", { resource: `${AUDIENCE}#x`, authorizationServers: [ISSUER] }],
    ["no authorization server", { resource: AUDIENCE, authorizationServers: [] }],
    ["relative authorization server", { resource: AUDIENCE, authorizationServers: ["clerk"] }],
    [
      "empty bearer methods",
      { resource: AUDIENCE, authorizationServers: [ISSUER], bearerMethodsSupported: [] },
    ],
  ])("throws on %s", (_name, config) => {
    expect(() => buildProtectedResourceMetadata(config)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// RFC 6750 / RFC 9728 challenge
// ---------------------------------------------------------------------------

describe("unauthorizedChallenge", () => {
  it("answers 401 with resource_metadata in WWW-Authenticate", () => {
    const r = unauthorizedChallenge({ realm: "mcp", resourceMetadataUrl: PRM_URL });
    expect(r.status).toBe(401);
    expect(r.headers["WWW-Authenticate"]).toBe(
      `Bearer realm="mcp", resource_metadata="${PRM_URL}"`,
    );
  });

  it("appends error, error_description and scope when given", () => {
    const h = unauthorizedChallenge({
      realm: "mcp",
      resourceMetadataUrl: PRM_URL,
      error: "invalid_token",
      errorDescription: "token rejected",
      scope: "mcp:read",
    }).headers["WWW-Authenticate"];
    expect(h).toContain('error="invalid_token"');
    expect(h).toContain('error_description="token rejected"');
    expect(h).toContain('scope="mcp:read"');
  });

  it("escapes quotes and backslashes so a value cannot inject a parameter", () => {
    const h = unauthorizedChallenge({
      realm: "mcp",
      resourceMetadataUrl: PRM_URL,
      errorDescription: 'x", error="none',
    }).headers["WWW-Authenticate"];
    expect(h).toContain('error_description="x\\", error=\\"none"');
    expect(h.match(/error="/g)).toBeNull();
  });

  it.each([
    ["empty realm", { realm: "", resourceMetadataUrl: PRM_URL }],
    ["empty resourceMetadataUrl", { realm: "mcp", resourceMetadataUrl: "" }],
    ["relative resourceMetadataUrl", { realm: "mcp", resourceMetadataUrl: "/.well-known/x" }],
    [
      "line break in a value",
      { realm: "mcp", resourceMetadataUrl: PRM_URL, errorDescription: "a\r\nSet-Cookie: x=1" },
    ],
  ])("throws on %s", (_name, config) => {
    expect(() => unauthorizedChallenge(config)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Discovery URLs
// ---------------------------------------------------------------------------

describe("deriveClerkDiscoveryUrls", () => {
  it("derives the OIDC discovery and JWKS URLs", () => {
    expect(deriveClerkDiscoveryUrls(ISSUER)).toEqual({
      discoveryUrl: `${ISSUER}/.well-known/openid-configuration`,
      jwksUrl: `${ISSUER}/.well-known/jwks.json`,
    });
  });

  it("strips one trailing slash", () => {
    expect(deriveClerkDiscoveryUrls(`${ISSUER}/`).jwksUrl).toBe(
      `${ISSUER}/.well-known/jwks.json`,
    );
  });

  it.each([["empty", ""], ["not a URL", "not-a-url"], ["http", "http://tenant-a.clerk.accounts.dev"]])(
    "throws on %s",
    (_n, issuer) => {
      expect(() => deriveClerkDiscoveryUrls(issuer)).toThrow();
    },
  );
});

// ---------------------------------------------------------------------------
// Access-token verification: every refusal bipolar, with a positive control
// ---------------------------------------------------------------------------

describe("verifyMcpAccessToken", () => {
  it("POSITIVE CONTROL: a correctly bound token is accepted", async () => {
    const r = await verifyMcpAccessToken(`Bearer ${await mint({ org: "org_a" })}`, cfg(), NOW);
    expect(r.ok).toBe(true);
    if (r.ok) {
      expect(r.session.userId).toBe("user_1");
      expect(r.session.claims.org).toBe("org_a");
    }
  });

  it("accepts an audience array that contains the resource", async () => {
    const r = await verifyMcpAccessToken(
      `Bearer ${await mint({ aud: [OTHER_AUDIENCE, AUDIENCE] })}`,
      cfg(),
      NOW,
    );
    expect(r.ok).toBe(true);
  });

  it("matches the Bearer scheme case-insensitively", async () => {
    const r = await verifyMcpAccessToken(`bearer ${await mint()}`, cfg(), NOW);
    expect(r.ok).toBe(true);
  });

  function expectChallenge(
    r: Awaited<ReturnType<typeof verifyMcpAccessToken>>,
    reason: string,
    error: string,
  ) {
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.status).toBe(401);
    if (r.status !== 401) return;
    expect(r.refusal).toMatchObject({ code: "CREDENTIAL_REFUSED", reason });
    expect(r.headers["WWW-Authenticate"]).toContain(`resource_metadata="${PRM_URL}"`);
    expect(r.headers["WWW-Authenticate"]).toContain(`error="${error}"`);
  }

  it("refuses no Authorization header: invalid_request", async () => {
    expectChallenge(await verifyMcpAccessToken(undefined, cfg(), NOW), "bearer-missing", "invalid_request");
    expectChallenge(await verifyMcpAccessToken("", cfg(), NOW), "bearer-missing", "invalid_request");
  });

  it("refuses a malformed header: invalid_request", async () => {
    expectChallenge(await verifyMcpAccessToken("Basic abc", cfg(), NOW), "bearer-malformed", "invalid_request");
    expectChallenge(await verifyMcpAccessToken("Bearer", cfg(), NOW), "bearer-malformed", "invalid_request");
    expectChallenge(await verifyMcpAccessToken("Bearer    ", cfg(), NOW), "bearer-malformed", "invalid_request");
  });

  it("refuses a token that is not a JWT: invalid_token", async () => {
    expectChallenge(await verifyMcpAccessToken("Bearer not.a.jwt", cfg(), NOW), "token-invalid", "invalid_token");
  });

  it("refuses a wrong audience (token minted for another resource)", async () => {
    const t = await mint({ aud: OTHER_AUDIENCE });
    expectChallenge(await verifyMcpAccessToken(`Bearer ${t}`, cfg(), NOW), "token-invalid", "invalid_token");
  });

  it("refuses a token with no audience at all", async () => {
    const t = await mint({ aud: undefined });
    expectChallenge(await verifyMcpAccessToken(`Bearer ${t}`, cfg(), NOW), "token-invalid", "invalid_token");
  });

  it("refuses a wrong issuer", async () => {
    const t = await mint({ iss: OTHER_ISSUER });
    expectChallenge(await verifyMcpAccessToken(`Bearer ${t}`, cfg(), NOW), "token-invalid", "invalid_token");
  });

  it("refuses an expired token", async () => {
    const t = await mint({ exp: NOW_S - 3600 });
    expectChallenge(await verifyMcpAccessToken(`Bearer ${t}`, cfg(), NOW), "token-invalid", "invalid_token");
  });

  it("refuses a token that is not yet valid (nbf)", async () => {
    const t = await mint({ nbf: NOW_S + 3600 });
    expectChallenge(await verifyMcpAccessToken(`Bearer ${t}`, cfg(), NOW), "token-invalid", "invalid_token");
  });

  it("refuses a token signed by another key", async () => {
    const t = await mint({}, {}, keyB.privateKey);
    expectChallenge(await verifyMcpAccessToken(`Bearer ${t}`, cfg(), NOW), "token-invalid", "invalid_token");
  });

  it("refuses a tampered signature", async () => {
    const t = await mint();
    const [h, p, s] = t.split(".") as [string, string, string];
    const bad = `${h}.${p}.${s.slice(0, -2)}${s.endsWith("AA") ? "BB" : "AA"}`;
    expectChallenge(await verifyMcpAccessToken(`Bearer ${bad}`, cfg(), NOW), "token-invalid", "invalid_token");
  });

  it("refuses alg none and HS256 (algorithm confusion)", async () => {
    const claims = b64uJson({ iss: ISSUER, aud: AUDIENCE, sub: "u", exp: NOW_S + 300 });
    const none = `${b64uJson({ alg: "none", kid: "k1" })}.${claims}.`;
    expectChallenge(await verifyMcpAccessToken(`Bearer ${none}`, cfg(), NOW), "token-invalid", "invalid_token");
    const hs = `${b64uJson({ alg: "HS256", kid: "k1" })}.${claims}.${b64u(new Uint8Array([1, 2, 3]))}`;
    expectChallenge(await verifyMcpAccessToken(`Bearer ${hs}`, cfg(), NOW), "token-invalid", "invalid_token");
  });

  it("answers 503 with no credential challenge when the key set is unreachable", async () => {
    const r = await verifyMcpAccessToken(
      `Bearer ${await mint()}`,
      cfg({ jwks: async () => { throw new Error("down"); } }),
      NOW,
    );
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.status).toBe(503);
      expect(r.refusal).toMatchObject({ code: "CREDENTIAL_REFUSED", reason: "jwks-unavailable" });
      expect("headers" in r).toBe(false);
    }
  });

  it("names the configured door in every refusal", async () => {
    const r = await verifyMcpAccessToken(undefined, cfg({ door: "mcp-edge" }), NOW);
    expect(!r.ok && r.refusal.door).toBe("mcp-edge");
  });

  it.each([
    ["issuer", { issuer: "" }],
    ["audience", { audience: "" }],
    ["audience (undefined)", { audience: undefined as unknown as string }],
    ["realm", { realm: "" }],
    ["resourceMetadataUrl", { resourceMetadataUrl: "" }],
  ])("throws a config error, never skips the check, when %s is missing", async (_n, over) => {
    await expect(
      verifyMcpAccessToken(`Bearer ${await mint()}`, cfg(over), NOW),
    ).rejects.toThrow();
  });

  it("never echoes the token in a refusal or a header", async () => {
    const t = await mint({ aud: OTHER_AUDIENCE });
    const r = await verifyMcpAccessToken(`Bearer ${t}`, cfg(), NOW);
    expect(JSON.stringify(r)).not.toContain(t);
  });
});
