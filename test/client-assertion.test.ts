import { beforeAll, describe, expect, it } from "vitest";
import {
  ASSERTION_SIGNING_ALGS,
  type AssertionRefusalReason,
  type AssertionResult,
  type AssertionVerifierOptions,
  createClientAssertionVerifier,
  createJtiStore,
  JWT_BEARER_ASSERTION_TYPE,
} from "../src/client-assertion.js";

/**
 * private_key_jwt client authentication (RFC 7523 / OIDC Core 9), ported from the
 * boilerplate's `/token` suite ("CIMD client that authenticates with private_key_jwt") to the
 * verifier itself. Every refusal reason the verifier can return has its own pole; the valid
 * RS256 assertion is the positive control that proves each refusal is caused by the one thing
 * the case changes. Keys are generated in-process; nothing is read from disk, env or network.
 */

const ID = "https://chatgpt.com/oauth/client.json";
const JWKS_URI = "https://chatgpt.com/oauth/jwks.json";
const CB = "https://chatgpt.com/connector_platform_oauth_redirect";
const ISSUER = "https://mcp.example.com";
const TOKEN_URL = `${ISSUER}/token`;
const AUDIENCES = [TOKEN_URL, ISSUER];
const NOW_MS = 1_800_000_000_000;
const NOW_S = Math.floor(NOW_MS / 1000);

const baseDoc = {
  client_id: ID,
  client_name: "ChatGPT",
  redirect_uris: [CB],
  token_endpoint_auth_method: "private_key_jwt",
  token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
  token_endpoint_auth_signing_alg: "RS256",
  jwks_uri: JWKS_URI,
};

const b64u = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString("base64url");
const b64uJson = (v: unknown): string => b64u(new TextEncoder().encode(JSON.stringify(v)));

async function genRsa(modulusLength = 2048): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
}

let good: CryptoKeyPair;
let other: CryptoKeyPair;
let goodJwk: Record<string, unknown>;

beforeAll(async () => {
  good = await genRsa();
  other = await genRsa();
  goodJwk = {
    ...(await crypto.subtle.exportKey("jwk", good.publicKey)),
    kid: "gpt-1",
    alg: "RS256",
    use: "sig",
  };
  delete goodJwk.key_ops;
  delete goodJwk.ext;
});

interface MintOptions {
  key?: CryptoKey;
  header?: Record<string, unknown>;
  claims?: Record<string, unknown>;
  omit?: string[];
}

async function sign(header: Record<string, unknown>, payload: Record<string, unknown>, key: CryptoKey) {
  const h = b64uJson(header);
  const p = b64uJson(payload);
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    key,
    new TextEncoder().encode(`${h}.${p}`),
  );
  return `${h}.${p}.${b64u(new Uint8Array(sig))}`;
}

let jtiCounter = 0;
function payloadOf(o: MintOptions = {}): Record<string, unknown> {
  const p: Record<string, unknown> = {
    iss: ID,
    sub: ID,
    aud: TOKEN_URL,
    iat: NOW_S,
    exp: NOW_S + 120,
    jti: `jti-${++jtiCounter}`,
    ...o.claims,
  };
  for (const k of o.omit ?? []) delete p[k];
  return p;
}

async function assertion(o: MintOptions = {}): Promise<string> {
  return sign(
    { alg: "RS256", kid: "gpt-1", ...o.header },
    payloadOf(o),
    o.key ?? good.privateKey,
  );
}

async function hs256Assertion(): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode("s".repeat(32)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const h = b64uJson({ alg: "HS256", kid: "gpt-1" });
  const p = b64uJson(payloadOf());
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${h}.${p}`));
  return `${h}.${p}.${b64u(new Uint8Array(sig))}`;
}

interface Harness {
  doc?: Record<string, unknown>;
  jwks?: unknown;
  /** Raw JWKS body, when a test needs a body that is not JSON.stringify of `jwks`. */
  jwksBody?: BodyInit;
  hosts?: Record<string, string[]>;
  fetched?: string[];
  extra?: Partial<AssertionVerifierOptions>;
}

function verifier(h: Harness = {}) {
  const fetched = h.fetched ?? [];
  const doc = h.doc ?? baseDoc;
  const fetchImpl = (async (input: RequestInfo | URL) => {
    const u = String(input);
    fetched.push(u);
    if (u === ID) return Response.json(doc);
    if (u === doc.jwks_uri) {
      return new Response(h.jwksBody ?? JSON.stringify(h.jwks ?? { keys: [goodJwk] }));
    }
    return new Response("nope", { status: 404 });
  }) as unknown as typeof fetch;
  return createClientAssertionVerifier({
    fetchImpl,
    resolveHost: async (host: string) => h.hosts?.[host] ?? ["93.184.216.34"],
    now: () => NOW_MS,
    ...h.extra,
  });
}

const input = (jwt: string, clientId?: string) => ({
  assertionType: JWT_BEARER_ASSERTION_TYPE,
  assertion: jwt,
  ...(clientId !== undefined ? { clientId } : {}),
  audiences: AUDIENCES,
});

const refused = (reason: AssertionRefusalReason): AssertionResult => ({ ok: false, reason });

describe("constants", () => {
  it("accepts only the RFC 7523 jwt-bearer type, signed with RS256", () => {
    expect(JWT_BEARER_ASSERTION_TYPE).toBe(
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    );
    expect([...ASSERTION_SIGNING_ALGS]).toEqual(["RS256"]);
  });
});

describe("a valid RS256 assertion (positive control)", () => {
  it("is accepted with client_id sent", async () => {
    expect(await verifier().verify(input(await assertion(), ID))).toEqual({
      ok: true,
      clientId: ID,
    });
  });

  it("is accepted without client_id", async () => {
    expect(await verifier().verify(input(await assertion()))).toEqual({ ok: true, clientId: ID });
  });

  it("aud may be the issuer instead of the token endpoint", async () => {
    const jwt = await assertion({ claims: { aud: ISSUER } });
    expect(await verifier().verify(input(jwt))).toEqual({ ok: true, clientId: ID });
  });

  it("aud may be an array naming one of the audiences", async () => {
    const jwt = await assertion({ claims: { aud: ["https://elsewhere.example", TOKEN_URL] } });
    expect(await verifier().verify(input(jwt))).toEqual({ ok: true, clientId: ID });
  });

  it("a key without kid in the header is found among the RSA keys", async () => {
    const jwt = await sign({ alg: "RS256" }, payloadOf(), good.privateKey);
    expect(await verifier().verify(input(jwt))).toEqual({ ok: true, clientId: ID });
  });

  it("a key set with an unrelated key first still verifies against the right one", async () => {
    const otherJwk = { ...(await crypto.subtle.exportKey("jwk", other.publicKey)), kid: "x" };
    const jwt = await sign({ alg: "RS256" }, payloadOf(), good.privateKey);
    const v = verifier({ jwks: { keys: [otherJwk, goodJwk] } });
    expect(await v.verify(input(jwt))).toEqual({ ok: true, clientId: ID });
  });

  it("a CIMD that declares no signing alg is accepted (RS256 is still the only verify alg)", async () => {
    const { token_endpoint_auth_signing_alg: _omit, ...noAlg } = baseDoc;
    const v = verifier({ doc: noAlg });
    expect(await v.verify(input(await assertion()))).toEqual({ ok: true, clientId: ID });
  });

  it("exp inside the 30 s skew is still accepted", async () => {
    const jwt = await assertion({ claims: { exp: NOW_S - 29 } });
    expect(await verifier().verify(input(jwt))).toEqual({ ok: true, clientId: ID });
  });

  it("fetches the CIMD document, then the jwks_uri it names", async () => {
    const fetched: string[] = [];
    await verifier({ fetched }).verify(input(await assertion()));
    expect(fetched).toEqual([ID, JWKS_URI]);
  });
});

describe("refusal: unsupported client assertion", () => {
  it("a wrong assertion type", async () => {
    const out = await verifier().verify({
      ...input(await assertion(), ID),
      assertionType: "urn:bogus",
    });
    expect(out).toEqual(refused("unsupported client assertion"));
  });

  it("an absent assertion type", async () => {
    const out = await verifier().verify({
      assertionType: undefined,
      assertion: await assertion(),
      audiences: AUDIENCES,
    });
    expect(out).toEqual(refused("unsupported client assertion"));
  });

  it("an absent or empty assertion", async () => {
    for (const a of [undefined, ""]) {
      const out = await verifier().verify({
        assertionType: JWT_BEARER_ASSERTION_TYPE,
        assertion: a,
        audiences: AUDIENCES,
      });
      expect(out).toEqual(refused("unsupported client assertion"));
    }
  });
});

describe("refusal: malformed client assertion", () => {
  it.each([
    ["not a JWT", "not-a-jwt"],
    ["two segments", "a.b"],
    ["payload not JSON", `${b64uJson({ alg: "RS256" })}.${b64u(new TextEncoder().encode("{"))}.x`],
    ["payload an array", `${b64uJson({ alg: "RS256" })}.${b64uJson([1])}.x`],
  ])("%s", async (_name, jwt) => {
    expect(await verifier().verify(input(jwt))).toEqual(refused("malformed client assertion"));
  });
});

describe("refusal: unknown client", () => {
  it("iss absent", async () => {
    const jwt = await assertion({ omit: ["iss"] });
    expect(await verifier().verify(input(jwt))).toEqual(refused("unknown client"));
  });

  it("iss not URL-shaped (a DCR id has no CIMD to hold a key set)", async () => {
    const jwt = await assertion({ claims: { iss: "client_abc", sub: "client_abc" } });
    expect(await verifier().verify(input(jwt))).toEqual(refused("unknown client"));
  });

  it("iss not a string", async () => {
    const jwt = await assertion({ claims: { iss: 42 } });
    expect(await verifier().verify(input(jwt))).toEqual(refused("unknown client"));
  });
});

describe("refusal: client_id does not match the assertion issuer", () => {
  it("a sent client_id that differs from iss", async () => {
    const out = await verifier().verify(input(await assertion(), "https://other.example.com/c.json"));
    expect(out).toEqual(refused("client_id does not match the assertion issuer"));
  });

  it("fetches nothing before refusing", async () => {
    const fetched: string[] = [];
    await verifier({ fetched }).verify(input(await assertion(), "https://other.example.com/c.json"));
    expect(fetched).toEqual([]);
  });
});

describe("refusal: client has no verifiable key set", () => {
  it("the CIMD document declares no jwks_uri", async () => {
    const { jwks_uri: _omit, ...noJwks } = baseDoc;
    const out = await verifier({ doc: noJwks }).verify(input(await assertion()));
    expect(out).toEqual(refused("client has no verifiable key set"));
  });

  it("the CIMD document names another client_id", async () => {
    const out = await verifier({ doc: { ...baseDoc, client_id: "https://evil.example.com/c.json" } })
      .verify(input(await assertion()));
    expect(out).toEqual(refused("client has no verifiable key set"));
  });

  it("the CIMD host resolves to a private address (SSRF)", async () => {
    const fetched: string[] = [];
    const out = await verifier({ fetched, hosts: { "chatgpt.com": ["10.0.0.5"] } }).verify(
      input(await assertion()),
    );
    expect(out).toEqual(refused("client has no verifiable key set"));
    expect(fetched).toEqual([]);
  });

  it("an http (non-https) client_id", async () => {
    const httpId = "http://chatgpt.com/oauth/client.json";
    const jwt = await assertion({ claims: { iss: httpId, sub: httpId } });
    expect(await verifier().verify(input(jwt))).toEqual(refused("client has no verifiable key set"));
  });
});

describe("refusal: unsupported signing algorithm", () => {
  it.each(["HS256", "ES256", "none", "PS256"])(
    "a CIMD declaring token_endpoint_auth_signing_alg %s",
    async (alg) => {
      const fetched: string[] = [];
      const out = await verifier({
        fetched,
        doc: { ...baseDoc, token_endpoint_auth_signing_alg: alg },
      }).verify(input(await assertion()));
      expect(out).toEqual(refused("unsupported signing algorithm"));
      expect(fetched).toEqual([ID]); // the key set is never fetched
    },
  );
});

describe("refusal: invalid jwks_uri", () => {
  it("a jwks_uri that is not a URL", async () => {
    const out = await verifier({ doc: { ...baseDoc, jwks_uri: "not a url" } }).verify(
      input(await assertion()),
    );
    expect(out).toEqual(refused("invalid jwks_uri"));
  });
});

describe("refusal: key set unavailable (SSRF-guarded jwks_uri)", () => {
  const keysHost = "keys.example.net";
  const keysUri = `https://${keysHost}/jwks.json`;

  it.each([
    ["RFC 1918", ["10.0.0.5"]],
    ["loopback", ["127.0.0.1"]],
    ["cloud metadata", ["169.254.169.254"]],
    ["hex-mapped loopback", ["::ffff:7f00:1"]],
    ["one public and one private record", ["93.184.216.34", "192.168.1.1"]],
    ["no record", []],
  ])("the jwks_uri host resolves to %s: never fetched", async (_name, addrs) => {
    const fetched: string[] = [];
    const out = await verifier({
      fetched,
      doc: { ...baseDoc, jwks_uri: keysUri },
      hosts: { [keysHost]: addrs },
    }).verify(input(await assertion()));
    expect(out).toEqual(refused("key set unavailable"));
    expect(fetched).toEqual([ID]);
  });

  it("the same jwks_uri on a public address is accepted (positive control)", async () => {
    const out = await verifier({
      doc: { ...baseDoc, jwks_uri: keysUri },
      hosts: { [keysHost]: ["93.184.216.34"] },
    }).verify(input(await assertion()));
    expect(out).toEqual({ ok: true, clientId: ID });
  });

  it.each([
    ["localhost", "https://localhost/jwks.json"],
    ["a loopback literal", "https://127.0.0.1/jwks.json"],
    ["a private literal", "https://10.0.0.1/jwks.json"],
    ["a hex-mapped metadata literal", "https://[::ffff:a9fe:a9fe]/jwks.json"],
    ["non-https", "http://chatgpt.com/oauth/jwks.json"],
    ["credentials in the URL", "https://u:p@chatgpt.com/oauth/jwks.json"],
    ["a fragment", "https://chatgpt.com/oauth/jwks.json#k"],
  ])("a jwks_uri on %s is refused without a fetch", async (_name, uri) => {
    const fetched: string[] = [];
    const out = await verifier({
      fetched,
      doc: { ...baseDoc, jwks_uri: uri },
      // "localhost" is resolved like any host: it answers loopback, as DNS would.
      hosts: { localhost: ["127.0.0.1"] },
    }).verify(input(await assertion()));
    expect(out).toEqual(refused("key set unavailable"));
    expect(fetched).toEqual([ID]);
  });

  it("a key set document over 64 KiB is refused", async () => {
    const big = JSON.stringify({ keys: [goodJwk], pad: "x".repeat(64 * 1024) });
    const out = await verifier({ jwksBody: big }).verify(input(await assertion()));
    expect(out).toEqual(refused("key set unavailable"));
  });

  it("a key set just under 64 KiB is accepted (the cap is 64 KiB, not the CIMD default)", async () => {
    const body = JSON.stringify({ keys: [goodJwk], pad: "" });
    const padded = JSON.stringify({
      keys: [goodJwk],
      pad: "x".repeat(64 * 1024 - body.length - 1),
    });
    expect(Buffer.byteLength(padded)).toBeLessThanOrEqual(64 * 1024);
    const out = await verifier({ jwksBody: padded }).verify(input(await assertion()));
    expect(out).toEqual({ ok: true, clientId: ID });
  });

  it("a key set that is not JSON, or has no keys array, is refused", async () => {
    for (const body of ["not json", JSON.stringify({ keys: "nope" }), JSON.stringify([goodJwk])]) {
      const out = await verifier({ jwksBody: body }).verify(input(await assertion()));
      expect(out).toEqual(refused("key set unavailable"));
    }
  });
});

describe("refusal: client assertion rejected", () => {
  const cases: Array<[string, () => Promise<string>]> = [
    ["wrong aud", () => assertion({ claims: { aud: "https://evil.example.com/token" } })],
    ["wrong iss (sub kept)", () =>
      assertion({ claims: { iss: "https://chatgpt.com/oauth/other.json" } })],
    ["iss != sub", () => assertion({ claims: { sub: "https://evil.example.com/c.json" } })],
    ["expired", () => assertion({ claims: { exp: NOW_S - 3600 } })],
    ["expired just past the 30 s skew", () => assertion({ claims: { exp: NOW_S - 30 } })],
    ["exp not a number", () => assertion({ claims: { exp: "soon" } })],
    ["nbf in the future past the skew", () => assertion({ claims: { nbf: NOW_S + 3600 } })],
    ["iat not a number", () => assertion({ claims: { iat: "now" } })],
    ["wrong key", () => assertion({ key: other.privateKey })],
    ["HS256", () => hs256Assertion()],
    ["missing jti", () => assertion({ omit: ["jti"] })],
    ["a numeric jti", () => assertion({ claims: { jti: 7 } })],
    ["missing exp", () => assertion({ omit: ["exp"] })],
    ["missing sub", () => assertion({ omit: ["sub"] })],
    ["missing aud", () => assertion({ omit: ["aud"] })],
    ["kid not in the key set", () => assertion({ header: { kid: "unknown" } })],
    ["a crit header", () => assertion({ header: { crit: ["exp"] } })],
    ["a tampered payload", async () => {
      const [h, , s] = (await assertion()).split(".");
      return `${h}.${b64uJson(payloadOf({ claims: { aud: ISSUER } }))}.${s}`;
    }],
    ["alg none", async () => `${b64uJson({ alg: "none" })}.${b64uJson(payloadOf())}.`],
  ];

  it.each(cases)("%s", async (name, make) => {
    // A changing iss needs a CIMD under that iss: only the "wrong iss" case changes it, and
    // its document does not exist (404), so it is refused one step earlier. Every other case
    // keeps iss = ID and reaches signature verification.
    const jwt = await make();
    const out = await verifier().verify(input(jwt));
    expect(out.ok).toBe(false);
    if (name.startsWith("wrong iss")) {
      expect(out).toEqual(refused("client has no verifiable key set"));
    } else {
      expect(out).toEqual(refused("client assertion rejected"));
    }
  });

  it("an RSA key under 2048 bits is refused even with a valid signature", async () => {
    const weak = await genRsa(1024);
    const weakJwk = { ...(await crypto.subtle.exportKey("jwk", weak.publicKey)), kid: "gpt-1" };
    const jwt = await assertion({ key: weak.privateKey });
    const out = await verifier({ jwks: { keys: [weakJwk] } }).verify(input(jwt));
    expect(out).toEqual(refused("client assertion rejected"));
  });

  it("a key whose use is not sig, or whose alg is not RS256, is not a candidate", async () => {
    for (const patch of [{ use: "enc" }, { alg: "RS512" }, { kty: "EC" }]) {
      const out = await verifier({ jwks: { keys: [{ ...goodJwk, ...patch }] } }).verify(
        input(await assertion()),
      );
      expect(out).toEqual(refused("client assertion rejected"));
    }
  });

  it("an empty key set is refused", async () => {
    const out = await verifier({ jwks: { keys: [] } }).verify(input(await assertion()));
    expect(out).toEqual(refused("client assertion rejected"));
  });
});

describe("refusal: client assertion replayed", () => {
  it("the same jti is accepted ONCE", async () => {
    const v = verifier();
    const jwt = await assertion({ claims: { jti: "replay-1" } });
    expect(await v.verify(input(jwt))).toEqual({ ok: true, clientId: ID });
    expect(await v.verify(input(jwt))).toEqual(refused("client assertion replayed"));
  });

  it("a fresh assertion carrying a used jti is a replay too", async () => {
    const v = verifier();
    await v.verify(input(await assertion({ claims: { jti: "j-same" } })));
    const again = await assertion({ claims: { jti: "j-same", iat: NOW_S + 1 } });
    expect(await v.verify(input(again))).toEqual(refused("client assertion replayed"));
  });

  it("a shared injected store refuses a replay across two verifiers", async () => {
    const jtiStore = createJtiStore();
    const jwt = await assertion({ claims: { jti: "shared-1" } });
    expect(await verifier({ extra: { jtiStore } }).verify(input(jwt))).toEqual({
      ok: true,
      clientId: ID,
    });
    expect(await verifier({ extra: { jtiStore } }).verify(input(jwt))).toEqual(
      refused("client assertion replayed"),
    );
  });

  it("an empty jti is never accepted (answered as a replay, as the boilerplate does)", async () => {
    const jwt = await assertion({ claims: { jti: "" } });
    expect(await verifier().verify(input(jwt))).toEqual(refused("client assertion replayed"));
  });

  it("a full store fails closed (a NEW jti is refused, never accepted by evicting)", async () => {
    const jtiStore = createJtiStore(1);
    const v = verifier({ extra: { jtiStore } });
    expect(await v.verify(input(await assertion()))).toEqual({ ok: true, clientId: ID });
    expect(await v.verify(input(await assertion()))).toEqual(refused("client assertion replayed"));
  });
});

describe("createJtiStore", () => {
  it("accepts a new jti once, then refuses it", () => {
    const s = createJtiStore();
    expect(s.accept("c", "j", NOW_S + 60, NOW_S)).toBe(true);
    expect(s.accept("c", "j", NOW_S + 60, NOW_S)).toBe(false);
  });

  it("keys by client: the same jti from another client is a different entry", () => {
    const s = createJtiStore();
    expect(s.accept("c1", "j", NOW_S + 60, NOW_S)).toBe(true);
    expect(s.accept("c2", "j", NOW_S + 60, NOW_S)).toBe(true);
  });

  it("holds a jti until exp + 30 s skew, then prunes it", () => {
    const s = createJtiStore();
    expect(s.accept("c", "j", NOW_S + 60, NOW_S)).toBe(true);
    expect(s.accept("c", "j", NOW_S + 60, NOW_S + 89)).toBe(false); // still live
    expect(s.accept("c", "j", NOW_S + 60, NOW_S + 90)).toBe(true); // pruned, then new
  });

  it("when full, refuses a new jti and never evicts a live one", () => {
    const s = createJtiStore(2);
    expect(s.accept("c", "a", NOW_S + 60, NOW_S)).toBe(true);
    expect(s.accept("c", "b", NOW_S + 60, NOW_S)).toBe(true);
    expect(s.accept("c", "x", NOW_S + 60, NOW_S)).toBe(false); // full: fail closed
    expect(s.accept("c", "a", NOW_S + 60, NOW_S)).toBe(false); // "a" still held
  });

  it("an expired entry frees its slot", () => {
    const s = createJtiStore(1);
    expect(s.accept("c", "a", NOW_S + 10, NOW_S)).toBe(true);
    expect(s.accept("c", "b", NOW_S + 60, NOW_S + 40)).toBe(true);
  });
});

describe("assertion lifetime cap (task k1734g39kq2dv007zm6n4bgne58hfzpr)", () => {
  // The cap is 300 s past now, plus the 30 s skew: exp = now + 330 is the last accepted second.
  const YEAR = 365 * 24 * 3600;

  it("an otherwise valid assertion with exp one year ahead is rejected", async () => {
    const jwt = await assertion({ claims: { exp: NOW_S + YEAR } });
    expect(await verifier().verify(input(jwt))).toEqual(refused("client assertion rejected"));
  });

  it("exp = now + 60 s is accepted", async () => {
    const jwt = await assertion({ claims: { exp: NOW_S + 60 } });
    expect(await verifier().verify(input(jwt))).toEqual({ ok: true, clientId: ID });
  });

  it("exp = now + 300 + 30 (the boundary) is accepted", async () => {
    const jwt = await assertion({ claims: { exp: NOW_S + 300 + 30 } });
    expect(await verifier().verify(input(jwt))).toEqual({ ok: true, clientId: ID });
  });

  it("exp = now + 300 + 30 + 1 (one second past the boundary) is rejected", async () => {
    const jwt = await assertion({ claims: { exp: NOW_S + 300 + 30 + 1 } });
    expect(await verifier().verify(input(jwt))).toEqual(refused("client assertion rejected"));
  });

  it("iat in the future past the 30 s skew is rejected", async () => {
    const jwt = await assertion({ claims: { iat: NOW_S + 31 } });
    expect(await verifier().verify(input(jwt))).toEqual(refused("client assertion rejected"));
  });

  it("iat in the future inside the 30 s skew is accepted", async () => {
    const jwt = await assertion({ claims: { iat: NOW_S + 30 } });
    expect(await verifier().verify(input(jwt))).toEqual({ ok: true, clientId: ID });
  });

  it("far-future assertions never reach the store, so they cannot fill it", async () => {
    // The store is shrunk from 10000 to 3 so the flood is cheap to sign; the logic is the same.
    const inner = createJtiStore(3);
    let accepted = 0;
    const jtiStore = {
      accept(c: string, j: string, e: number, n: number) {
        const ok = inner.accept(c, j, e, n);
        if (ok) accepted++;
        return ok;
      },
    };
    const v = verifier({ extra: { jtiStore } });
    for (let i = 0; i < 5; i++) {
      const jwt = await assertion({ claims: { exp: NOW_S + YEAR } });
      expect(await v.verify(input(jwt))).toEqual(refused("client assertion rejected"));
    }
    expect(accepted).toBe(0);
    // A legitimate client is still served after the flood.
    expect(await v.verify(input(await assertion()))).toEqual({ ok: true, clientId: ID });
  });

  it("a store filled with maximum-lifetime assertions frees itself 360 s later", async () => {
    let t = NOW_MS;
    const jtiStore = createJtiStore(2);
    const v = verifier({ extra: { jtiStore, now: () => t } });
    for (let i = 0; i < 2; i++) {
      const jwt = await assertion({ claims: { exp: NOW_S + 330 } });
      expect(await v.verify(input(jwt))).toEqual({ ok: true, clientId: ID });
    }
    expect(await v.verify(input(await assertion()))).toEqual(refused("client assertion replayed"));
    t = NOW_MS + 360 * 1000;
    const late = await assertion({ claims: { iat: NOW_S + 360, exp: NOW_S + 420 } });
    expect(await v.verify(input(late))).toEqual({ ok: true, clientId: ID });
  });
});
