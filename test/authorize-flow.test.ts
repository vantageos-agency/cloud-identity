import { beforeAll, describe, expect, it } from "vitest";
import {
  type AuthorizationCodeRecord,
  type AuthorizationCodeStore,
  type AuthorizeConfig,
  type AuthorizeDeps,
  type ClerkOrgMembership,
  type ClerkJwks,
  buildDiscoveryDocument,
  buildUserInfo,
  exchangeAuthorizationCode,
  oauthErrorFor,
  pkceChallengeFromVerifier,
  resumeAuthorize,
  sha256Hex,
  startAuthorize,
  verifyClerkSessionToken,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ISSUER = "https://clerk.example.test";
const RESOURCE = "https://mcp.example.test/mcp";
const REDIRECT = "https://client.example.test/cb";
const NOW = 1_800_000_000_000;
const VERIFIER = "v".repeat(50);

const b64u = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const b64uJson = (v: unknown) => b64u(new TextEncoder().encode(JSON.stringify(v)));

let privateKey: CryptoKey;
let jwks: ClerkJwks;

async function mintSession(
  claims: Record<string, unknown> = {},
  header: Record<string, unknown> = {},
  key: CryptoKey = privateKey,
): Promise<string> {
  const h = b64uJson({ alg: "RS256", kid: "k1", typ: "JWT", ...header });
  const p = b64uJson({
    iss: ISSUER,
    sub: "user_1",
    sid: "sess_1",
    exp: NOW / 1000 + 300,
    nbf: NOW / 1000 - 10,
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
  const pair = await crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256",
    },
    true,
    ["sign", "verify"],
  );
  privateKey = pair.privateKey;
  const pub = await crypto.subtle.exportKey("jwk", pair.publicKey);
  jwks = { keys: [{ kty: "RSA", kid: "k1", n: pub.n, e: pub.e, alg: "RS256" }] };
});

function memStore(): AuthorizationCodeStore & {
  rows: Map<string, { rec: AuthorizationCodeRecord; used: boolean }>;
} {
  const rows = new Map<string, { rec: AuthorizationCodeRecord; used: boolean }>();
  return {
    rows,
    async put(rec) {
      rows.set(rec.codeHash, { rec, used: false });
    },
    async consume(hash) {
      const row = rows.get(hash);
      if (!row) return { status: "unknown" };
      if (row.used) return { status: "already-used" };
      row.used = true;
      return { status: "ok", record: row.rec };
    },
  };
}

const orgA: ClerkOrgMembership = {
  role: "org:admin",
  organization: { id: "org_A", slug: "acme", name: "Acme" },
};
const orgB: ClerkOrgMembership = {
  role: "org:member",
  organization: { id: "org_B", slug: "beta", name: "Beta" },
};

function setup(memberships: readonly ClerkOrgMembership[], over: Partial<AuthorizeConfig> = {}) {
  const store = memStore();
  const cfg: AuthorizeConfig = {
    stateSecret: "s".repeat(40),
    signInUrl: `${ISSUER}/sign-in`,
    callbackUrl: "https://mcp.example.test/authorize/callback",
    allowedResources: [RESOURCE],
    session: { issuer: ISSUER, jwks },
    // fixtures auto-pick; the consent-default tests remove this key
    requireConsent: false,
    ...over,
  };
  let n = 0;
  const deps: AuthorizeDeps = {
    lookupClient: async (id) =>
      id === "client_1"
        ? {
            clientId: "client_1",
            redirectUris: [REDIRECT],
            clientName: "Claude",
          }
        : null,
    listMemberships: async () => memberships,
    codeStore: store,
    now: () => NOW,
    generateCode: () => `code-${++n}`,
  };
  return { cfg, deps, store };
}

async function params(over: Record<string, string | undefined> = {}) {
  return {
    client_id: "client_1",
    redirect_uri: REDIRECT,
    response_type: "code",
    state: "client-state",
    code_challenge: await pkceChallengeFromVerifier(VERIFIER),
    code_challenge_method: ["S", "256"].join(""),
    resource: RESOURCE,
    scope: "openid email",
    ...over,
  };
}

const stateOf = (url: string) =>
  new URL(
    new URL(url).searchParams.get("redirect_url") as string,
  ).searchParams.get("authorize_state") as string;

async function exchange(deps: AuthorizeDeps, code: string, over = {}) {
  return exchangeAuthorizationCode(
    {
      code,
      codeVerifier: VERIFIER,
      redirectUri: REDIRECT,
      clientId: "client_1",
      ...over,
    },
    { codeStore: deps.codeStore, now: deps.now },
  );
}

// ---------------------------------------------------------------------------
// Authorize flow
// ---------------------------------------------------------------------------

describe("startAuthorize", () => {
  it("without a Clerk session redirects to sign-in with a signed state and issues no code", async () => {
    const { cfg, deps, store } = setup([orgA]);
    const out = await startAuthorize(await params(), undefined, cfg, deps);
    expect(out.kind).toBe("redirect-to-sign-in");
    if (out.kind !== "redirect-to-sign-in") return;
    expect(out.url.startsWith(`${ISSUER}/sign-in?`)).toBe(true);
    expect(stateOf(out.url)).toMatch(/^[\w-]+\.[\w-]+$/);
    expect(store.rows.size).toBe(0);
  });

  it("a forged or expired session token is treated as no session", async () => {
    const { cfg, deps, store } = setup([orgA]);
    const expired = await mintSession({ exp: NOW / 1000 - 3600 });
    const out = await startAuthorize(await params(), expired, cfg, deps);
    expect(out.kind).toBe("redirect-to-sign-in");
    expect(store.rows.size).toBe(0);
  });

  it("an unreachable key set is a refusal, not a redirect and not a grant", async () => {
    const { cfg, deps, store } = setup([orgA], {
      session: {
        issuer: ISSUER,
        jwks: async () => {
          throw new Error("down");
        },
      },
    });
    const out = await startAuthorize(await params(), await mintSession(), cfg, deps);
    expect(out).toEqual({
      kind: "refused",
      refusal: { code: "AUTHORIZE_REFUSED", reason: "jwks-unavailable" },
    });
    expect(store.rows.size).toBe(0);
  });

  it("with a session and exactly one organisation, auto-picks it and binds the code", async () => {
    const { cfg, deps, store } = setup([orgA], { requireConsent: false });
    const out = await startAuthorize(await params(), await mintSession(), cfg, deps);
    expect(out.kind).toBe("redirect-to-client");
    if (out.kind !== "redirect-to-client") return;
    const u = new URL(out.url);
    expect(u.origin + u.pathname).toBe(REDIRECT);
    expect(u.searchParams.get("code")).toBe("code-1");
    expect(u.searchParams.get("state")).toBe("client-state");
    const rec = [...store.rows.values()][0]?.rec;
    expect(rec).toMatchObject({
      clerkUserId: "user_1",
      orgId: "org_A",
      orgSlug: "acme",
      orgRole: "org:admin",
      clientId: "client_1",
      redirectUri: REDIRECT,
      resource: RESOURCE,
    });
    // only the digest is stored, never the code
    expect(rec?.codeHash).toBe(await sha256Hex("code-1"));
    expect(JSON.stringify(rec)).not.toContain('"code-1"');
  });

  it.each([
    ["unknown client", { client_id: "nope" }, "unknown-client"],
    ["unregistered redirect_uri", { redirect_uri: "https://evil.test/cb" }, "redirect-uri-mismatch"],
    ["prefix of a registered redirect_uri", { redirect_uri: `${REDIRECT}/x` }, "redirect-uri-mismatch"],
    ["missing code_challenge", { code_challenge: undefined }, "pkce-required"],
    ["plain method", { code_challenge_method: "plain" }, "pkce-required"],
    ["resource not allowed", { resource: "https://other.test/mcp" }, "resource-not-allowed"],
    ["missing resource", { resource: undefined }, "resource-not-allowed"],
    ["response_type token", { response_type: "token" }, "unsupported-response-type"],
  ])("refuses %s", async (_n, over, reason) => {
    const { cfg, deps, store } = setup([orgA]);
    const out = await startAuthorize(await params(over), await mintSession(), cfg, deps);
    expect(out).toEqual({
      kind: "refused",
      refusal: { code: "AUTHORIZE_REFUSED", reason },
    });
    expect(store.rows.size).toBe(0);
  });

  it("a user with no organisation gets no code", async () => {
    const { cfg, deps, store } = setup([]);
    const out = await startAuthorize(await params(), await mintSession(), cfg, deps);
    expect(out).toMatchObject({ kind: "refused", refusal: { reason: "no-organization" } });
    expect(store.rows.size).toBe(0);
  });

  it("a membership lookup that throws is a refusal, never a grant", async () => {
    const { cfg, deps, store } = setup([orgA]);
    deps.listMemberships = async () => {
      throw new Error("clerk 500");
    };
    const out = await startAuthorize(await params(), await mintSession(), cfg, deps);
    expect(out).toMatchObject({
      kind: "refused",
      refusal: { reason: "membership-lookup-unavailable" },
    });
    expect(store.rows.size).toBe(0);
  });

  it("a short state secret fails closed", async () => {
    const { cfg, deps } = setup([orgA], { stateSecret: "short" });
    const out = await startAuthorize(await params(), undefined, cfg, deps);
    expect(out).toMatchObject({ kind: "refused", refusal: { reason: "server-misconfigured" } });
  });
});

describe("resumeAuthorize", () => {
  async function stateFor(cfg: AuthorizeConfig, deps: AuthorizeDeps) {
    const out = await startAuthorize(await params(), undefined, cfg, deps);
    if (out.kind !== "redirect-to-sign-in") throw new Error("setup");
    return stateOf(out.url);
  }

  it("on return with a session, one organisation -> code bound to that organisation", async () => {
    const { cfg, deps, store } = setup([orgB]);
    const state = await stateFor(cfg, deps);
    const out = await resumeAuthorize({ state, sessionToken: await mintSession() }, cfg, deps);
    expect(out.kind).toBe("redirect-to-client");
    expect([...store.rows.values()][0]?.rec.orgId).toBe("org_B");
  });

  it("two organisations -> a picker listing only the user's organisations, no code yet", async () => {
    const { cfg, deps, store } = setup([orgA, orgB]);
    const state = await stateFor(cfg, deps);
    const out = await resumeAuthorize({ state, sessionToken: await mintSession() }, cfg, deps);
    expect(out.kind).toBe("org-picker");
    if (out.kind !== "org-picker") return;
    expect(out.model.organizations.map((o) => o.id)).toEqual(["org_A", "org_B"]);
    expect(out.model.client.clientName).toBe("Claude");
    expect(out.model.state).toBe(state);
    expect(store.rows.size).toBe(0);
  });

  it("the chosen organisation is honoured when the user belongs to it", async () => {
    const { cfg, deps, store } = setup([orgA, orgB]);
    const state = await stateFor(cfg, deps);
    const out = await resumeAuthorize(
      { state, sessionToken: await mintSession(), orgId: "org_B" },
      cfg,
      deps,
    );
    expect(out.kind).toBe("redirect-to-client");
    expect([...store.rows.values()][0]?.rec).toMatchObject({ orgId: "org_B", orgRole: "org:member" });
  });

  it("a forged orgId (the user is not a member) is refused, with one or many memberships", async () => {
    for (const memberships of [[orgA], [orgA, orgB]]) {
      const { cfg, deps, store } = setup(memberships);
      const state = await stateFor(cfg, deps);
      const out = await resumeAuthorize(
        { state, sessionToken: await mintSession(), orgId: "org_FORGED" },
        cfg,
        deps,
      );
      expect(out).toMatchObject({ kind: "refused", refusal: { reason: "org-not-a-member" } });
      expect(store.rows.size).toBe(0);
    }
  });

  it("a tampered state is refused", async () => {
    const { cfg, deps, store } = setup([orgA]);
    const state = await stateFor(cfg, deps);
    const [body, mac] = state.split(".") as [string, string];
    const payload = JSON.parse(atob(body.replace(/-/g, "+").replace(/_/g, "/")));
    payload.ru = "https://evil.test/cb";
    const forged = `${b64uJson(payload)}.${mac}`;
    for (const bad of [forged, `${body}.${"A".repeat(mac.length)}`, "garbage", ""]) {
      const out = await resumeAuthorize({ state: bad, sessionToken: await mintSession() }, cfg, deps);
      expect(out).toMatchObject({ kind: "refused", refusal: { reason: "state-invalid" } });
    }
    expect(store.rows.size).toBe(0);
  });

  it("a state signed with another secret is refused", async () => {
    const a = setup([orgA]);
    const b = setup([orgA], { stateSecret: "z".repeat(40) });
    const state = await stateFor(a.cfg, a.deps);
    const out = await resumeAuthorize({ state, sessionToken: await mintSession() }, b.cfg, b.deps);
    expect(out).toMatchObject({ kind: "refused", refusal: { reason: "state-invalid" } });
  });

  it("an expired state is refused", async () => {
    const { cfg, deps, store } = setup([orgA]);
    const state = await stateFor(cfg, deps);
    deps.now = () => NOW + 601_000;
    const out = await resumeAuthorize({ state, sessionToken: await mintSession() }, cfg, deps);
    expect(out).toMatchObject({ kind: "refused", refusal: { reason: "state-expired" } });
    expect(store.rows.size).toBe(0);
  });

  it("no session on return, or a forged one, is refused", async () => {
    const { cfg, deps, store } = setup([orgA]);
    const state = await stateFor(cfg, deps);
    expect(await resumeAuthorize({ state, sessionToken: undefined }, cfg, deps)).toMatchObject({
      refusal: { reason: "session-required" },
    });
    const other = await crypto.subtle.generateKey(
      { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
      true,
      ["sign", "verify"],
    );
    const forged = await mintSession({}, {}, other.privateKey);
    expect(await resumeAuthorize({ state, sessionToken: forged }, cfg, deps)).toMatchObject({
      refusal: { reason: "session-invalid" },
    });
    expect(store.rows.size).toBe(0);
  });

  it("a client revoked mid-flow gets no code", async () => {
    const { cfg, deps, store } = setup([orgA]);
    const state = await stateFor(cfg, deps);
    deps.lookupClient = async () => ({ clientId: "client_1", redirectUris: [REDIRECT], revoked: true });
    const out = await resumeAuthorize({ state, sessionToken: await mintSession() }, cfg, deps);
    expect(out).toMatchObject({ refusal: { reason: "unknown-client" } });
    expect(store.rows.size).toBe(0);
  });

  it("requireConsent: one organisation still needs explicit approval", async () => {
    const { cfg, deps, store } = setup([orgA], { requireConsent: true });
    const out = await startAuthorize(await params(), await mintSession(), cfg, deps);
    expect(out.kind).toBe("org-picker");
    if (out.kind !== "org-picker") return;
    expect(out.model.consentRequired).toBe(true);
    expect(store.rows.size).toBe(0);
    const approved = await resumeAuthorize(
      {
        state: out.model.state,
        sessionToken: await mintSession(),
        orgId: "org_A",
        approved: true,
        consentToken: out.model.consentToken ?? undefined,
      },
      cfg,
      deps,
    );
    expect(approved.kind).toBe("redirect-to-client");
  });

  it("a code-store failure is a refusal", async () => {
    const { cfg, deps } = setup([orgA]);
    deps.codeStore = {
      put: async () => {
        throw new Error("convex down");
      },
      consume: async () => ({ status: "unknown" }),
    };
    const out = await startAuthorize(await params(), await mintSession(), cfg, deps);
    expect(out).toMatchObject({ refusal: { reason: "code-store-unavailable" } });
  });
});

// ---------------------------------------------------------------------------
// Token exchange
// ---------------------------------------------------------------------------

describe("exchangeAuthorizationCode", () => {
  async function issued(memberships = [orgA]) {
    const s = setup(memberships);
    const out = await startAuthorize(await params(), await mintSession(), s.cfg, s.deps);
    if (out.kind !== "redirect-to-client") throw new Error("setup");
    return { ...s, code: new URL(out.url).searchParams.get("code") as string };
  }

  it("returns claims carrying the user and the organisation, and never a scopeProfile", async () => {
    const { deps, code } = await issued();
    const res = await exchange(deps, code);
    expect(res).toEqual({
      ok: true,
      claims: {
        sub: "user_1",
        org_id: "org_A",
        org_slug: "acme",
        org_role: "org:admin",
        aud: RESOURCE,
        client_id: "client_1",
        scope: "openid email",
      },
    });
    if (res.ok) expect(Object.keys(res.claims)).not.toContain("scopeProfile");
  });

  it("a code is single-use: the second redemption is refused as reuse", async () => {
    const { deps, code } = await issued();
    expect((await exchange(deps, code)).ok).toBe(true);
    expect(await exchange(deps, code)).toEqual({
      ok: false,
      refusal: { code: "AUTHORIZE_REFUSED", reason: "code-reused" },
    });
  });

  it("an unknown code is refused", async () => {
    const { deps } = await issued();
    expect(await exchange(deps, "nope")).toMatchObject({ refusal: { reason: "code-unknown" } });
  });

  it("an expired code is refused", async () => {
    const { deps, code } = await issued();
    deps.now = () => NOW + 61_000;
    expect(await exchange(deps, code)).toMatchObject({ refusal: { reason: "code-expired" } });
  });

  it("a PKCE mismatch is refused, and burns the code", async () => {
    const { deps, code } = await issued();
    const wrong = await exchange(deps, code, { codeVerifier: "w".repeat(50) });
    expect(wrong).toMatchObject({ ok: false, refusal: { reason: "pkce-mismatch" } });
    expect(await exchange(deps, code)).toMatchObject({ refusal: { reason: "code-reused" } });
  });

  it("a malformed verifier is refused", async () => {
    const { deps, code } = await issued();
    expect(await exchange(deps, code, { codeVerifier: "short" })).toMatchObject({
      refusal: { reason: "verifier-malformed" },
    });
  });

  it("a resource mismatch is refused; an omitted resource uses the bound one", async () => {
    const a = await issued();
    expect(await exchange(a.deps, a.code, { resource: "https://other.test/mcp" })).toMatchObject({
      refusal: { reason: "resource-mismatch" },
    });
    const b = await issued();
    const ok = await exchange(b.deps, b.code, { resource: RESOURCE });
    expect(ok.ok).toBe(true);
  });

  it("a different redirect_uri or client is refused", async () => {
    const a = await issued();
    expect(await exchange(a.deps, a.code, { redirectUri: "https://evil.test/cb" })).toMatchObject({
      refusal: { reason: "redirect-uri-changed" },
    });
    const b = await issued();
    expect(await exchange(b.deps, b.code, { clientId: "client_2" })).toMatchObject({
      refusal: { reason: "client-mismatch" },
    });
  });

  it("a store that throws on consume is a refusal", async () => {
    const res = await exchangeAuthorizationCode(
      { code: "x", codeVerifier: VERIFIER, redirectUri: REDIRECT, clientId: "client_1" },
      {
        codeStore: {
          put: async () => undefined,
          consume: async () => {
            throw new Error("down");
          },
        },
      },
    );
    expect(res).toMatchObject({ refusal: { reason: "code-store-unavailable" } });
  });

  it("the org chosen in the picker travels to the claims", async () => {
    const s = setup([orgA, orgB]);
    const out = await startAuthorize(await params(), await mintSession(), s.cfg, s.deps);
    if (out.kind !== "org-picker") throw new Error("setup");
    const done = await resumeAuthorize(
      { state: out.model.state, sessionToken: await mintSession(), orgId: "org_B" },
      s.cfg,
      s.deps,
    );
    if (done.kind !== "redirect-to-client") throw new Error("setup");
    const res = await exchange(s.deps, new URL(done.url).searchParams.get("code") as string);
    expect(res).toMatchObject({ ok: true, claims: { org_id: "org_B", org_role: "org:member" } });
  });
});

// ---------------------------------------------------------------------------
// Clerk session verifier
// ---------------------------------------------------------------------------

describe("verifyClerkSessionToken", () => {
  const cfg = () => ({ issuer: ISSUER, jwks });
  it("accepts a valid token", async () => {
    const r = await verifyClerkSessionToken(await mintSession(), cfg(), NOW);
    expect(r).toMatchObject({ ok: true, session: { userId: "user_1", sessionId: "sess_1" } });
  });
  it.each([
    ["wrong issuer", { iss: "https://evil.test" }, {}],
    ["expired", { exp: NOW / 1000 - 60 }, {}],
    ["not yet valid", { nbf: NOW / 1000 + 600 }, {}],
    ["no subject", { sub: "" }, {}],
    ["alg none", {}, { alg: "none" }],
    ["alg HS256", {}, { alg: "HS256" }],
    ["unknown kid", {}, { kid: "zzz" }],
  ])("refuses %s", async (_n, claims, header) => {
    const r = await verifyClerkSessionToken(await mintSession(claims, header), cfg(), NOW);
    expect(r).toMatchObject({ ok: false, refusal: { reason: "session-invalid" } });
  });
  it("refuses a tampered payload", async () => {
    const t = (await mintSession()).split(".");
    t[1] = b64uJson({ iss: ISSUER, sub: "user_2", exp: NOW / 1000 + 300 });
    const r = await verifyClerkSessionToken(t.join("."), cfg(), NOW);
    expect(r).toMatchObject({ ok: false });
  });
  it("enforces audience and authorized parties when configured", async () => {
    const t = await mintSession({ aud: "a1", azp: "https://app.test" });
    expect((await verifyClerkSessionToken(t, { ...cfg(), audience: "a1" }, NOW)).ok).toBe(true);
    expect((await verifyClerkSessionToken(t, { ...cfg(), audience: "a2" }, NOW)).ok).toBe(false);
    expect((await verifyClerkSessionToken(t, { ...cfg(), authorizedParties: ["https://app.test"] }, NOW)).ok).toBe(true);
    expect((await verifyClerkSessionToken(t, { ...cfg(), authorizedParties: ["https://x.test"] }, NOW)).ok).toBe(false);
  });
  it("garbage is refused", async () => {
    for (const t of ["", "a.b", "a.b.c", "..."]) {
      expect((await verifyClerkSessionToken(t, cfg(), NOW)).ok).toBe(false);
    }
  });
});

// ---------------------------------------------------------------------------
// OIDC
// ---------------------------------------------------------------------------

describe("buildDiscoveryDocument", () => {
  const base = {
    issuer: "https://mcp.example.test",
    authorizationEndpoint: "https://mcp.example.test/authorize",
    tokenEndpoint: "https://mcp.example.test/token",
    jwksUri: "https://mcp.example.test/jwks",
    userinfoEndpoint: "https://mcp.example.test/userinfo",
  };
  it("advertises only what is implemented", () => {
    const r = buildDiscoveryDocument(base);
    if (!r.ok) throw new Error("setup");
    expect(r.document.grant_types_supported).toEqual(["authorization_code"]);
    for (const k of [
      "id_token_signing_alg_values_supported",
      "token_endpoint_auth_methods_supported",
    ]) {
      expect(Object.keys(r.document)).not.toContain(k);
    }
  });
  it("builds a document that requires PKCE and code flow", () => {
    const r = buildDiscoveryDocument({ ...base, registrationEndpoint: "https://mcp.example.test/register" });
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.document).toMatchObject({
      issuer: base.issuer,
      response_types_supported: ["code"],
      code_challenge_methods_supported: [["S", "256"].join("")],
      subject_types_supported: ["public"],
      registration_endpoint: "https://mcp.example.test/register",
    });
  });
  it("refuses a non-https issuer, an issuer with a query, and a relative endpoint", () => {
    for (const over of [
      { issuer: "http://mcp.example.test" },
      { issuer: "https://mcp.example.test/?x=1" },
      { tokenEndpoint: "/token" },
    ]) {
      expect(buildDiscoveryDocument({ ...base, ...over })).toEqual({
        ok: false,
        refusal: { code: "AUTHORIZE_REFUSED", reason: "issuer-invalid" },
      });
    }
  });
});

describe("buildUserInfo", () => {
  const user = {
    id: "user_1",
    primaryEmailAddressId: "e2",
    emailAddresses: [
      { id: "e1", emailAddress: "other@x.test", verification: { status: "verified" } },
      { id: "e2", emailAddress: "me@x.test", verification: { status: "verified" } },
    ],
  };
  it("returns sub, email and email_verified for openid email", () => {
    expect(buildUserInfo({ sub: "user_1", scope: "openid email" }, user)).toEqual({
      ok: true,
      userinfo: { sub: "user_1", email: "me@x.test", email_verified: true },
    });
  });
  it("openid alone returns only sub", () => {
    expect(buildUserInfo({ sub: "user_1", scope: "openid" }, user)).toEqual({
      ok: true,
      userinfo: { sub: "user_1" },
    });
  });
  it("an unverified primary address is email_verified false", () => {
    const u = { ...user, emailAddresses: [{ id: "e2", emailAddress: "me@x.test", verification: { status: "unverified" } }] };
    expect(buildUserInfo({ sub: "user_1", scope: "openid email" }, u)).toMatchObject({
      userinfo: { email_verified: false },
    });
  });
  it("refuses without openid and for another user's record", () => {
    expect(buildUserInfo({ sub: "user_1", scope: "email" }, user)).toMatchObject({
      refusal: { reason: "openid-scope-required" },
    });
    expect(buildUserInfo({ sub: "user_9", scope: "openid" }, user)).toMatchObject({
      refusal: { reason: "subject-mismatch" },
    });
  });
});

describe("oauthErrorFor", () => {
  it("maps retryable failures to 503 and grant failures to invalid_grant", () => {
    expect(oauthErrorFor({ code: "AUTHORIZE_REFUSED", reason: "code-store-unavailable" }).status).toBe(503);
    expect(oauthErrorFor({ code: "AUTHORIZE_REFUSED", reason: "pkce-mismatch" }).error).toBe("invalid_grant");
    expect(oauthErrorFor({ code: "AUTHORIZE_REFUSED", reason: "resource-mismatch" }).error).toBe("invalid_target");
  });
});

describe("consent is the default", () => {
  it("default config, one organisation: consent model, never a code without approval", async () => {
    const { cfg, deps, store } = setup([orgA]);
    delete cfg.requireConsent;
    const out = await startAuthorize(await params(), await mintSession(), cfg, deps);
    expect(out.kind).toBe("org-picker");
    if (out.kind !== "org-picker") return;
    expect(out.model.consentRequired).toBe(true);
    expect(store.rows.size).toBe(0);
    const again = await resumeAuthorize(
      { state: out.model.state, sessionToken: await mintSession(), orgId: "org_A" },
      cfg,
      deps,
    );
    expect(again.kind).toBe("org-picker");
    expect(store.rows.size).toBe(0);
  });

  it("explicit requireConsent: false auto-picks the single organisation", async () => {
    const { cfg, deps } = setup([orgA], { requireConsent: false });
    const out = await startAuthorize(await params(), await mintSession(), cfg, deps);
    expect(out.kind).toBe("redirect-to-client");
  });

  it("auto-pick binds exactly the single listed membership, with its role", async () => {
    const { cfg, deps, store } = setup([orgA], { requireConsent: false });
    const out = await startAuthorize(await params(), await mintSession(), cfg, deps);
    expect(out.kind).toBe("redirect-to-client");
    expect([...store.rows.values()][0]?.rec).toMatchObject({ orgId: "org_A", orgSlug: "acme", orgRole: "org:admin" });
  });
});

describe("consent cannot be minted by the client", () => {
  const consentSetup = () => setup([orgA, orgB], { requireConsent: true });
  const stateFor = async (cfg: AuthorizeConfig, deps: AuthorizeDeps, over = {}) => {
    const out = await startAuthorize(await params(over), undefined, cfg, deps);
    if (out.kind !== "redirect-to-sign-in") throw new Error("setup");
    return stateOf(out.url);
  };
  const picker = async (cfg: AuthorizeConfig, deps: AuthorizeDeps, session: string) => {
    const out = await startAuthorize(await params(), session, cfg, deps);
    if (out.kind !== "org-picker") throw new Error("setup");
    return out.model;
  };

  it("Eta's attack: attacker state + victim session + approved:true, no token -> refused, no code", async () => {
    const { cfg, deps, store } = consentSetup();
    const attackerState = await stateFor(cfg, deps);
    const victim = await mintSession({ sub: "victim" });
    for (const consentToken of [undefined, "forged", ""]) {
      const out = await resumeAuthorize(
        { state: attackerState, sessionToken: victim, orgId: "org_A", approved: true, consentToken },
        cfg,
        deps,
      );
      expect(out).toMatchObject({ kind: "refused", refusal: { reason: "consent-required" } });
    }
    expect(store.rows.size).toBe(0);
  });

  it("also refused with a single organisation", async () => {
    const { cfg, deps, store } = setup([orgA], { requireConsent: true });
    const attackerState = await stateFor(cfg, deps);
    const out = await resumeAuthorize(
      { state: attackerState, sessionToken: await mintSession(), orgId: "org_A", approved: true },
      cfg,
      deps,
    );
    expect(out).toMatchObject({ refusal: { reason: "consent-required" } });
    expect(store.rows.size).toBe(0);
  });

  it("legitimate flow: picker -> token -> resume -> code", async () => {
    const { cfg, deps, store } = consentSetup();
    const session = await mintSession();
    const model = await picker(cfg, deps, session);
    expect(model.consentToken).toMatch(/^[\w-]{43}$/);
    const out = await resumeAuthorize(
      { state: model.state, sessionToken: session, orgId: "org_B", approved: true, consentToken: model.consentToken ?? undefined },
      cfg,
      deps,
    );
    expect(out.kind).toBe("redirect-to-client");
    expect([...store.rows.values()][0]?.rec.orgId).toBe("org_B");
  });

  it("a token minted for user A is refused under user B's session", async () => {
    const { cfg, deps, store } = consentSetup();
    const modelA = await picker(cfg, deps, await mintSession({ sub: "user_A" }));
    const out = await resumeAuthorize(
      { state: modelA.state, sessionToken: await mintSession({ sub: "user_B" }), orgId: "org_A", approved: true, consentToken: modelA.consentToken ?? undefined },
      cfg,
      deps,
    );
    expect(out).toMatchObject({ refusal: { reason: "consent-required" } });
    expect(store.rows.size).toBe(0);
  });

  it("a token for state S1 is refused with state S2", async () => {
    const { cfg, deps, store } = consentSetup();
    const session = await mintSession();
    const m1 = await picker(cfg, deps, session);
    const s2 = await stateFor(cfg, deps, { state: "other" });
    const out = await resumeAuthorize(
      { state: s2, sessionToken: session, orgId: "org_A", approved: true, consentToken: m1.consentToken ?? undefined },
      cfg,
      deps,
    );
    expect(out).toMatchObject({ refusal: { reason: "consent-required" } });
    expect(store.rows.size).toBe(0);
  });

  it("a token minted for a different organisation set is refused", async () => {
    const a = setup([orgA, orgB], { requireConsent: true });
    const session = await mintSession();
    const model = await picker(a.cfg, a.deps, session);
    a.deps.listMemberships = async () => [orgA];
    const out = await resumeAuthorize(
      { state: model.state, sessionToken: session, orgId: "org_A", approved: true, consentToken: model.consentToken ?? undefined },
      a.cfg,
      a.deps,
    );
    expect(out).toMatchObject({ refusal: { reason: "consent-required" } });
  });
});
