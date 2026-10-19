import { beforeAll, describe, expect, it } from "vitest";
import {
  AUTHORIZE_ENV,
  DEFAULT_AUTHORIZE_SCOPE,
  buildAuthorizeRuntime,
  codeStoreFrom,
  createClerkDirectory,
  createClerkJwksSource,
  createInMemoryCodeStore,
  pickerContentSecurityPolicy,
  readAuthorizeSettings,
  renderOrgPicker,
  type AuthorizeSettings,
} from "../src/authorize-runtime.js";
import {
  type AuthorizationCodeRecord,
  type ClerkJwks,
  type ClerkOrgMembership,
  type OrgPickerModel,
  exchangeAuthorizationCode,
  pkceChallengeFromVerifier,
  resumeAuthorize,
  startAuthorize,
} from "../src/index.js";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const ISSUER = "https://clerk.example.test";
const BASE = "https://mcp.example.test";
const REDIRECT = "https://client.example.test/cb";
const NOW = 1_800_000_000_000;
const VERIFIER = "v".repeat(50);

const goodEnv = {
  AUTHORIZE_STATE_SECRET: "s".repeat(40),
  CLERK_DOMAIN: `${ISSUER}/`,
  AUTHORIZE_SIGN_IN_URL: `${ISSUER}/sign-in`,
  AUTHORIZE_CALLBACK_URL: `${BASE}/authorize/callback`,
  PUBLIC_BASE_URL: `${BASE}/`,
  CLERK_SECRET_KEY: "sk_test_placeholder",
};

const b64u = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const b64uJson = (v: unknown) => b64u(new TextEncoder().encode(JSON.stringify(v)));

let privateKey: CryptoKey;
let jwks: ClerkJwks;

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

async function mintSession(): Promise<string> {
  const h = b64uJson({ alg: "RS256", kid: "k1", typ: "JWT" });
  const p = b64uJson({
    iss: ISSUER,
    sub: "user_1",
    sid: "sess_1",
    azp: BASE,
    exp: NOW / 1000 + 300,
    nbf: NOW / 1000 - 10,
  });
  const sig = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    privateKey,
    new TextEncoder().encode(`${h}.${p}`),
  );
  return `${h}.${p}.${b64u(new Uint8Array(sig))}`;
}

function settingsOf(env: Record<string, string | undefined> = goodEnv): AuthorizeSettings {
  const r = readAuthorizeSettings(env);
  if (!r.ok) throw new Error(`settings fixture refused: ${r.missing.join(",")}`);
  return r.settings;
}

const record = (over: Partial<AuthorizationCodeRecord> = {}): AuthorizationCodeRecord => ({
  codeHash: "h1",
  clerkUserId: "user_1",
  orgId: "org_A",
  orgSlug: "acme",
  orgRole: "org:admin",
  clientId: "client_1",
  redirectUri: REDIRECT,
  codeChallenge: "c".repeat(43),
  resource: `${BASE}/mcp`,
  scope: "mcp:full openid",
  expiresAt: NOW + 60_000,
  ...over,
});

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

describe("readAuthorizeSettings", () => {
  it("reads typed settings from the env object it is given", () => {
    const r = readAuthorizeSettings(goodEnv);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.settings.issuer).toBe(ISSUER);
    expect(r.settings.baseUrl).toBe(BASE);
    expect(r.settings.authorizedParties).toEqual(expect.arrayContaining([ISSUER, BASE]));
  });

  it("refuses a missing AUTHORIZE_STATE_SECRET by name", () => {
    const { AUTHORIZE_STATE_SECRET: _omit, ...rest } = goodEnv;
    const r = readAuthorizeSettings(rest);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.missing).toEqual([AUTHORIZE_ENV.stateSecret]);
    expect(r.refusal).toEqual({ code: "AUTHORIZE_REFUSED", reason: "server-misconfigured" });
  });

  it("refuses a state secret shorter than 32 characters, naming the variable and never its value", () => {
    const short = "x".repeat(31);
    const r = readAuthorizeSettings({ ...goodEnv, AUTHORIZE_STATE_SECRET: short });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.missing).toEqual(["AUTHORIZE_STATE_SECRET"]);
    expect(JSON.stringify(r)).not.toContain(short);
  });

  it("accepts exactly 32 characters", () => {
    expect(readAuthorizeSettings({ ...goodEnv, AUTHORIZE_STATE_SECRET: "x".repeat(32) }).ok).toBe(true);
  });

  it("reports every unusable variable by name, and a URL that does not parse as missing", () => {
    const r = readAuthorizeSettings({ AUTHORIZE_STATE_SECRET: "s".repeat(40), CLERK_DOMAIN: "not a url" });
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.missing).toEqual([
      "CLERK_DOMAIN",
      "AUTHORIZE_SIGN_IN_URL",
      "AUTHORIZE_CALLBACK_URL",
      "PUBLIC_BASE_URL",
      "CLERK_SECRET_KEY",
    ]);
  });

  it("does not require the Clerk secret key when the host injects its own collaborators", () => {
    const { CLERK_SECRET_KEY: _omit, ...rest } = goodEnv;
    expect(readAuthorizeSettings(rest).ok).toBe(false);
    const r = readAuthorizeSettings(rest, { requireClerkSecretKey: false });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.settings.clerkSecretKey).toBeNull();
  });

  it("adds extra authorized parties from the comma list", () => {
    const r = readAuthorizeSettings({
      ...goodEnv,
      AUTHORIZE_AUTHORIZED_PARTIES: " https://a.example.test , ,https://b.example.test",
    });
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.settings.authorizedParties).toEqual(
      expect.arrayContaining(["https://a.example.test", "https://b.example.test"]),
    );
  });
});

// ---------------------------------------------------------------------------
// JWKS cache
// ---------------------------------------------------------------------------

describe("createClerkJwksSource", () => {
  function fakeFetch(body: unknown = jwks, status = 200) {
    const calls: string[] = [];
    const fn = async (url: string) => {
      calls.push(url);
      return { ok: status >= 200 && status < 300, status, json: async () => body };
    };
    return { fn, calls };
  }

  it("serves from the cache within the TTL", async () => {
    const f = fakeFetch();
    let now = NOW;
    const source = createClerkJwksSource({ issuer: ISSUER, fetch: f.fn, now: () => now, ttlMs: 1000 });
    await source();
    now += 999;
    await source();
    expect(f.calls).toEqual([`${ISSUER}/.well-known/jwks.json`]);
  });

  it("refetches once the TTL has elapsed", async () => {
    const f = fakeFetch();
    let now = NOW;
    const source = createClerkJwksSource({ issuer: ISSUER, fetch: f.fn, now: () => now, ttlMs: 1000 });
    await source();
    now += 1000;
    await source();
    expect(f.calls.length).toBe(2);
  });

  it("throws on a non-2xx answer, caches nothing, and recovers on the next call", async () => {
    let status = 503;
    let calls = 0;
    const source = createClerkJwksSource({
      issuer: ISSUER,
      now: () => NOW,
      fetch: async () => {
        calls += 1;
        return { ok: status === 200, status, json: async () => jwks };
      },
    });
    await expect(source()).rejects.toThrow(/503/);
    status = 200;
    await expect(source()).resolves.toEqual(jwks);
    expect(calls).toBe(2);
  });

  it("refuses a body that is not a key set", async () => {
    const f = fakeFetch({ nope: true });
    const source = createClerkJwksSource({ issuer: ISSUER, fetch: f.fn });
    await expect(source()).rejects.toThrow(/key set/);
  });

  it("keeps one cache per source, not per process", async () => {
    const f = fakeFetch();
    await createClerkJwksSource({ issuer: ISSUER, fetch: f.fn })();
    await createClerkJwksSource({ issuer: ISSUER, fetch: f.fn })();
    expect(f.calls.length).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// Code store
// ---------------------------------------------------------------------------

describe("code store", () => {
  it("in-memory: a code is consumable exactly once", async () => {
    const store = createInMemoryCodeStore();
    await store.put(record());
    expect((await store.consume("h1")).status).toBe("ok");
    expect(await store.consume("h1")).toEqual({ status: "already-used" });
    expect(await store.consume("nope")).toEqual({ status: "unknown" });
  });

  it("in-memory: of two concurrent consumes exactly one wins", async () => {
    const store = createInMemoryCodeStore();
    await store.put(record());
    const [a, b] = await Promise.all([store.consume("h1"), store.consume("h1")]);
    expect([a.status, b.status].sort()).toEqual(["already-used", "ok"]);
  });

  it("adapter: passes the record to the backend and the backend's consume through", async () => {
    const put: AuthorizationCodeRecord[] = [];
    const store = codeStoreFrom({
      insert: async (r) => {
        put.push(r);
      },
      takeOnce: async () => ({ status: "ok", record: record() }),
    });
    await store.put(record());
    expect(put).toEqual([record()]);
    expect(await store.consume("h1")).toEqual({ status: "ok", record: record() });
  });

  it("adapter: single-use consume holds end to end over an atomic backend", async () => {
    const used = new Set<string>();
    const rows = new Map<string, AuthorizationCodeRecord>();
    const store = codeStoreFrom({
      insert: async (r) => {
        rows.set(r.codeHash, r);
      },
      takeOnce: async (h) => {
        const row = rows.get(h);
        if (!row) return { status: "unknown" };
        if (used.has(h)) return { status: "already-used" };
        used.add(h);
        return { status: "ok", record: row };
      },
    });
    await store.put(record());
    expect((await store.consume("h1")).status).toBe("ok");
    expect((await store.consume("h1")).status).toBe("already-used");
  });

  it("adapter: a malformed backend answer throws instead of granting", async () => {
    const bad: unknown[] = [
      undefined,
      null,
      "ok",
      { status: "ok" },
      { status: "ok", record: { codeHash: "h1" } },
      { status: "granted", record: record() },
    ];
    for (const answer of bad) {
      const store = codeStoreFrom({ insert: async () => {}, takeOnce: async () => answer });
      await expect(store.consume("h1")).rejects.toThrow(/consume/);
    }
  });

  it("adapter: a malformed answer reaches the exchange as code-store-unavailable", async () => {
    const store = codeStoreFrom({ insert: async () => {}, takeOnce: async () => ({ status: "ok" }) });
    const out = await exchangeAuthorizationCode(
      { code: "c", codeVerifier: VERIFIER, redirectUri: REDIRECT, clientId: "client_1" },
      { codeStore: store, now: () => NOW },
    );
    expect(out).toEqual({ ok: false, refusal: { code: "AUTHORIZE_REFUSED", reason: "code-store-unavailable" } });
  });
});

// ---------------------------------------------------------------------------
// Picker
// ---------------------------------------------------------------------------

const pickerModel = (over: Partial<OrgPickerModel> = {}): OrgPickerModel => ({
  state: "st.ate",
  client: { clientId: "client_1", clientName: "Claude" },
  resource: `${BASE}/mcp`,
  scope: "openid",
  redirectOrigin: "https://client.example.test",
  organizations: [{ id: "org_A", slug: "acme", name: "Acme", role: "org:admin" }],
  consentRequired: true,
  consentToken: "tok",
  ...over,
});

describe("org picker", () => {
  it("escapes organisation names, client names, roles and state", () => {
    const html = renderOrgPicker(
      pickerModel({
        state: `"><script>alert(1)</script>`,
        client: { clientId: "c", clientName: `<img src=x onerror=alert(1)>` },
        organizations: [
          { id: `o"><b>`, slug: null, name: `<script>alert('x')</script>&`, role: `org:<i>admin` },
        ],
      }),
      { productName: "Acme MCP" },
    );
    expect(html).not.toContain("<script>");
    expect(html).not.toContain("<img");
    expect(html).not.toContain("<b>");
    expect(html).not.toContain("<i>");
    expect(html).toContain("&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;&amp;");
  });

  it("escapes the product name and the form action", () => {
    const html = renderOrgPicker(pickerModel(), { productName: `<u>P</u>`, formAction: `/a"b` });
    expect(html).not.toContain("<u>");
    expect(html).toContain(`action="/a&quot;b"`);
  });

  it("posts state, consentToken, orgId and approved to the default action", () => {
    const html = renderOrgPicker(pickerModel(), { productName: "Acme MCP" });
    expect(html).toContain(`action="/authorize/org"`);
    expect(html).toContain(`name="state" value="st.ate"`);
    expect(html).toContain(`name="consentToken" value="tok"`);
    expect(html).toContain(`name="orgId"`);
    expect(html).toContain(`name="approved" value="true"`);
    expect(html).toContain(`name="approved" value="false"`);
    expect(html).toContain("Acme MCP");
  });

  it("pre-checks a single organisation only", () => {
    const one = renderOrgPicker(pickerModel(), { productName: "P" });
    expect(one).toContain(" checked>");
    const two = renderOrgPicker(
      pickerModel({
        organizations: [
          { id: "a", slug: null, name: "A", role: "org:member" },
          { id: "b", slug: null, name: "B", role: "org:member" },
        ],
      }),
      { productName: "P" },
    );
    expect(two).not.toContain(" checked>");
  });

  it("carries no script and no external asset", () => {
    const html = renderOrgPicker(pickerModel(), { productName: "P" });
    expect(html).not.toMatch(/<script/i);
    expect(html).not.toMatch(/(src|href)=/i);
  });

  it("CSP forbids everything but one hashed inline style, and the hash matches the page's style", async () => {
    const csp = await pickerContentSecurityPolicy();
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'none'");
    expect(csp).not.toMatch(/unsafe-inline|script-src/);
    const html = renderOrgPicker(pickerModel(), { productName: "P" });
    const style = /<style>([\s\S]*?)<\/style>/.exec(html)?.[1] ?? "";
    const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(style));
    const hash = btoa(String.fromCharCode(...new Uint8Array(digest)));
    expect(csp).toContain(`style-src 'sha256-${hash}'`);
  });
});

// ---------------------------------------------------------------------------
// Clerk directory
// ---------------------------------------------------------------------------

describe("createClerkDirectory", () => {
  const membership = (n: number) => ({
    role: "org:member",
    organization: { id: `org_${n}`, slug: n % 2 ? null : `s${n}`, name: `Org ${n}` },
  });

  it("maps memberships to the package shape and pages through all of them", async () => {
    const all = Array.from({ length: 5 }, (_, i) => membership(i));
    const calls: Array<{ limit?: number; offset?: number }> = [];
    const dir = createClerkDirectory(
      {
        users: {
          getOrganizationMembershipList: async (a) => {
            calls.push({ limit: a.limit, offset: a.offset });
            const off = a.offset ?? 0;
            return { data: all.slice(off, off + (a.limit ?? 100)), totalCount: all.length };
          },
          getUser: async () => ({ id: "user_1", emailAddresses: [] }),
        },
      },
      { pageSize: 2 },
    );
    const got = await dir.listMemberships("user_1");
    expect(got.map((m) => m.organization.id)).toEqual(all.map((m) => m.organization.id));
    expect(got[1]?.organization.slug).toBeNull();
    expect(calls).toEqual([
      { limit: 2, offset: 0 },
      { limit: 2, offset: 2 },
      { limit: 2, offset: 4 },
    ]);
  });

  it("propagates a Clerk failure instead of returning a partial list", async () => {
    const dir = createClerkDirectory({
      users: {
        getOrganizationMembershipList: async () => {
          throw new Error("clerk down");
        },
        getUser: async () => ({ id: "u", emailAddresses: [] }),
      },
    });
    await expect(dir.listMemberships("user_1")).rejects.toThrow("clerk down");
  });

  it("fails closed when Clerk never stops paging", async () => {
    const dir = createClerkDirectory(
      {
        users: {
          getOrganizationMembershipList: async () => ({ data: [membership(1), membership(2)], totalCount: 10_000 }),
          getUser: async () => ({ id: "u", emailAddresses: [] }),
        },
      },
      { pageSize: 2, maxPages: 3 },
    );
    await expect(dir.listMemberships("user_1")).rejects.toThrow(/pages/);
  });

  it("getUser returns the Clerk user", async () => {
    const dir = createClerkDirectory({
      users: {
        getOrganizationMembershipList: async () => ({ data: [], totalCount: 0 }),
        getUser: async (id) => ({ id, emailAddresses: [] }),
      },
    });
    expect((await dir.getUser("user_9")).id).toBe("user_9");
  });
});

// ---------------------------------------------------------------------------
// Runtime
// ---------------------------------------------------------------------------

const orgA: ClerkOrgMembership = {
  role: "org:admin",
  organization: { id: "org_A", slug: "acme", name: "Acme" },
};

function wire(memberships: readonly ClerkOrgMembership[]) {
  const store = createInMemoryCodeStore();
  const runtime = buildAuthorizeRuntime({
    settings: settingsOf(),
    lookupClient: async (id) =>
      id === "client_1"
        ? { clientId: "client_1", redirectUris: [REDIRECT], clientName: "Claude" }
        : null,
    listMemberships: async () => memberships,
    codeStore: store,
    jwks: async () => jwks,
    now: () => NOW,
  });
  return { runtime, store };
}

const stateOf = (url: string) =>
  new URL(new URL(url).searchParams.get("redirect_url") as string).searchParams.get(
    "authorize_state",
  ) as string;

async function params() {
  return {
    client_id: "client_1",
    redirect_uri: REDIRECT,
    response_type: "code",
    state: "client-state",
    code_challenge: await pkceChallengeFromVerifier(VERIFIER),
    code_challenge_method: ["S", "256"].join(""),
    resource: `${BASE}/mcp`,
    scope: "openid",
  };
}

describe("buildAuthorizeRuntime", () => {
  it("derives the configuration from the settings, with consent left on", () => {
    const { runtime } = wire([orgA]);
    expect(runtime.cfg.allowedResources).toEqual([`${BASE}/mcp`]);
    expect(runtime.cfg.defaultScope).toBe(DEFAULT_AUTHORIZE_SCOPE);
    expect(runtime.cfg.requireConsent).toBeUndefined();
    expect(runtime.cfg.session.issuer).toBe(ISSUER);
    expect(runtime.cfg.stateSecret).toBe("s".repeat(40));
  });

  it("honours a host resource path", () => {
    const r = buildAuthorizeRuntime({
      settings: settingsOf(),
      lookupClient: async () => null,
      listMemberships: async () => [],
      codeStore: createInMemoryCodeStore(),
      resourcePath: "/rpc",
    });
    expect(r.cfg.allowedResources).toEqual([`${BASE}/rpc`]);
  });

  it("refuses an organisation outside the person's memberships", async () => {
    const { runtime, store } = wire([orgA]);
    const session = await mintSession();
    const first = await startAuthorize(await params(), session, runtime.cfg, runtime.deps);
    expect(first.kind).toBe("org-picker");
    if (first.kind !== "org-picker") return;
    const out = await resumeAuthorize(
      {
        state: first.model.state,
        sessionToken: session,
        orgId: "org_NOT_MINE",
        approved: true,
        consentToken: first.model.consentToken ?? undefined,
      },
      runtime.cfg,
      runtime.deps,
    );
    expect(out.kind).toBe("refused");
    if (out.kind === "refused") expect(out.refusal.reason).toBe("org-not-a-member");
    expect((await store.consume("anything")).status).toBe("unknown");
  });

  it("walks start -> sign-in -> picker -> code -> token with a fake key set", async () => {
    const { runtime } = wire([orgA]);
    const p = await params();

    const signIn = await startAuthorize(p, undefined, runtime.cfg, runtime.deps);
    expect(signIn.kind).toBe("redirect-to-sign-in");
    if (signIn.kind !== "redirect-to-sign-in") return;

    const session = await mintSession();
    const picker = await resumeAuthorize(
      { state: stateOf(signIn.url), sessionToken: session },
      runtime.cfg,
      runtime.deps,
    );
    expect(picker.kind).toBe("org-picker");
    if (picker.kind !== "org-picker") return;
    const html = renderOrgPicker(picker.model, { productName: "Acme MCP" });
    expect(html).toContain("Acme");
    expect(await pickerContentSecurityPolicy()).toContain("default-src 'none'");

    const done = await resumeAuthorize(
      {
        state: picker.model.state,
        sessionToken: session,
        orgId: "org_A",
        approved: true,
        consentToken: picker.model.consentToken ?? undefined,
      },
      runtime.cfg,
      runtime.deps,
    );
    expect(done.kind).toBe("redirect-to-client");
    if (done.kind !== "redirect-to-client") return;
    const redirect = new URL(done.url);
    expect(redirect.origin + redirect.pathname).toBe(REDIRECT);
    expect(redirect.searchParams.get("state")).toBe("client-state");
    const code = redirect.searchParams.get("code") as string;

    const exchange = () =>
      exchangeAuthorizationCode(
        { code, codeVerifier: VERIFIER, redirectUri: REDIRECT, clientId: "client_1", resource: `${BASE}/mcp` },
        { codeStore: runtime.deps.codeStore, now: runtime.deps.now },
      );
    const token = await exchange();
    expect(token.ok).toBe(true);
    if (token.ok) {
      expect(token.claims.sub).toBe("user_1");
      expect(token.claims.org_id).toBe("org_A");
    }
    const replay = await exchange();
    expect(replay).toEqual({ ok: false, refusal: { code: "AUTHORIZE_REFUSED", reason: "code-reused" } });
  });

  it("a key set that cannot be fetched is a refusal, never a grant", async () => {
    const r = buildAuthorizeRuntime({
      settings: settingsOf(),
      lookupClient: async () => ({ clientId: "client_1", redirectUris: [REDIRECT] }),
      listMemberships: async () => [orgA],
      codeStore: createInMemoryCodeStore(),
      jwks: async () => {
        throw new Error("down");
      },
      now: () => NOW,
    });
    const out = await startAuthorize(await params(), await mintSession(), r.cfg, r.deps);
    expect(out.kind).toBe("refused");
    if (out.kind === "refused") expect(out.refusal.reason).toBe("jwks-unavailable");
  });
});
