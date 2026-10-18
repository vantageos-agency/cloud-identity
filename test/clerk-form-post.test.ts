import { createSign, generateKeyPairSync } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { resolveClerkSessionForFormPost } from "../src/index.js";

/**
 * The org picker's form post. Nothing is mocked: the real @clerk/backend
 * authenticateRequest runs, networkless (a `jwtKey` PEM). A PRODUCTION
 * publishable key is used on purpose: a production instance names its
 * session cookie `__session_<suffix>`, never a bare `__session`, which is the
 * defect a cookie read by hand did not survive.
 */
const FAPI = "clerk.example.test";
const PK = `pk_live_${Buffer.from(`${FAPI}$`).toString("base64")}`;
const SK = "sk_live_" + "x".repeat(40);
const HOST = "https://mcp.example.test";

let pem: string;
let privatePem: string;

const b64u = (b: Buffer | string) =>
  Buffer.from(b).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function mint(claims: Record<string, unknown> = {}): string {
  const h = b64u(JSON.stringify({ alg: "RS256", kid: "ins_test", typ: "JWT" }));
  const iat = Math.floor(Date.now() / 1000);
  const p = b64u(
    JSON.stringify({
      iss: `https://${FAPI}`,
      sub: "user_1",
      sid: "sess_1",
      iat: iat - 5,
      nbf: iat - 5,
      exp: iat + 300,
      ...claims,
    }),
  );
  const s = createSign("RSA-SHA256").update(`${h}.${p}`).sign(privatePem);
  return `${h}.${p}.${b64u(s)}`;
}

/** The suffix a production instance appends to its cookie names (Clerk's own rule). */
async function cookieSuffix(): Promise<string> {
  const { getCookieSuffix } = await import("@clerk/shared/keys");
  return getCookieSuffix(PK);
}

const opts = () => ({ secretKey: SK, publishableKey: PK, jwtKey: pem, expectedOrigin: HOST });

function post(cookie: string, headers: Record<string, string> = { origin: HOST }): Request {
  return new Request(`${HOST}/authorize/org`, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "text/html",
      "sec-fetch-dest": "document",
      cookie,
      ...headers,
    },
    body: "state=s&approved=true",
  });
}

beforeAll(() => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  pem = publicKey.export({ type: "spki", format: "pem" }) as string;
  privatePem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
});

describe("resolveClerkSessionForFormPost: the picker's same-origin form post", () => {
  it("reads the production instance's suffixed session cookie -> signed-in", async () => {
    const t = mint();
    const sfx = await cookieSuffix();
    const r = await resolveClerkSessionForFormPost(
      post(`__session_${sfx}=${t}; __client_uat_${sfx}=1; __client_uat=1`),
      opts(),
    );
    expect(r.kind).toBe("signed-in");
    if (r.kind !== "signed-in") return;
    expect(r.sessionToken).toBe(t);
    expect(r.userId).toBe("user_1");
  });

  it("refuses a post whose Origin is another site, before any session is read", async () => {
    const sfx = await cookieSuffix();
    const r = await resolveClerkSessionForFormPost(
      post(`__session_${sfx}=${mint()}; __client_uat_${sfx}=1`, { origin: "https://evil.example" }),
      opts(),
    );
    expect(r).toMatchObject({ kind: "signed-out", reason: "cross-origin-post" });
  });

  it("refuses a post with no Origin header", async () => {
    const sfx = await cookieSuffix();
    const r = await resolveClerkSessionForFormPost(post(`__session_${sfx}=${mint()}; __client_uat_${sfx}=1`, {}), opts());
    expect(r).toMatchObject({ kind: "signed-out", reason: "cross-origin-post" });
  });

  it("refuses a request that is not a POST", async () => {
    const r = await resolveClerkSessionForFormPost(new Request(`${HOST}/authorize/org`, { headers: { origin: HOST } }), opts());
    expect(r).toMatchObject({ kind: "signed-out", reason: "not-a-form-post" });
  });

  it("an expired session with no way to refresh it is signed-out, never a redirect on a POST", async () => {
    const sfx = await cookieSuffix();
    const expired = mint({ iat: Math.floor(Date.now() / 1000) - 600, nbf: Math.floor(Date.now() / 1000) - 600, exp: Math.floor(Date.now() / 1000) - 300 });
    const r = await resolveClerkSessionForFormPost(post(`__session_${sfx}=${expired}; __client_uat_${sfx}=1`), opts());
    expect(r.kind).toBe("signed-out");
  });

  it("no session cookie at all is signed-out", async () => {
    const r = await resolveClerkSessionForFormPost(post(""), opts());
    expect(r.kind).toBe("signed-out");
  });
});
