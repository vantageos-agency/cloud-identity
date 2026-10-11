import { beforeAll, describe, expect, it } from "vitest";
import { generateKeyPairSync, createSign } from "node:crypto";
import {
  resolveClerkSessionFromRequest,
  resumeAuthorizeFromRequest,
} from "../src/index.js";

/**
 * Nothing is mocked: the real @clerk/backend authenticateRequest runs. Verification is
 * networkless (a `jwtKey` PEM), the dev-instance handshake is built offline by the SDK.
 */
const FAPI = "sharp-sponge-67.clerk.accounts.dev";
const PK = `pk_test_${Buffer.from(`${FAPI}$`).toString("base64")}`;
const SK = "sk_test_" + "x".repeat(40);
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

const doc = { accept: "text/html", "sec-fetch-dest": "document" };
const opts = () => ({ secretKey: SK, publishableKey: PK, jwtKey: pem });

beforeAll(() => {
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  pem = publicKey.export({ type: "spki", format: "pem" }) as string;
  privatePem = privateKey.export({ type: "pkcs8", format: "pem" }) as string;
});

describe("resolveClerkSessionFromRequest", () => {
  it("a return carrying only __clerk_db_jwt, no session -> handshake with Location", async () => {
    const r = await resolveClerkSessionFromRequest(
      new Request(`${HOST}/authorize/callback?authorize_state=s&__clerk_db_jwt=dvb_abc`, { headers: doc }),
      opts(),
    );
    expect(r.kind).toBe("handshake");
    if (r.kind !== "handshake") return;
    expect([307, 302]).toContain(r.status);
    const loc = r.headers.get("location") ?? "";
    expect(loc).toContain(`${FAPI}/v1/client/handshake`);
    expect(loc).toContain("redirect_url=");
  });

  it("a bare document request with no session -> handshake, not session-required", async () => {
    const r = await resolveClerkSessionFromRequest(new Request(`${HOST}/authorize/callback`, { headers: doc }), opts());
    expect(r.kind).toBe("handshake");
  });

  it("a valid session cookie (+ client_uat) -> signed-in with the session token", async () => {
    const t = mint();
    const r = await resolveClerkSessionFromRequest(
      new Request(`${HOST}/authorize/callback`, {
        headers: { ...doc, cookie: `__session=${t}; __client_uat=1; __clerk_db_jwt=dvb_abc` },
      }),
      opts(),
    );
    expect(r.kind).toBe("signed-in");
    if (r.kind !== "signed-in") return;
    expect(r.sessionToken).toBe(t);
    expect(r.userId).toBe("user_1");
    expect(r.sessionId).toBe("sess_1");
  });

  it("the return carrying __clerk_handshake -> handshake: Set-Cookie __session + Location without the parameter", async () => {
    const t = mint();
    const iat = Math.floor(Date.now() / 1000);
    const h = b64u(JSON.stringify({ alg: "RS256", kid: "ins_test", typ: "JWT" }));
    const p = b64u(
      JSON.stringify({ iss: `https://${FAPI}`, iat, nbf: iat, exp: iat + 60, handshake: [`__session=${t}; Path=/; HttpOnly`, "__client_uat=1; Path=/"] }),
    );
    const hs = `${h}.${p}.${b64u(createSign("RSA-SHA256").update(`${h}.${p}`).sign(privatePem))}`;
    const r = await resolveClerkSessionFromRequest(
      new Request(`${HOST}/authorize/callback?authorize_state=s&__clerk_handshake=${hs}`, { headers: doc }),
      opts(),
    );
    expect(r.kind).toBe("handshake");
    if (r.kind !== "handshake") return;
    expect(r.headers.getSetCookie().some((c) => c.startsWith("__session="))).toBe(true);
    const loc = r.headers.get("location") ?? "";
    expect(loc).toContain("/authorize/callback?authorize_state=s");
    expect(loc).not.toContain("__clerk_handshake");
  });

  it("a valid Bearer session token still resolves signed-in", async () => {
    const t = mint();
    const r = await resolveClerkSessionFromRequest(
      new Request(`${HOST}/authorize`, { headers: { authorization: `Bearer ${t}` } }),
      opts(),
    );
    expect(r.kind).toBe("signed-in");
    if (r.kind === "signed-in") expect(r.sessionToken).toBe(t);
  });

  it("a non-document request with no session -> signed-out (no redirect for fetch)", async () => {
    const r = await resolveClerkSessionFromRequest(
      new Request(`${HOST}/authorize/callback`, { headers: { accept: "application/json", "sec-fetch-dest": "empty" } }),
      opts(),
    );
    expect(r.kind).toBe("signed-out");
  });

  it("an expired Bearer -> signed-out with a reason", async () => {
    const t = mint({ exp: Math.floor(Date.now() / 1000) - 600, iat: Math.floor(Date.now() / 1000) - 900, nbf: Math.floor(Date.now() / 1000) - 900 });
    const r = await resolveClerkSessionFromRequest(
      new Request(`${HOST}/authorize`, { headers: { authorization: `Bearer ${t}` } }),
      opts(),
    );
    expect(r.kind).toBe("signed-out");
    if (r.kind === "signed-out") expect(r.reason.length).toBeGreaterThan(0);
  });

  it("a token signed by another key is never signed-in", async () => {
    const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const h = b64u(JSON.stringify({ alg: "RS256", kid: "ins_test", typ: "JWT" }));
    const iat = Math.floor(Date.now() / 1000);
    const p = b64u(JSON.stringify({ iss: `https://${FAPI}`, sub: "user_x", sid: "s", iat, nbf: iat, exp: iat + 300 }));
    const sig = createSign("RSA-SHA256").update(`${h}.${p}`).sign(other.privateKey.export({ type: "pkcs8", format: "pem" }) as string);
    const r = await resolveClerkSessionFromRequest(
      new Request(`${HOST}/authorize`, { headers: { authorization: `Bearer ${h}.${p}.${b64u(sig)}` } }),
      opts(),
    );
    expect(r.kind).not.toBe("signed-in");
  });
});

describe("an invalid __clerk_handshake is signed-out, never a throw", () => {
  // The forms an untrusted `__clerk_handshake` takes: not a JWT, signed by another key, expired.
  const iat = () => Math.floor(Date.now() / 1000);
  const hsHeader = () => b64u(JSON.stringify({ alg: "RS256", kid: "ins_test", typ: "JWT" }));
  const signed = (payload: Record<string, unknown>, pemKey: string) => {
    const h = hsHeader();
    const p = b64u(JSON.stringify(payload));
    return `${h}.${p}.${b64u(createSign("RSA-SHA256").update(`${h}.${p}`).sign(pemKey))}`;
  };
  const cookies = () => [`__session=${mint()}; Path=/; HttpOnly`, "__client_uat=1; Path=/"];
  const forms: Array<[string, () => string]> = [
    ["not a JWT", () => "forged.not.a.jwt"],
    [
      "signed by another key",
      () => {
        const other = generateKeyPairSync("rsa", { modulusLength: 2048 });
        const t = iat();
        return signed(
          { iss: `https://${FAPI}`, iat: t, nbf: t, exp: t + 60, handshake: cookies() },
          other.privateKey.export({ type: "pkcs8", format: "pem" }) as string,
        );
      },
    ],
    [
      "expired",
      () => {
        const t = iat() - 3600;
        return signed({ iss: `https://${FAPI}`, iat: t, nbf: t, exp: t + 60, handshake: cookies() }, privatePem);
      },
    ],
  ];

  for (const [name, make] of forms) {
    it(`${name} -> signed-out "handshake-invalid", no __session set`, async () => {
      const r = await resolveClerkSessionFromRequest(
        new Request(`${HOST}/authorize/callback?authorize_state=s&__clerk_handshake=${make()}`, { headers: doc }),
        opts(),
      );
      expect(r.kind).toBe("signed-out");
      if (r.kind !== "signed-out") return;
      expect(r.reason).toBe("handshake-invalid");
      expect(r.headers.getSetCookie().some((c) => c.startsWith("__session="))).toBe(false);
    });
  }

  it("resumeAuthorizeFromRequest continues signed out on a forged handshake instead of throwing", async () => {
    const out = await resumeAuthorizeFromRequest(
      new Request(`${HOST}/authorize/callback?authorize_state=s&__clerk_handshake=forged.not.a.jwt`, { headers: doc }),
      { state: "s" },
      opts(),
      {} as never,
      {} as never,
    ).catch((e: unknown) => ({ kind: "threw", e }));
    expect(out.kind).not.toBe("threw");
    expect(out.kind).not.toBe("handshake");
  });
});

describe("resumeAuthorizeFromRequest", () => {
  it("returns the handshake before looking at the state when there is no session", async () => {
    const out = await resumeAuthorizeFromRequest(
      new Request(`${HOST}/authorize/callback?authorize_state=s`, { headers: doc }),
      { state: "s" },
      opts(),
      {} as never,
      {} as never,
    );
    expect(out.kind).toBe("handshake");
  });
});
