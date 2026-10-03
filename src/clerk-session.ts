import {
  type AuthorizeRefusal,
  fromBase64Url,
  refusal,
  utf8,
} from "./authorize-shared.js";

/**
 * Verification of a Clerk session token (a signed RS256 JWT) against the
 * instance's JWKS. The consumer supplies the issuer, the key set and, where it
 * wants them, the audience and authorized parties; this module holds every
 * decision and performs no network call of its own.
 *
 * @security Only RS256 is accepted. `alg: none`, HMAC algorithms and any key
 * type other than RSA are refused before a signature is looked at.
 */

export interface ClerkJwk {
  kty: string;
  kid?: string;
  n?: string;
  e?: string;
  alg?: string;
  use?: string;
}

export interface ClerkJwks {
  keys: readonly ClerkJwk[];
}

export interface ClerkSessionVerifierConfig {
  /** Exact `iss` the token must carry (the Clerk frontend API URL). */
  issuer: string;
  /** The key set, or a function returning it (the consumer owns fetching and caching). */
  jwks: ClerkJwks | (() => Promise<ClerkJwks>);
  /** When set, the token's `aud` must contain one of these. */
  audience?: string | readonly string[];
  /** When set, the token's `azp` must be present and listed. */
  authorizedParties?: readonly string[];
  /** Clock tolerance in seconds for `exp` / `nbf`. Default 5. */
  clockToleranceSeconds?: number;
}

export interface VerifiedClerkSession {
  userId: string;
  sessionId: string | null;
  claims: Readonly<Record<string, unknown>>;
}

export type VerifyClerkSessionResult =
  | { ok: true; session: VerifiedClerkSession }
  | { ok: false; refusal: AuthorizeRefusal };

function parseJson(bytes: Uint8Array | null): Record<string, unknown> | null {
  if (!bytes) return null;
  try {
    const v: unknown = JSON.parse(new TextDecoder().decode(bytes));
    return typeof v === "object" && v !== null && !Array.isArray(v)
      ? (v as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/**
 * Verifies a Clerk session token. `nowMs` is injectable for tests.
 * An unreachable key set is `jwks-unavailable` (retryable, 503), never a
 * bad-credential answer; every other failure is `session-invalid`.
 */
export async function verifyClerkSessionToken(
  token: string,
  config: ClerkSessionVerifierConfig,
  nowMs: number = Date.now(),
): Promise<VerifyClerkSessionResult> {
  const bad = (): VerifyClerkSessionResult => ({
    ok: false,
    refusal: refusal("session-invalid"),
  });

  const parts = token.split(".");
  if (parts.length !== 3) return bad();
  const [h, p, s] = parts as [string, string, string];
  const header = parseJson(fromBase64Url(h));
  const claims = parseJson(fromBase64Url(p));
  const sig = fromBase64Url(s);
  if (!header || !claims || !sig || sig.length === 0) return bad();
  if (header.alg !== "RS256") return bad();
  if (typeof header.kid !== "string" || header.kid.length === 0) return bad();

  let jwks: ClerkJwks;
  try {
    jwks = typeof config.jwks === "function" ? await config.jwks() : config.jwks;
  } catch {
    return { ok: false, refusal: refusal("jwks-unavailable") };
  }
  const jwk = jwks.keys.find((k) => k.kid === header.kid && k.kty === "RSA");
  if (!jwk) return bad();

  let valid = false;
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    valid = await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      sig as unknown as BufferSource,
      utf8(`${h}.${p}`) as unknown as BufferSource,
    );
  } catch {
    return bad();
  }
  if (!valid) return bad();

  const tol = config.clockToleranceSeconds ?? 5;
  const nowSec = Math.floor(nowMs / 1000);
  if (claims.iss !== config.issuer) return bad();
  if (typeof claims.exp !== "number" || claims.exp + tol < nowSec) return bad();
  if (claims.nbf !== undefined) {
    if (typeof claims.nbf !== "number" || claims.nbf - tol > nowSec) return bad();
  }
  if (typeof claims.sub !== "string" || claims.sub.length === 0) return bad();

  if (config.audience !== undefined) {
    const wanted =
      typeof config.audience === "string" ? [config.audience] : config.audience;
    const got = Array.isArray(claims.aud)
      ? (claims.aud as unknown[])
      : [claims.aud];
    if (!got.some((a) => typeof a === "string" && wanted.includes(a))) return bad();
  }
  if (config.authorizedParties !== undefined) {
    if (
      typeof claims.azp !== "string" ||
      !config.authorizedParties.includes(claims.azp)
    ) {
      return bad();
    }
  }

  return {
    ok: true,
    session: {
      userId: claims.sub,
      sessionId: typeof claims.sid === "string" ? claims.sid : null,
      claims,
    },
  };
}
