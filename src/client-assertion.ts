/**
 * private_key_jwt client authentication at `/token` (RFC 7523 / OIDC Core 9).
 *
 * A presented assertion is VERIFIED, never ignored and never trusted unverified:
 *  - the key set comes from the `jwks_uri` of the client's CIMD document, fetched through the
 *    same SSRF guard as the document itself;
 *  - alg is pinned to RS256 (a document declaring another signing alg is refused), so `none`
 *    and HMAC assertions cannot verify;
 *  - `iss` and `sub` equal the client_id; `aud` is this token endpoint or this issuer; `exp`
 *    is required (30 s skew) and at most `MAX_ASSERTION_LIFETIME_SECONDS` (300 s) plus the
 *    skew ahead of now; `iat`, when present, is not in the future past the skew; `jti` is
 *    required and accepted ONCE.
 *
 * Lifted from the vantage-mcp-boilerplate (`src/oauth/clientAssertion.ts`). The decisions and
 * the refusal reasons are unchanged; the one difference is the JWT library. The boilerplate
 * verifies with `jose`, which this package does not depend on, so the RS256 check below uses
 * Web Crypto with this package's own base64url and UTF-8 helpers (`./authorize-shared.js`),
 * the same primitive `verifyClerkSessionToken` uses. The `jose` checks it replaces are kept:
 * alg allow-list, unrecognised `crit` refused, key candidates by kty/kid/alg/use/key_ops
 * (each candidate tried), RSA modulus of at least 2048 bits, `iss`/`sub`/`aud` exact,
 * `exp` required and numeric, `nbf`/`iat` numeric when present, 30 s clock tolerance.
 *
 * Node only (the SSRF guard uses `node:net` and `node:dns/promises`): subpath
 * `@vantageos/cloud-identity/client-assertion`, never the root.
 */
import { fromBase64Url, utf8 } from "./authorize-shared.js";
import {
  type CimdOptions,
  fetchGuardedJson,
  isUrlShapedClientId,
  resolveCimdDocument,
} from "./cimd-fetch.js";

export {
  type CimdDocument,
  type CimdOptions,
  fetchGuardedJson,
  isAllowedRedirectUri,
  isPublicAddress,
  isUrlShapedClientId,
  resolveCimdDocument,
} from "./cimd-fetch.js";

export const JWT_BEARER_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
export const ASSERTION_SIGNING_ALGS = ["RS256"] as const;

const SKEW_SECONDS = 30;
/**
 * The furthest ahead of now an assertion's `exp` may be (plus the 30 s skew). Each accepted jti
 * is held until its `exp`, and client ids are open (any host serving a CIMD and a key set), so
 * without this bound one caller could fill the bounded jti store with far-future assertions and
 * lock every client out until those expire.
 */
export const MAX_ASSERTION_LIFETIME_SECONDS = 300;
const MAX_JWKS_BYTES = 64 * 1024;
const MIN_RSA_MODULUS_BITS = 2048;

/** Every reason `verify` can refuse with. The strings are the boilerplate's, unchanged. */
export type AssertionRefusalReason =
  | "unsupported client assertion"
  | "malformed client assertion"
  | "unknown client"
  | "client_id does not match the assertion issuer"
  | "client has no verifiable key set"
  | "unsupported signing algorithm"
  | "invalid jwks_uri"
  | "key set unavailable"
  | "client assertion rejected"
  | "client assertion replayed";

export type AssertionResult =
  | { ok: true; clientId: string }
  | { ok: false; reason: AssertionRefusalReason };

/** The bounded jti store `createJtiStore` returns; inject your own (for example shared). */
export interface JtiStore {
  /** True when the jti is new (and is now recorded); false on a replay or when full. */
  accept(clientId: string, jti: string, exp: number, nowSeconds: number): boolean;
}

/** Bounded set of accepted jti values, each held until its assertion expires. */
export function createJtiStore(maxEntries = 10_000): JtiStore {
  const seen = new Map<string, number>(); // `${clientId}\n${jti}` -> exp (epoch seconds)
  return {
    accept(clientId: string, jti: string, exp: number, nowSeconds: number): boolean {
      for (const [k, e] of seen) if (e + SKEW_SECONDS <= nowSeconds) seen.delete(k);
      const key = `${clientId}\n${jti}`;
      if (seen.has(key)) return false;
      if (seen.size >= maxEntries) return false; // fail closed: never evict a live jti
      seen.set(key, exp);
      return true;
    },
  };
}

export interface AssertionVerifierOptions extends CimdOptions {
  now?: () => number; // epoch milliseconds
  jtiStore?: JtiStore;
}

export interface ClientAssertionInput {
  assertionType: string | undefined;
  assertion: string | undefined;
  /** The `client_id` request parameter, when sent. */
  clientId?: string | undefined;
  /** The audiences accepted for `aud`: this token endpoint and this issuer. */
  audiences: readonly string[];
}

export interface ClientAssertionVerifier {
  verify(input: ClientAssertionInput): Promise<AssertionResult>;
}

type JsonObject = Record<string, unknown>;

interface CandidateJwk {
  kty?: unknown;
  kid?: unknown;
  alg?: unknown;
  use?: unknown;
  key_ops?: unknown;
  n?: unknown;
  e?: unknown;
}

function decodeSegment(segment: string): JsonObject | null {
  const bytes = fromBase64Url(segment);
  if (!bytes) return null;
  try {
    const v: unknown = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
    return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as JsonObject) : null;
  } catch {
    return null;
  }
}

/** The payload of a compact JWS, unverified. Null when it is not one. */
function decodeUnverifiedPayload(token: string): JsonObject | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  return decodeSegment(parts[1] as string);
}

/** RSA keys of the set that may verify an RS256 signature carrying `kid` (when it has one). */
function candidateKeys(keys: readonly unknown[], kid: unknown): CandidateJwk[] {
  return keys.filter((raw): raw is CandidateJwk => {
    if (typeof raw !== "object" || raw === null) return false;
    const k = raw as CandidateJwk;
    if (k.kty !== "RSA") return false;
    if (kid !== undefined && k.kid !== kid) return false;
    if (k.alg !== undefined && k.alg !== "RS256") return false;
    if (k.use !== undefined && k.use !== "sig") return false;
    if (k.key_ops !== undefined && !(Array.isArray(k.key_ops) && k.key_ops.includes("verify"))) {
      return false;
    }
    return typeof k.n === "string" && typeof k.e === "string";
  });
}

async function verifiesWith(jwk: CandidateJwk, signed: Uint8Array, sig: Uint8Array) {
  try {
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: "RSA", n: jwk.n as string, e: jwk.e as string, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    const bits = (key.algorithm as RsaHashedKeyAlgorithm).modulusLength;
    if (typeof bits !== "number" || bits < MIN_RSA_MODULUS_BITS) return false;
    return await crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      key,
      sig as unknown as BufferSource,
      signed as unknown as BufferSource,
    );
  } catch {
    return false;
  }
}

/**
 * Verifies an RS256 compact JWS against a key set and checks the registered claims. Returns
 * the verified payload, or null for ANY failure.
 */
async function verifyRs256Assertion(
  token: string,
  keys: readonly unknown[],
  expect: { clientId: string; audiences: readonly string[]; nowSeconds: number },
): Promise<JsonObject | null> {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [h, p, s] = parts as [string, string, string];
  const header = decodeSegment(h);
  const payload = decodeSegment(p);
  const sig = fromBase64Url(s);
  if (!header || !payload || !sig || sig.length === 0) return null;
  if (!(ASSERTION_SIGNING_ALGS as readonly unknown[]).includes(header.alg)) return null;
  // No critical header extension is understood here, so any `crit` is refused (RFC 7515 4.1.11).
  if (header.crit !== undefined) return null;

  const signed = utf8(`${h}.${p}`);
  let verified = false;
  for (const jwk of candidateKeys(keys, header.kid)) {
    if (await verifiesWith(jwk, signed, sig)) {
      verified = true;
      break;
    }
  }
  if (!verified) return null;

  const now = expect.nowSeconds;
  for (const claim of ["iss", "sub", "aud", "exp", "jti"]) if (!(claim in payload)) return null;
  if (payload.iss !== expect.clientId || payload.sub !== expect.clientId) return null;
  const aud = typeof payload.aud === "string" ? [payload.aud] : payload.aud;
  if (!Array.isArray(aud) || !aud.some((a) => typeof a === "string" && expect.audiences.includes(a))) {
    return null;
  }
  if (typeof payload.exp !== "number" || payload.exp <= now - SKEW_SECONDS) return null;
  if (payload.exp - now > MAX_ASSERTION_LIFETIME_SECONDS + SKEW_SECONDS) return null;
  if (payload.nbf !== undefined && (typeof payload.nbf !== "number" || payload.nbf > now + SKEW_SECONDS)) {
    return null;
  }
  if (payload.iat !== undefined && (typeof payload.iat !== "number" || payload.iat > now + SKEW_SECONDS)) {
    return null;
  }
  return payload;
}

export function createClientAssertionVerifier(
  options: AssertionVerifierOptions = {},
): ClientAssertionVerifier {
  const now = options.now ?? (() => Date.now());
  const jtiStore = options.jtiStore ?? createJtiStore();
  const fetchOpts: CimdOptions = {
    ...(options.fetchImpl !== undefined ? { fetchImpl: options.fetchImpl } : {}),
    ...(options.resolveHost !== undefined ? { resolveHost: options.resolveHost } : {}),
    maxBytes: MAX_JWKS_BYTES,
    ...(options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {}),
  };

  return {
    async verify(input: ClientAssertionInput): Promise<AssertionResult> {
      const fail = (reason: AssertionRefusalReason): AssertionResult => ({ ok: false, reason });
      if (input.assertionType !== JWT_BEARER_ASSERTION_TYPE || !input.assertion) {
        return fail("unsupported client assertion");
      }
      // The unverified iss only LOCATES the key set; it is re-checked against the verified claims.
      const unverified = decodeUnverifiedPayload(input.assertion);
      if (!unverified) return fail("malformed client assertion");
      const claimedIss = unverified.iss;
      if (typeof claimedIss !== "string" || !claimedIss || !isUrlShapedClientId(claimedIss)) {
        return fail("unknown client");
      }
      if (input.clientId !== undefined && input.clientId !== claimedIss) {
        return fail("client_id does not match the assertion issuer");
      }
      const clientId = claimedIss;

      const cimd = await resolveCimdDocument(clientId, options);
      if (!cimd?.jwksUri) return fail("client has no verifiable key set");
      if (
        cimd.signingAlg !== undefined &&
        !(ASSERTION_SIGNING_ALGS as readonly string[]).includes(cimd.signingAlg)
      ) {
        return fail("unsupported signing algorithm");
      }
      let jwksUrl: URL;
      try {
        jwksUrl = new URL(cimd.jwksUri);
      } catch {
        return fail("invalid jwks_uri");
      }
      const jwks = (await fetchGuardedJson(jwksUrl, fetchOpts)) as { keys?: unknown } | null;
      if (!jwks || !Array.isArray(jwks.keys)) return fail("key set unavailable");

      const nowSeconds = Math.floor(now() / 1000);
      const payload = await verifyRs256Assertion(input.assertion, jwks.keys, {
        clientId,
        audiences: input.audiences,
        nowSeconds,
      });
      if (!payload) return fail("client assertion rejected");
      const exp = payload.exp as number;
      const jti = payload.jti;
      // A jti that is not a string cannot be held as an identity: stricter than the
      // boilerplate, which keyed the store on its string form.
      if (jti !== undefined && jti !== null && jti !== "" && typeof jti !== "string") {
        return fail("client assertion rejected");
      }
      // An empty jti is answered as the boilerplate answers it: never accepted, as a replay.
      if (!jti || !jtiStore.accept(clientId, jti, exp, nowSeconds)) {
        return fail("client assertion replayed");
      }
      return { ok: true, clientId };
    },
  };
}
