import type { AuthorizationCodeStore } from "./authorize-flow.js";
import {
  type AuthorizeRefusal,
  isWellFormedVerifier,
  pkceChallengeFromVerifier,
  refusal,
  toBase64Url,
  utf8,
} from "./authorize-shared.js";
import { sha256Hex, timingSafeEqual } from "./crypto.js";

/**
 * The claims a token minted from an authorization code carries. They are
 * copied from the code's own binding, which was written from the verified
 * Clerk user and a membership that user holds. There is no `scopeProfile`
 * here and no code path that reads one: an identity is never supplied by the
 * client-registration row.
 */
export interface AuthorizedTokenClaims {
  sub: string;
  org_id: string;
  org_slug: string | null;
  org_role: string;
  aud: string;
  client_id: string;
  scope: string;
}

export interface ExchangeInput {
  /** The authorization code the client presents. */
  code: string;
  /** PKCE verifier (RFC 7636). */
  codeVerifier: string;
  /** Must equal the redirect_uri of the authorize request. */
  redirectUri: string;
  /** The authenticated client's id. */
  clientId: string;
  /** Optional RFC 8707 resource; when present it must equal the bound one. */
  resource?: string;
}

export interface ExchangeDeps {
  codeStore: AuthorizationCodeStore;
  /** Epoch milliseconds. */
  now?: () => number;
}

export type ExchangeResult =
  | { ok: true; claims: AuthorizedTokenClaims }
  | { ok: false; refusal: AuthorizeRefusal };

const fail = (reason: Parameters<typeof refusal>[0]): ExchangeResult => ({
  ok: false,
  refusal: refusal(reason),
});

/**
 * Redeems an authorization code. The code is CONSUMED first (atomically, by
 * the store) so that every attempt, successful or not, burns it: a wrong
 * verifier cannot be retried against the same code. A code presented twice is
 * `code-reused`, distinct from `code-unknown`, so the consumer can revoke what
 * the first redemption issued.
 *
 * Checks, in order: expiry, client, redirect_uri, resource, PKCE.
 */
export async function exchangeAuthorizationCode(
  input: ExchangeInput,
  deps: ExchangeDeps,
): Promise<ExchangeResult> {
  if (typeof input.code !== "string" || input.code.length === 0) {
    return fail("code-unknown");
  }
  let consumed;
  try {
    consumed = await deps.codeStore.consume(await sha256Hex(input.code));
  } catch {
    return fail("code-store-unavailable");
  }
  if (consumed.status === "unknown") return fail("code-unknown");
  if (consumed.status === "already-used") return fail("code-reused");
  const rec = consumed.record;

  if (rec.expiresAt <= (deps.now ?? Date.now)()) return fail("code-expired");
  if (rec.clientId !== input.clientId) return fail("client-mismatch");
  if (rec.redirectUri !== input.redirectUri) return fail("redirect-uri-changed");
  if (input.resource !== undefined && input.resource !== rec.resource) {
    return fail("resource-mismatch");
  }

  if (!isWellFormedVerifier(input.codeVerifier)) return fail("verifier-malformed");
  const derived = await pkceChallengeFromVerifier(input.codeVerifier);
  if (!(await timingSafeEqual(utf8(derived), utf8(rec.codeChallenge)))) {
    return fail("pkce-mismatch");
  }

  return {
    ok: true,
    claims: {
      sub: rec.clerkUserId,
      org_id: rec.orgId,
      org_slug: rec.orgSlug,
      org_role: rec.orgRole,
      aud: rec.resource,
      client_id: rec.clientId,
      scope: rec.scope,
    },
  };
}

// ---------------------------------------------------------------------------
// refresh_token grant (OAuth 2.1 section 4.3; RFC 9700 section 4.14)
// ---------------------------------------------------------------------------

/** How long a refresh token lives: 30 days. */
export const REFRESH_TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;

/**
 * What the store keeps for one refresh token. `tokenHash` is the SHA-256 hex
 * digest of the opaque token; the token itself is never stored. `familyId`
 * ties every token rotated from the same authorization together, so a replay
 * can revoke them all. `claims` are what the next access token is minted from.
 */
export interface RefreshTokenRecord {
  tokenHash: string;
  familyId: string;
  claims: AuthorizedTokenClaims;
  /** Epoch milliseconds. */
  issuedAt: number;
  /** Epoch milliseconds. */
  expiresAt: number;
}

export type ConsumeRefreshResult =
  | { status: "ok"; record: RefreshTokenRecord }
  | { status: "unknown" }
  | { status: "already-used"; familyId: string };

/**
 * Where refresh tokens live. A durable adapter MUST:
 * - key records by the digest only (`put` receives no raw token);
 * - make `consume` atomic: of two concurrent calls for the same digest exactly
 *   one gets `ok` (a read-then-write is not an implementation). A consumed
 *   record is KEPT, marked used, so a replay answers `already-used` with its
 *   `familyId` instead of `unknown`;
 * - make `revokeFamily` leave every token of the family, including ones issued
 *   after the call began, refused by `consume` (`already-used` or `unknown`);
 * - sweep records past `expiresAt` in its own time (this package checks expiry
 *   itself and does not delete);
 * - throw on any failure: a store that cannot answer must not answer.
 */
export interface RefreshTokenStore {
  put(record: RefreshTokenRecord): Promise<void>;
  consume(tokenHash: string): Promise<ConsumeRefreshResult>;
  revokeFamily(familyId: string): Promise<void>;
}

export interface RefreshTokenIssueDeps {
  refreshStore: RefreshTokenStore;
  /** Epoch milliseconds. */
  now?: () => number;
  /** Lifetime of the token. Default `REFRESH_TOKEN_TTL_MS`. */
  ttlMs?: number;
  /** Join an existing family (rotation). Default: a new family. */
  familyId?: string;
  /** Token generator, for tests. Default: 32 random bytes, base64url. */
  randomToken?: () => string;
}

function randomOpaque(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

/**
 * Issues an opaque refresh token for `claims` and stores ONLY its SHA-256
 * digest. The raw token is returned once and exists nowhere else.
 */
export async function issueRefreshToken(
  claims: AuthorizedTokenClaims,
  deps: RefreshTokenIssueDeps,
): Promise<{ refreshToken: string; expiresAt: number }> {
  const issuedAt = (deps.now ?? Date.now)();
  const expiresAt = issuedAt + (deps.ttlMs ?? REFRESH_TOKEN_TTL_MS);
  const refreshToken = (deps.randomToken ?? randomOpaque)();
  await deps.refreshStore.put({
    tokenHash: await sha256Hex(refreshToken),
    familyId: deps.familyId ?? crypto.randomUUID(),
    claims,
    issuedAt,
    expiresAt,
  });
  return { refreshToken, expiresAt };
}

export interface RefreshExchangeInput {
  /** The refresh token the client presents. */
  refreshToken: string;
  /** The authenticated client's id. */
  clientId: string;
  /** Optional RFC 8707 resource; when present it must equal the bound audience. */
  resource?: string;
}

export interface RefreshExchangeDeps {
  refreshStore: RefreshTokenStore;
  /** Epoch milliseconds. */
  now?: () => number;
  /** Lifetime of the rotated token. Default `REFRESH_TOKEN_TTL_MS`. */
  ttlMs?: number;
  /**
   * REQUIRED. Called with the stored claims before anything new is issued; the
   * consumer re-checks, now, that the person still holds the membership and
   * role, and returns the claims to mint from (a role may have changed).
   * `{ ok: false }` (or a throw) refuses and revokes the family.
   */
  reauthorize: (
    claims: AuthorizedTokenClaims,
  ) => Promise<{ ok: true; claims: AuthorizedTokenClaims } | { ok: false }>;
}

export type RefreshExchangeResult =
  | {
      ok: true;
      claims: AuthorizedTokenClaims;
      refreshToken: string;
      expiresAt: number;
    }
  | { ok: false; refusal: AuthorizeRefusal };

const refreshFail = (
  reason: Parameters<typeof refusal>[0],
): RefreshExchangeResult => ({ ok: false, refusal: refusal(reason) });

/**
 * Redeems a refresh token with rotation. The token is CONSUMED first
 * (atomically, by the store), so every attempt burns it. A token presented
 * twice is `refresh-reused`: the whole family is revoked, because either the
 * client or a thief holds a stale copy and the two cannot be told apart
 * (RFC 9700 section 4.14). A refusal after the consume leaves the token burnt.
 *
 * Checks, in order: shape, consume, reuse, expiry, client, resource,
 * reauthorization. On success a NEW token is issued in the SAME family, from
 * the reauthorized claims.
 */
export async function exchangeRefreshToken(
  input: RefreshExchangeInput,
  deps: RefreshExchangeDeps,
): Promise<RefreshExchangeResult> {
  if (typeof input.refreshToken !== "string" || input.refreshToken.length === 0) {
    return refreshFail("refresh-unknown");
  }
  let consumed;
  try {
    consumed = await deps.refreshStore.consume(await sha256Hex(input.refreshToken));
  } catch {
    return refreshFail("refresh-store-unavailable");
  }
  if (consumed.status === "unknown") return refreshFail("refresh-unknown");
  if (consumed.status === "already-used") {
    try {
      await deps.refreshStore.revokeFamily(consumed.familyId);
    } catch {
      // Refused either way; the replayed token never yields a new one.
    }
    return refreshFail("refresh-reused");
  }
  const rec = consumed.record;

  const now = deps.now ?? Date.now;
  if (rec.expiresAt <= now()) return refreshFail("refresh-expired");
  if (rec.claims.client_id !== input.clientId) return refreshFail("client-mismatch");
  if (input.resource !== undefined && input.resource !== rec.claims.aud) {
    return refreshFail("resource-mismatch");
  }

  const revoke = async () => {
    try {
      await deps.refreshStore.revokeFamily(rec.familyId);
    } catch {
      // Refused either way.
    }
  };
  let again;
  try {
    again = await deps.reauthorize(rec.claims);
  } catch {
    await revoke();
    return refreshFail("refresh-reauthorization-failed");
  }
  if (!again.ok) {
    await revoke();
    return refreshFail("refresh-reauthorization-failed");
  }

  try {
    const next = await issueRefreshToken(again.claims, {
      refreshStore: deps.refreshStore,
      now,
      ttlMs: deps.ttlMs,
      familyId: rec.familyId,
    });
    return { ok: true, claims: again.claims, ...next };
  } catch {
    return refreshFail("refresh-store-unavailable");
  }
}
