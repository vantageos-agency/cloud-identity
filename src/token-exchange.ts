import type { AuthorizationCodeStore } from "./authorize-flow.js";
import {
  type AuthorizeRefusal,
  isWellFormedVerifier,
  pkceChallengeFromVerifier,
  refusal,
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
