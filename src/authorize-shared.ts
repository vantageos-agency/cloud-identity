/**
 * Shared vocabulary of the person-authorization flow: the typed refusal, the
 * base64url and PKCE helpers, and the signed state blob. Internal to the
 * package except for the names `index.ts` re-exports.
 */

/**
 * Why the flow refused. Every refusal of the authorize flow, the token
 * exchange, the session verifier and the OIDC helpers carries one of these.
 */
export type AuthorizeRefusalReason =
  // request shape
  | "invalid-request"
  | "unknown-client"
  | "redirect-uri-mismatch"
  | "unsupported-response-type"
  | "pkce-required"
  | "resource-not-allowed"
  | "scope-not-supported"
  // signed state
  | "state-invalid"
  | "state-expired"
  // Clerk session
  | "session-required"
  | "session-invalid"
  | "jwks-unavailable"
  // organisation binding
  | "no-organization"
  | "org-not-a-member"
  | "consent-required"
  // collaborators that threw: fail closed, never grant
  | "client-lookup-unavailable"
  | "membership-lookup-unavailable"
  | "code-store-unavailable"
  | "server-misconfigured"
  // token exchange
  | "code-unknown"
  | "code-reused"
  | "code-expired"
  | "client-mismatch"
  | "redirect-uri-changed"
  | "resource-mismatch"
  | "verifier-malformed"
  | "pkce-mismatch"
  // OIDC
  | "subject-mismatch"
  | "openid-scope-required"
  | "issuer-invalid";

/**
 * The typed refusal: a non-empty object carrying its own code, in the same
 * `{ code, reason }` shape as `RoleRefusal` and `TenantAbsence`.
 */
export type AuthorizeRefusal = {
  code: "AUTHORIZE_REFUSED";
  reason: AuthorizeRefusalReason;
};

export function refusal(reason: AuthorizeRefusalReason): AuthorizeRefusal {
  return { code: "AUTHORIZE_REFUSED", reason };
}

/**
 * Maps a refusal to the OAuth error code and HTTP status a token or
 * authorize endpoint answers with (RFC 6749 section 5.2, RFC 8707).
 */
export function oauthErrorFor(r: AuthorizeRefusal): {
  error: string;
  status: number;
} {
  switch (r.reason) {
    case "unknown-client":
    case "client-mismatch":
      return { error: "invalid_client", status: 400 };
    case "unsupported-response-type":
      return { error: "unsupported_response_type", status: 400 };
    case "scope-not-supported":
      return { error: "invalid_scope", status: 400 };
    case "resource-not-allowed":
    case "resource-mismatch":
      return { error: "invalid_target", status: 400 };
    case "code-unknown":
    case "code-reused":
    case "code-expired":
    case "redirect-uri-changed":
    case "verifier-malformed":
    case "pkce-mismatch":
      return { error: "invalid_grant", status: 400 };
    case "session-required":
    case "session-invalid":
    case "no-organization":
    case "org-not-a-member":
    case "consent-required":
    case "subject-mismatch":
    case "openid-scope-required":
      return { error: "access_denied", status: 403 };
    case "jwks-unavailable":
    case "client-lookup-unavailable":
    case "membership-lookup-unavailable":
    case "code-store-unavailable":
      return { error: "temporarily_unavailable", status: 503 };
    case "server-misconfigured":
    case "issuer-invalid":
      return { error: "server_error", status: 500 };
    default:
      return { error: "invalid_request", status: 400 };
  }
}

// ---------------------------------------------------------------------------
// base64url
// ---------------------------------------------------------------------------

export function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(input: string): Uint8Array | null {
  if (!/^[A-Za-z0-9_-]*$/.test(input)) return null;
  const padded = input.replace(/-/g, "+").replace(/_/g, "/");
  try {
    const bin = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
    return Uint8Array.from(bin, (c) => c.charCodeAt(0));
  } catch {
    return null;
  }
}

export function utf8(input: string): Uint8Array {
  return new TextEncoder().encode(input);
}

// ---------------------------------------------------------------------------
// PKCE (RFC 7636)
// ---------------------------------------------------------------------------

/** The PKCE method name, assembled as one constant. */
export const PKCE_METHOD: string = ["S", "256"].join("");

const VERIFIER_RE = /^[A-Za-z0-9\-._~]{43,128}$/;
const CHALLENGE_RE = /^[A-Za-z0-9_-]{43}$/;

export function isWellFormedChallenge(challenge: string): boolean {
  return CHALLENGE_RE.test(challenge);
}

export function isWellFormedVerifier(verifier: string): boolean {
  return VERIFIER_RE.test(verifier);
}

/** `base64url(SHA-256(verifier))` — the challenge a client derives from its verifier. */
export async function pkceChallengeFromVerifier(
  verifier: string,
): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    utf8(verifier) as unknown as BufferSource,
  );
  return toBase64Url(new Uint8Array(digest));
}

// ---------------------------------------------------------------------------
// Signed state blob
// ---------------------------------------------------------------------------

export const MIN_SECRET_LENGTH = 32;

async function hmacKey(secret: string, usage: "sign" | "verify") {
  return crypto.subtle.importKey(
    "raw",
    utf8(secret) as unknown as BufferSource,
    { name: "HMAC", hash: "SHA-256" },
    false,
    [usage],
  );
}

/** `base64url(json).base64url(hmac)`. */
export async function signBlob(
  payload: unknown,
  secret: string,
): Promise<string> {
  const body = toBase64Url(utf8(JSON.stringify(payload)));
  const mac = await crypto.subtle.sign(
    "HMAC",
    await hmacKey(secret, "sign"),
    utf8(body) as unknown as BufferSource,
  );
  return `${body}.${toBase64Url(new Uint8Array(mac))}`;
}

/** Returns the parsed payload when the MAC verifies (constant time), else `null`. */
export async function verifyBlob(
  blob: string,
  secret: string,
): Promise<unknown | null> {
  const parts = blob.split(".");
  if (parts.length !== 2) return null;
  const [body, mac] = parts as [string, string];
  const macBytes = fromBase64Url(mac);
  if (!macBytes) return null;
  const ok = await crypto.subtle.verify(
    "HMAC",
    await hmacKey(secret, "verify"),
    macBytes as unknown as BufferSource,
    utf8(body) as unknown as BufferSource,
  );
  if (!ok) return null;
  const bodyBytes = fromBase64Url(body);
  if (!bodyBytes) return null;
  try {
    return JSON.parse(new TextDecoder().decode(bodyBytes));
  } catch {
    return null;
  }
}

