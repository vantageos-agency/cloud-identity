/**
 * Master-token Bearer validation.
 *
 * Extracted from the master-gate logic in
 * `vantage-memory/mcp-server/server-http.ts` (`masterOnlyMiddleware`) and
 * HARDENED per @vantageos/cloud-identity 0.1.0 contract:
 *   - SHA-256 hash both the presented token AND the configured master secret,
 *     then compare the two digests with `timingSafeEqual` (constant time).
 *   - The original middleware did a direct `token !== masterToken` string
 *     compare which is non-constant-time. This brick fixes that leak so any
 *     caller using `validateMasterBearer` inherits the safer behaviour.
 *
 * Surface:
 *   `validateMasterBearer(authHeader, masterSecret) → ValidateMasterBearerResult`
 *
 * Errors are coarse-grained on purpose — callers should not surface the exact
 * reason to remote clients beyond a generic 401/403.
 */

import { timingSafeEqual } from "./crypto.js";
import type { ValidateMasterBearerResult } from "./types.js";

const BEARER_PREFIX_LOWER = "bearer ";

async function sha256Bytes(input: string): Promise<Uint8Array> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return new Uint8Array(digest);
}

/**
 * Validate an `Authorization: Bearer <token>` header against a configured
 * master secret.
 *
 *   - missing header  → `{ok: false, error: "missing"}`
 *   - bad format / empty token / empty secret → `{ok: false, error: "malformed"}`
 *   - token sha256 != master sha256 (constant-time) → `{ok: false, error: "mismatch"}`
 *   - match → `{ok: true}`
 *
 * The scheme prefix match is case-insensitive (RFC 7235 §2.1) but the token
 * itself is treated as opaque bytes.
 */
export async function validateMasterBearer(
  authHeader: string | undefined,
  masterSecret: string,
): Promise<ValidateMasterBearerResult> {
  if (authHeader === undefined || authHeader === null || authHeader === "") {
    return { ok: false, error: "missing" };
  }
  if (!masterSecret || masterSecret.length === 0) {
    return { ok: false, error: "malformed" };
  }
  // Case-insensitive scheme match without lower-casing the token bytes.
  const lower = authHeader.toLowerCase();
  if (!lower.startsWith(BEARER_PREFIX_LOWER)) {
    return { ok: false, error: "malformed" };
  }
  const token = authHeader.slice(BEARER_PREFIX_LOWER.length).trim();
  if (token.length === 0) {
    return { ok: false, error: "malformed" };
  }
  const [tokenDigest, secretDigest] = await Promise.all([
    sha256Bytes(token),
    sha256Bytes(masterSecret),
  ]);
  const ok = await timingSafeEqual(tokenDigest, secretDigest);
  return ok ? { ok: true } : { ok: false, error: "mismatch" };
}
