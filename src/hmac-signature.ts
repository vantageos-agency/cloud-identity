/**
 * Generic HMAC-SHA256 body-signature verification, Web Crypto only.
 *
 * For a provider that signs the raw request body with a shared secret and sends
 * the digest in a header (hex or base64, optionally prefixed `sha256=`). It is
 * pure: no store, no clock, no `node:crypto`, so it runs in Convex and on any
 * edge runtime, and a narrow import (`./hmac-signature`) bundles no `@clerk`
 * module. The refusal carries neither the secret, the signature nor the body,
 * and nothing is logged.
 */

import { type IdentityRefusal, refusal } from "./identity-refusal.js";
import { timingSafeEqualSync } from "./secret-compare-sync.js";

/** How the digest in the header is written. Default `hex`. */
export type HmacSignatureEncoding = "hex" | "base64";

/** The raw body, exactly as received, and the signature header value. */
export type HmacSignatureDelivery = {
  /** The body before any parse: text, or bytes (signed as UTF-8 text would be). */
  body: string | Uint8Array;
  /** The header value: the digest, optionally prefixed `sha256=`. Absent or empty refuses. */
  signature?: string | null;
};

export type VerifyHmacSha256SignatureOptions = {
  /** The shared secret, used as its UTF-8 bytes. Absent or empty refuses. */
  secret?: string | null;
  /** `hex` (default, either case) or `base64` (standard alphabet, padded). */
  encoding?: HmacSignatureEncoding;
};

export type VerifyHmacSha256SignatureResult = { ok: true } | { ok: false; refusal: IdentityRefusal };

const DOOR = "hmac-signature:verifyHmacSha256Signature";
const PREFIX = "sha256=";
const DIGEST_BYTES = 32;

function hexToBytes(hex: string): Uint8Array | null {
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) return null;
  const out = new Uint8Array(DIGEST_BYTES);
  for (let i = 0; i < DIGEST_BYTES; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function base64ToBytes(b64: string): Uint8Array | null {
  // A SHA-256 digest is 32 bytes: 44 base64 characters, one `=` of padding.
  if (!/^[A-Za-z0-9+/]{43}=$/.test(b64)) return null;
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.length === DIGEST_BYTES ? out : null;
  } catch {
    return null;
  }
}

/**
 * Verifies `signature` as the HMAC-SHA256 of `body` keyed by `secret`.
 *
 * Refusals (`CREDENTIAL_REFUSED`, no new reason word):
 * - `webhook-secret-invalid`: the secret is absent, not a string or empty (a
 *   server misconfiguration, so answer 500). An empty key never verifies.
 * - `webhook-headers-missing`: the signature is absent, not a string, or empty
 *   once the optional `sha256=` prefix is removed.
 * - `webhook-signature-mismatch`: anything else, a wrong digest and a
 *   malformed one alike (wrong length, non-hex, bad base64). One reason, so the
 *   refusal does not say how the presented value was wrong.
 *
 * The presented digest is always decoded to 32 bytes (a malformed one becomes
 * 32 zero bytes) and compared with the package's `timingSafeEqualSync`, so the
 * work does not depend on where, or whether, the value differs. A malformed
 * value can never pass, whatever the compare returns.
 */
export async function verifyHmacSha256Signature(
  delivery: HmacSignatureDelivery,
  options: VerifyHmacSha256SignatureOptions,
): Promise<VerifyHmacSha256SignatureResult> {
  const deny = (reason: Parameters<typeof refusal>[1], detail: string): VerifyHmacSha256SignatureResult => ({
    ok: false,
    refusal: refusal("CREDENTIAL_REFUSED", reason, DOOR, detail),
  });

  const { secret } = options;
  if (typeof secret !== "string" || secret.length === 0) {
    return deny("webhook-secret-invalid", "The signing secret is absent or empty.");
  }

  const presented = delivery.signature;
  const value = typeof presented === "string" && presented.startsWith(PREFIX) ? presented.slice(PREFIX.length) : presented;
  if (typeof value !== "string" || value.length === 0) {
    return deny("webhook-headers-missing", "The signature is absent or empty.");
  }

  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const data = typeof delivery.body === "string" ? new TextEncoder().encode(delivery.body) : delivery.body;
  const expected = new Uint8Array(await crypto.subtle.sign("HMAC", key, data as BufferSource));

  const decoded = options.encoding === "base64" ? base64ToBytes(value) : hexToBytes(value);
  const equal = timingSafeEqualSync(expected, decoded ?? new Uint8Array(DIGEST_BYTES));
  return equal && decoded !== null
    ? { ok: true }
    : deny("webhook-signature-mismatch", "The signature does not match the body.");
}
