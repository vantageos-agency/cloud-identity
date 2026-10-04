/**
 * Synchronous constant-time secret comparison.
 *
 * `timingSafeEqual` in `./crypto` is async (it uses Web Crypto for its dummy
 * work) and takes bytes. A synchronous call site — a plain admin-secret gate,
 * a framework hook that cannot await — needs a synchronous equivalent. This is
 * pure JavaScript with no runtime dependency, so it also runs on any edge
 * runtime. The async comparator is unchanged.
 *
 * Constant time here means: the number of loop iterations depends only on the
 * LONGER input's length, never on where the first difference is. JavaScript
 * gives no hard timing guarantee; this removes the content-dependent early
 * exit, which is the leak a naive `===` has.
 */

import { IdentityRefusalError, refusal } from "./identity-refusal.js";

const encoder = new TextEncoder();

function toBytes(value: unknown): Uint8Array | null {
  if (typeof value === "string") return encoder.encode(value);
  if (value instanceof Uint8Array) return value;
  return null;
}

/**
 * Compare two strings (UTF-8) or byte arrays in constant time with respect to
 * their content. Always walks the longer length; a length difference is folded
 * into the result rather than returned early. Any other input type is `false`.
 */
export function timingSafeEqualSync(
  a: string | Uint8Array,
  b: string | Uint8Array,
): boolean {
  const x = toBytes(a);
  const y = toBytes(b);
  if (x === null || y === null) return false;
  const xl = x.length;
  const yl = y.length;
  const max = xl > yl ? xl : yl;
  let diff = xl ^ yl;
  for (let i = 0; i < max; i++) {
    const xi = i < xl ? (x[i] as number) : 0;
    const yi = i < yl ? (y[i] as number) : 0;
    diff |= xi ^ yi;
  }
  return diff === 0;
}

/**
 * Assert a presented secret equals the configured one. Throws
 * `IdentityRefusalError` (`CREDENTIAL_REFUSED`) on mismatch. An unset expected
 * secret (undefined, null, empty) matches NOTHING, not even an empty
 * presentation: a missing configuration must never open a door. The refusal
 * carries neither value.
 */
export function assertSecretSync(
  presented: string | Uint8Array | null | undefined,
  expected: string | Uint8Array | null | undefined,
  door = "assertSecretSync",
): void {
  const expectedBytes = toBytes(expected);
  if (expectedBytes === null || expectedBytes.length === 0) {
    throw new IdentityRefusalError(
      refusal(
        "CREDENTIAL_REFUSED",
        "secret-not-configured",
        door,
        "No secret is configured for this entry point, so nothing can match.",
      ),
    );
  }
  const presentedBytes = toBytes(presented) ?? new Uint8Array(0);
  // Compare even when presented is empty so the work does not depend on it.
  const equal = timingSafeEqualSync(presentedBytes, expectedBytes);
  if (!equal || presentedBytes.length === 0) {
    throw new IdentityRefusalError(
      refusal(
        "CREDENTIAL_REFUSED",
        "secret-mismatch",
        door,
        "The presented secret does not match.",
      ),
    );
  }
}
