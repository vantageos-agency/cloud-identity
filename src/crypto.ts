/**
 * Constant-time byte-array comparison.
 *
 * Takes `(Uint8Array, Uint8Array)` rather than strings so the helper stays
 * framework-agnostic and reusable by any caller: hash bytes, raw token
 * bytes, HMAC tags.
 *
 * Algorithm (identical to source):
 *   1. Length mismatch → still run a dummy Web Crypto HMAC over equal-length
 *      input to avoid a branch-timing leak, then return false.
 *   2. Equal length → XOR-accumulate diff across all bytes, return diff === 0.
 *
 * Web Crypto (`crypto.subtle`) is used for the dummy work (not Node's
 * `crypto.timingSafeEqual`) for portability across runtimes (Node 20+, Bun,
 * Deno, edge runtimes) and parity with the original Convex implementation.
 */
export async function timingSafeEqual(
  a: Uint8Array,
  b: Uint8Array,
): Promise<boolean> {
  if (a.length !== b.length) {
    // Still do a comparison on equal-length buffers to avoid branch-timing leak.
    const dummy = new Uint8Array(a.length);
    const keyMaterial = a.length > 0 ? a : new Uint8Array([0]);
    const aKey = await crypto.subtle.importKey(
      "raw",
      keyMaterial as unknown as BufferSource,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    await crypto.subtle.sign("HMAC", aKey, dummy as unknown as BufferSource);
    return false;
  }
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

/**
 * SHA-256 of a UTF-8 string as a lower-case hex digest.
 *
 * Exported because a consumer that STORES a bearer row must produce the digest
 * the same way the resolver will recompute it. Without this, each consumer
 * hashes its own way and the mismatch surfaces as "correct token refused".
 *
 * @security Hash the token once, store the digest, discard the token. This
 * function is one-way; it is not a substitute for a comparison — compare
 * digests with `timingSafeEqual`, never with `===`.
 */
export async function sha256Hex(input: string): Promise<string> {
  const data = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}
