/**
 * Constant-time byte-array comparison.
 *
 * Ported from `vantage-memory/mcp-server/src/crypto.ts` (Day 47 master-token
 * gate, Eta F1 MAJOR PR #621). Surface adapted from `(string, string)` to
 * `(Uint8Array, Uint8Array)` per @vantageos/cloud-identity 0.1.0 contract so
 * the helper is framework-agnostic and reusable by any caller (hash bytes,
 * raw token bytes, HMAC tags, etc.).
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
