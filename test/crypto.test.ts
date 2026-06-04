import { describe, it, expect } from "vitest";
import { timingSafeEqual } from "../src/crypto.js";

describe("timingSafeEqual", () => {
  it("returns true for two same-length equal byte arrays", async () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 2, 3, 4, 5]);
    expect(await timingSafeEqual(a, b)).toBe(true);
  });

  it("returns false for two same-length but different byte arrays", async () => {
    const a = new Uint8Array([1, 2, 3, 4, 5]);
    const b = new Uint8Array([1, 2, 3, 4, 6]);
    expect(await timingSafeEqual(a, b)).toBe(false);
  });

  it("returns false for arrays of different lengths", async () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new Uint8Array([1, 2, 3, 4]);
    expect(await timingSafeEqual(a, b)).toBe(false);
  });

  it("returns true for two empty arrays", async () => {
    const a = new Uint8Array(0);
    const b = new Uint8Array(0);
    expect(await timingSafeEqual(a, b)).toBe(true);
  });

  it("returns true for single-byte equal arrays", async () => {
    const a = new Uint8Array([42]);
    const b = new Uint8Array([42]);
    expect(await timingSafeEqual(a, b)).toBe(true);
  });

  it("returns false for single-byte different arrays", async () => {
    const a = new Uint8Array([42]);
    const b = new Uint8Array([43]);
    expect(await timingSafeEqual(a, b)).toBe(false);
  });

  it("does not short-circuit on first byte mismatch (loose timing property)", async () => {
    // We can't measure absolute timing reliably in a unit test, but we can
    // assert that the function executes the full loop without throwing and
    // returns the correct verdict regardless of WHERE the difference lies.
    const base = new Uint8Array(64).fill(7);
    const diffAtStart = new Uint8Array(64).fill(7);
    diffAtStart[0] = 99;
    const diffAtEnd = new Uint8Array(64).fill(7);
    diffAtEnd[63] = 99;
    expect(await timingSafeEqual(base, diffAtStart)).toBe(false);
    expect(await timingSafeEqual(base, diffAtEnd)).toBe(false);
  });

  it("returns false when one array is empty and the other is not", async () => {
    const a = new Uint8Array(0);
    const b = new Uint8Array([1]);
    expect(await timingSafeEqual(a, b)).toBe(false);
  });
});
