import { describe, it, expect } from "vitest";
import {
  timingSafeEqualSync,
  assertSecretSync,
  IdentityRefusalError,
} from "../src/index.js";

// Synthetic placeholders; nothing here is a live secret.
const A = "synthetic-secret-one";

function refusalOf(fn: () => void) {
  try {
    fn();
  } catch (e) {
    expect(e).toBeInstanceOf(IdentityRefusalError);
    return (e as IdentityRefusalError).refusal;
  }
  throw new Error("expected a refusal");
}

describe("timingSafeEqualSync", () => {
  it("true for equal strings and equal byte arrays", () => {
    expect(timingSafeEqualSync(A, A)).toBe(true);
    expect(timingSafeEqualSync(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
    expect(timingSafeEqualSync("", "")).toBe(true);
  });

  it("a string equals its UTF-8 bytes", () => {
    expect(timingSafeEqualSync("héllo", new TextEncoder().encode("héllo"))).toBe(true);
  });

  it("false when one byte differs, at any position", () => {
    const base = "abcdefgh";
    for (let i = 0; i < base.length; i++) {
      const mutated = base.slice(0, i) + "Z" + base.slice(i + 1);
      expect(timingSafeEqualSync(base, mutated)).toBe(false);
    }
  });

  it("false on length mismatch, in both directions, including a shared prefix and a zero-padded tail", () => {
    expect(timingSafeEqualSync("abc", "abcd")).toBe(false);
    expect(timingSafeEqualSync("abcd", "abc")).toBe(false);
    expect(timingSafeEqualSync(new Uint8Array([1, 2]), new Uint8Array([1, 2, 0]))).toBe(false);
    expect(timingSafeEqualSync(new Uint8Array([1, 2, 0]), new Uint8Array([1, 2]))).toBe(false);
    expect(timingSafeEqualSync("", "a")).toBe(false);
  });

  it("false (not a throw) for a non string / non byte-array input", () => {
    expect(timingSafeEqualSync(undefined as never, "a")).toBe(false);
    expect(timingSafeEqualSync("a", null as never)).toBe(false);
    expect(timingSafeEqualSync(5 as never, 5 as never)).toBe(false);
  });

  it("is synchronous: returns a boolean, not a promise", () => {
    expect(typeof timingSafeEqualSync(A, A)).toBe("boolean");
  });

  it("does not exit early on content: every byte index is read for a same-length mismatch", () => {
    // A Proxy-wrapped array counts reads. An early-exit comparator would read
    // far fewer than length elements when the first byte already differs.
    const reads: number[] = [];
    const watch = (bytes: number[]) =>
      new Proxy(new Uint8Array(bytes), {
        get(target, prop) {
          if (typeof prop === "string" && /^\d+$/.test(prop)) reads.push(Number(prop));
          return Reflect.get(target, prop);
        },
      });
    const n = 16;
    const x = watch(Array.from({ length: n }, () => 1));
    const y = new Uint8Array(Array.from({ length: n }, (_, i) => (i === 0 ? 9 : 1)));
    expect(timingSafeEqualSync(x, y)).toBe(false);
    expect(new Set(reads).size).toBe(n);
  });
});

describe("assertSecretSync", () => {
  it("returns when the presented secret equals the expected one", () => {
    expect(() => assertSecretSync(A, A)).not.toThrow();
  });

  it("throws a typed refusal on mismatch", () => {
    const r = refusalOf(() => assertSecretSync("wrong", A));
    expect(r.code).toBe("CREDENTIAL_REFUSED");
    expect(r.reason).toBe("secret-mismatch");
    // the refusal carries no secret
    expect(JSON.stringify(r)).not.toContain(A);
  });

  it("an unset expected secret matches NOTHING — not even an equally empty presentation", () => {
    for (const expected of [undefined, null, ""]) {
      for (const presented of ["anything", "", undefined, null]) {
        const r = refusalOf(() => assertSecretSync(presented, expected));
        expect(r.reason).toBe("secret-not-configured");
      }
    }
  });

  it("refuses an absent or empty presented secret against a configured one", () => {
    for (const presented of [undefined, null, ""]) {
      expect(refusalOf(() => assertSecretSync(presented, A)).reason).toBe("secret-mismatch");
    }
  });

  it("refuses a length mismatch and a prefix", () => {
    expect(() => assertSecretSync(A.slice(0, -1), A)).toThrow(IdentityRefusalError);
    expect(() => assertSecretSync(`${A}x`, A)).toThrow(IdentityRefusalError);
  });

  it("names the supplied door", () => {
    expect(refusalOf(() => assertSecretSync("x", A, "admin:reset")).door).toBe("admin:reset");
  });
});
