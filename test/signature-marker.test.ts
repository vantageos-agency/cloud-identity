/**
 * `@signatureCompare` marks, in the published declarations, the package
 * functions that compare two secret values in constant time and answer a
 * boolean. `@signatureVerifier` marks the functions that compute a signature
 * over a delivery AND compare it with the received one, answering a verdict
 * whose `ok` is the result. A consumer's analyser (backend-doctor R-21) derives
 * which package calls finish a webhook verification from these markers instead
 * of a hand-typed list.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const ROOT = join(__dirname, "..");
const SRC = join(ROOT, "src");
const DIST = join(ROOT, "dist");

function tagged(dir: string, tag: string, decl: RegExp): string[] {
  const names: string[] = [];
  const line = new RegExp(`^[ \\t]*\\*?[ \\t]*${tag}(?![\\w$])`, "m");
  for (const file of readdirSync(dir).filter((f) => f.endsWith(".ts"))) {
    const text = readFileSync(join(dir, file), "utf8");
    for (const m of text.matchAll(decl)) {
      if (line.test(m[1])) names.push(m[2]);
    }
  }
  return names.sort();
}

const SRC_DECL = /\/\*\*((?:(?!\*\/)[\s\S])*?)\*\/\s*export\s+(?:async\s+)?function\s+(\w+)/g;
const DTS_DECL = /\/\*\*((?:(?!\*\/)[\s\S])*?)\*\/\s*export\s+declare\s+function\s+(\w+)/g;

const COMPARES = ["timingSafeEqual", "timingSafeEqualSync"];
const VERIFIERS = ["verifyHmacSha256Signature", "verifySvixWebhook"];

describe("@signatureCompare / @signatureVerifier markers", () => {
  it("@signatureCompare marks exactly the constant-time comparators", () => {
    expect(tagged(SRC, "@signatureCompare", SRC_DECL)).toEqual(COMPARES);
  });

  it("@signatureVerifier marks exactly the compute-and-compare verifiers", () => {
    expect(tagged(SRC, "@signatureVerifier", SRC_DECL)).toEqual(VERIFIERS);
  });

  it("every marked function is exported from the package root", () => {
    const index = readFileSync(join(SRC, "index.ts"), "utf8");
    for (const name of [...COMPARES, ...VERIFIERS]) expect(index).toMatch(new RegExp(`\\b${name}\\b`));
  });

  it("both markers survive into the built declarations, as block tags directly above the declaration", () => {
    expect(existsSync(DIST)).toBe(true);
    expect(tagged(DIST, "@signatureCompare", DTS_DECL)).toEqual(COMPARES);
    expect(tagged(DIST, "@signatureVerifier", DTS_DECL)).toEqual(VERIFIERS);
  });
});
