/**
 * `@callerResolver` marks, in the published declarations, the package functions
 * that resolve a verified caller. A consumer's analyser (backend-doctor CR-2)
 * derives its accepted sinks for a verified identity from this marker instead
 * of a hand-typed list, so a new resolver needs no analyser edit.
 */
import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(__dirname, "..", "src");

function taggedFunctions(): string[] {
  const names: string[] = [];
  for (const file of readdirSync(SRC).filter((f) => f.endsWith(".ts"))) {
    const text = readFileSync(join(SRC, file), "utf8");
    const re = /\/\*\*((?:(?!\*\/)[\s\S])*?)\*\/\s*export\s+(?:async\s+)?function\s+(\w+)/g;
    for (const m of text.matchAll(re)) {
      if (/@callerResolver\b/.test(m[1])) names.push(m[2]);
    }
  }
  return names.sort();
}

describe("@callerResolver marker", () => {
  it("marks exactly the package's caller resolvers", () => {
    expect(taggedFunctions()).toEqual(
      [
        "resolveActingPrincipal",
        "resolveCallerFromAgentCredential",
        "resolveCallerFromClaims",
        "resolveConvexMachineCaller",
        "resolveConvexMachineCallerFromDigest",
        "resolvePersonPrincipal",
        "requireTenantFromIdentity",
        "requireSubjectFromIdentity",
        "resolveSupportAccess",
        "resolveAgentLink",
        "resolveAgentWriter",
        "resolvePersonalAgent",
        "resolveAgentWriterFromIdentity",
      ].sort(),
    );
  });

  it("every marked resolver is exported from the package root", () => {
    const index = readFileSync(join(SRC, "index.ts"), "utf8");
    for (const name of taggedFunctions()) {
      expect(index).toMatch(new RegExp(`\\b${name}\\b`));
    }
  });

  it("the marker survives into the declarations (no removeComments)", () => {
    const tsconfig = readFileSync(join(SRC, "..", "tsconfig.json"), "utf8");
    expect(tsconfig).not.toMatch(/"removeComments"\s*:\s*true/);
  });
});
