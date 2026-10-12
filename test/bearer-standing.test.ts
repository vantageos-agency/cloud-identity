import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { bearerStanding } from "../src/scope-standing.js";

// The context an MCP transport attaches to a request after verifying its
// bearer: `isMaster` for the master population, `viaMasterBearer` set ONLY when
// that master presented the network master bearer (the fleet service account).
// A master without it is process-local trust (a stdio server on the operator's
// machine), which never crossed the network.
describe("bearerStanding", () => {
  it("the master bearer is service-bearer", () => {
    expect(bearerStanding({ isMaster: true, viaMasterBearer: true })).toBe("service-bearer");
  });

  it("a master with no network bearer is local-trust", () => {
    expect(bearerStanding({ isMaster: true })).toBe("local-trust");
  });

  it("a non-master token is caller", () => {
    expect(bearerStanding({ isMaster: false })).toBe("caller");
  });

  it("fails closed: no context, a non-boolean isMaster, or a master bearer flag on a non-master is refused", () => {
    expect(bearerStanding(undefined)).toBe("refused");
    expect(bearerStanding(null)).toBe("refused");
    expect(bearerStanding({})).toBe("refused");
    expect(bearerStanding({ isMaster: "true" })).toBe("refused");
    expect(bearerStanding({ isMaster: false, viaMasterBearer: true })).toBe("refused");
    expect(bearerStanding({ isMaster: true, viaMasterBearer: "yes" })).toBe("refused");
  });
});

// `@standingGate` marks, in the published declarations, the package functions
// that judge a resolved scope or a verified bearer context. A consumer's
// analyser credits a call to a tagged function as a delegated gate instead of
// keeping a hand-typed list.
const SRC = join(__dirname, "..", "src");

function taggedFunctions(): string[] {
  const names: string[] = [];
  for (const file of readdirSync(SRC).filter((f) => f.endsWith(".ts"))) {
    const text = readFileSync(join(SRC, file), "utf8");
    const re = /\/\*\*((?:(?!\*\/)[\s\S])*?)\*\/\s*export\s+(?:async\s+)?function\s+(\w+)/g;
    for (const m of text.matchAll(re)) {
      if (/@standingGate\b/.test(m[1])) names.push(m[2]);
    }
  }
  return names.sort();
}

describe("@standingGate marker", () => {
  it("marks exactly the package's standing gates", () => {
    expect(taggedFunctions()).toEqual(
      [
        "bearerStanding",
        "hasFleetRead",
        "isServiceAccountScope",
        "requireFleetStanding",
        "requireServiceAccountStanding",
        "requireStanding",
        "scopeStanding",
      ].sort(),
    );
  });

  it("every marked gate is exported from the package root", () => {
    const index = readFileSync(join(SRC, "index.ts"), "utf8");
    for (const name of taggedFunctions()) {
      expect(index).toMatch(new RegExp(`\\b${name}\\b`));
    }
  });
});
