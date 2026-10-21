import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

describe("IdentityRefusalReason", () => {
  it("names each reason once: no union member is repeated in the source", () => {
    const src = readFileSync(join(__dirname, "..", "src", "identity-refusal.ts"), "utf8");
    const start = src.indexOf("export type IdentityRefusalReason");
    expect(start).toBeGreaterThan(-1);
    const end = src.indexOf(";\n", start);
    const members = [...src.slice(start, end).matchAll(/^\s*\|\s*"([^"]+)"/gm)].map((m) => m[1]);
    expect(members.length).toBeGreaterThan(0);
    const dupes = members.filter((m, i) => members.indexOf(m) !== i);
    expect(dupes).toEqual([]);
  });
});
