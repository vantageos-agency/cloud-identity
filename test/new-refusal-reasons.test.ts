import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { type IdentityRefusalReason, refusal } from "../src/identity-refusal.js";

/**
 * 0.28.0 adds two members to the closed IdentityRefusalReason union. The union
 * is the only declaration of the vocabulary (no runtime list or schema), so it
 * is read from the source, the same way identity-refusal-union.test.ts does.
 */
const src = readFileSync(join(__dirname, "..", "src", "identity-refusal.ts"), "utf8");
const start = src.indexOf("export type IdentityRefusalReason");
const members = [...src.slice(start, src.indexOf(";\n", start)).matchAll(/^\s*\|\s*"([^"]+)"/gm)].map((m) => m[1]);

describe("0.28.0 refusal reasons", () => {
  it("declares assignee-not-an-agent-of-org and no-organisation in the union", () => {
    expect(members).toContain("assignee-not-an-agent-of-org");
    expect(members).toContain("no-organisation");
  });

  it("both are accepted by the type and build a typed refusal that carries its own reason", () => {
    const a: IdentityRefusalReason = "assignee-not-an-agent-of-org";
    const b: IdentityRefusalReason = "no-organisation";
    expect(refusal("RBAC_DENIED", a, "door-a", "d").reason).toBe("assignee-not-an-agent-of-org");
    expect(refusal("RBAC_DENIED", b, "door-b", "d").reason).toBe("no-organisation");
  });

  it("an unknown reason is still refused by the type", () => {
    // @ts-expect-error not a member of the closed union
    const bad: IdentityRefusalReason = "not-a-declared-reason";
    expect(members).not.toContain(bad);
  });

  it("every previously declared reason is still declared (additive only)", () => {
    for (const kept of ["webhook-signature-mismatch", "webhook-secret-invalid", "webhook-headers-missing", "other-organisation", "membership-inactive"]) {
      expect(members).toContain(kept);
    }
  });
});
