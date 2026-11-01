import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { resolveCallerFromClaims } from "../src/caller-from-claims.js";
import { type IdentityRefusal, type IdentityRefusalReason, noOrganisationRefusal } from "../src/identity-refusal.js";
import * as root from "../src/index.js";
import { resolveOrgFromClaim } from "../src/org-by-id.js";

/**
 * 0.32.0: the producer of the `no-organisation` refusal declared in 0.28.0.
 * A verified identity with no organisation attached is refused by the package's
 * resolvers with `no-verified-organisation`; `noOrganisationRefusal` turns that
 * refusal into the `no-organisation` refusal a consumer's door forwards, and
 * answers null for every other refusal.
 */

const ORG_A = "org_aaa";
const mappingA = { id: ORG_A, label: "acme", active: true, allowedOrchestrators: [], scopes: [], orgKind: "operator" };
const deps = {
  orgLookups: {
    orgById: (id: string) => (id === ORG_A ? mappingA : null),
    orgByLabel: (label: string) => (label === "acme" ? mappingA : null),
  },
  principalLookups: {
    personById: () => null,
    organisationById: (id: string) => (id === ORG_A ? { id, active: true } : null),
    orgKindOf: () => "operator",
  },
};
const opts = { adminRoles: ["org:admin"], door: "door:x" } as const;

const DETAIL = "identity has no verified organisation attached";

async function refusedBy(claims: Record<string, unknown> | null): Promise<IdentityRefusal> {
  const r = await resolveCallerFromClaims(claims, deps, opts);
  if (r.ok) throw new Error("expected a refusal");
  return r.refusal;
}

const src = readFileSync(join(__dirname, "..", "src", "identity-refusal.ts"), "utf8");
const start = src.indexOf("export type IdentityRefusalReason");
const reasons = [...src.slice(start, src.indexOf(";\n", start)).matchAll(/^\s*\|\s*"([^"]+)"/gm)].map(
  (m) => m[1] as IdentityRefusalReason,
);

describe("noOrganisationRefusal (0.32.0)", () => {
  it("a verified identity carrying no organisation claim: the resolver's refusal becomes no-organisation", async () => {
    const from = await refusedBy({ subject: "user_1" });
    expect(from.reason).toBe("no-verified-organisation");
    expect(noOrganisationRefusal(from)).toEqual({
      code: "RBAC_DENIED",
      reason: "no-organisation",
      door: "door:x",
      detail: DETAIL,
    });
  });

  it("a slug claim alone is still no verified organisation (a label never selects one)", async () => {
    const from = await refusedBy({ subject: "user_1", org_slug: "acme" });
    expect(noOrganisationRefusal(from)?.reason).toBe("no-organisation");
  });

  it("the door is the refusing door's own, never invented", async () => {
    const r = await resolveOrgFromClaim({ subject: "u" }, deps.orgLookups, { door: "other:door" });
    if (r.ok) throw new Error("expected a refusal");
    expect(noOrganisationRefusal(r.refusal)?.door).toBe("other:door");
  });

  it("an anonymous caller is not 'no organisation': credential-invalid answers null", async () => {
    const from = await refusedBy(null);
    expect(from.reason).toBe("credential-invalid");
    expect(noOrganisationRefusal(from)).toBeNull();
  });

  it("an organisation that is claimed but unmapped, or a person not found, answers null", async () => {
    expect(noOrganisationRefusal(await refusedBy({ subject: "u", org_id: "org_zzz" }))).toBeNull();
    expect(noOrganisationRefusal(await refusedBy({ subject: "u", org_id: ORG_A }))).toBeNull();
  });

  it("every other declared reason answers null; no-organisation itself is not re-minted", () => {
    expect(reasons.length).toBeGreaterThan(50);
    for (const reason of reasons) {
      if (reason === "no-verified-organisation") continue;
      expect(noOrganisationRefusal({ code: "RBAC_DENIED", reason, door: "d", detail: "x" })).toBeNull();
    }
  });

  it("the input refusal is not mutated, and the output carries exactly the four refusal fields", async () => {
    const from = await refusedBy({ subject: "u" });
    const before = { ...from };
    const out = noOrganisationRefusal(from);
    expect(from).toEqual(before);
    expect(out).not.toBe(from);
    expect(Object.keys(out ?? {}).sort()).toEqual(["code", "detail", "door", "reason"]);
  });

  it("is exported from the package root", () => {
    expect(typeof root.noOrganisationRefusal).toBe("function");
    expect(root.noOrganisationRefusal).toBe(noOrganisationRefusal);
  });
});
