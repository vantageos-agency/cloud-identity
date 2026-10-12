import { describe, expect, it } from "vitest";
import { resolveCallerFromClaims } from "../src/caller-from-claims.js";

// A consumer decides some callers by SUBJECT before any organisation is read
// (a fleet service account is a verified subject with no organisation of its
// own). The refusal therefore carries the verified subject when the claims had
// one, so the consumer never reads the credential itself to get it.
const ORG_A = "org_aaa";
const mappingA = { id: ORG_A, label: "acme", active: true, allowedOrchestrators: [], scopes: [], orgKind: "client" };
const deps = {
  orgLookups: {
    orgById: (id: string) => (id === ORG_A ? mappingA : null),
    orgByLabel: () => null,
  },
  principalLookups: {
    personById: (personId: string, orgId: string) => ({ id: personId, orgId, active: true }),
    organisationById: (id: string) => (id === ORG_A ? { id, active: true } : null),
    orgKindOf: () => "client" as const,
  },
};
const opts = { adminRoles: ["org:admin"], door: "withOrgScope" } as const;

describe("resolveCallerFromClaims refusal subject", () => {
  it("a verified subject with no organisation is refused AND names the subject", async () => {
    const r = await resolveCallerFromClaims({ subject: "user_svc" }, deps, opts);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.reason).toBe("no-verified-organisation");
    expect(r.subject).toBe("user_svc");
  });

  it("an org the mapping does not hold is refused and names the subject", async () => {
    const r = await resolveCallerFromClaims({ sub: "user_x", org_id: "org_zzz" }, deps, opts);
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.subject).toBe("user_x");
  });

  it("no subject at all: the refusal carries no subject", async () => {
    for (const claims of [undefined, null, {}, { subject: "" }, { subject: 42 }]) {
      const r = await resolveCallerFromClaims(claims as never, deps, opts);
      expect(r.ok).toBe(false);
      if (r.ok) continue;
      expect(r.refusal.reason).toBe("credential-invalid");
      expect("subject" in r).toBe(false);
    }
  });
});
