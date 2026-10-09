import { describe, expect, it } from "vitest";
import { type ActingPrincipal, assertPrincipalListed } from "../src/index.js";

/**
 * Admission by membership of a stored list, decided by agent ID only.
 *
 * The list holds IDs. A name never matches, "*" is not a wildcard, and every
 * absence refuses. The refusal names the door when one is given.
 */

const AGENT: ActingPrincipal = { principalId: "agent_1", orgId: "org_a", kind: "agent" };
const LIST = { orgId: "org_a", principalIds: ["agent_1", "agent_2"] } as const;

function refusedWith(result: ReturnType<typeof assertPrincipalListed>) {
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error("expected a refusal");
  return result.refusal;
}

describe("assertPrincipalListed", () => {
  it("admits a listed agent ID", () => {
    expect(assertPrincipalListed(AGENT, LIST)).toEqual({ ok: true });
  });

  it("refuses an unlisted agent ID", () => {
    const r = refusedWith(
      assertPrincipalListed({ ...AGENT, principalId: "agent_9" }, LIST),
    );
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe("principal-not-listed");
  });

  it("matches byte for byte: no case folding, no trimming, no prefix", () => {
    for (const id of ["AGENT_1", "agent_1 ", "agent_", "agent_11"]) {
      const r = assertPrincipalListed({ ...AGENT, principalId: id }, LIST);
      expect(r.ok).toBe(false);
    }
  });

  it("refuses a missing list (null and undefined)", () => {
    expect(refusedWith(assertPrincipalListed(AGENT, null)).reason).toBe("list-absent");
    expect(refusedWith(assertPrincipalListed(AGENT, undefined)).reason).toBe("list-absent");
  });

  it("refuses an empty list", () => {
    const r = refusedWith(assertPrincipalListed(AGENT, { orgId: "org_a", principalIds: [] }));
    expect(r.reason).toBe("list-empty");
  });

  it("refuses a malformed list (ids not an array)", () => {
    const bad = { orgId: "org_a", principalIds: "agent_1" } as unknown as typeof LIST;
    expect(refusedWith(assertPrincipalListed(AGENT, bad)).reason).toBe("list-empty");
  });

  it("refuses a list from another organisation", () => {
    const r = refusedWith(
      assertPrincipalListed(AGENT, { orgId: "org_b", principalIds: ["agent_1"] }),
    );
    expect(r.reason).toBe("target-other-organisation");
  });

  it("refuses a list with a missing or empty orgId", () => {
    const noOrg = { principalIds: ["agent_1"] } as unknown as typeof LIST;
    expect(refusedWith(assertPrincipalListed(AGENT, noOrg)).reason).toBe("target-unstamped");
    const emptyOrg = { orgId: "", principalIds: ["agent_1"] };
    expect(refusedWith(assertPrincipalListed(AGENT, emptyOrg)).reason).toBe("target-unstamped");
  });

  it("never matches a name equal to the agent's name", () => {
    const named = { ...AGENT, name: "eta", agentName: "eta" } as unknown as ActingPrincipal;
    const r = assertPrincipalListed(named, { orgId: "org_a", principalIds: ["eta"] });
    expect(r.ok).toBe(false);
  });

  it("refuses a principal carrying only a name", () => {
    const onlyName = { name: "eta", orgId: "org_a", kind: "agent" } as unknown as ActingPrincipal;
    const r = refusedWith(assertPrincipalListed(onlyName, { orgId: "org_a", principalIds: ["eta"] }));
    expect(r.reason).toBe("credential-invalid");
  });

  it('never treats "*" as a wildcard', () => {
    const r = refusedWith(assertPrincipalListed(AGENT, { orgId: "org_a", principalIds: ["*"] }));
    expect(r.reason).toBe("principal-not-listed");
    const star = { ...AGENT, principalId: "*" };
    expect(assertPrincipalListed(star, { orgId: "org_a", principalIds: ["*"] }).ok).toBe(true);
  });

  it("refuses a missing principal and a principal with no agent ID or org", () => {
    for (const p of [null, undefined, { ...AGENT, principalId: "" }, { ...AGENT, orgId: "" }]) {
      const r = refusedWith(assertPrincipalListed(p, LIST));
      expect(r.reason).toBe("credential-invalid");
    }
  });

  it("admits an agent acting through a service account by the agent's own ID", () => {
    const via: ActingPrincipal = { ...AGENT, viaServiceAccountId: "svc_a" };
    expect(assertPrincipalListed(via, LIST)).toEqual({ ok: true });
  });

  it("refuses a principal that is not an agent, even if its ID is listed", () => {
    for (const kind of ["person", "service", "fleet"] as const) {
      const r = refusedWith(assertPrincipalListed({ ...AGENT, kind }, LIST));
      expect(r.reason).toBe("principal-not-an-agent");
    }
  });

  it("names the door on every refusal, defaulting to the function name", () => {
    expect(refusedWith(assertPrincipalListed(AGENT, null, { door: "tasks:complete" })).door).toBe(
      "tasks:complete",
    );
    expect(refusedWith(assertPrincipalListed(AGENT, null)).door).toBe("assertPrincipalListed");
  });
});
