import { describe, expect, it } from "vitest";
import { decideActingClaim } from "../src/index.js";

/**
 * May a name a caller TYPED into a call be treated as the acting agent?
 *
 * A typed name is a CLAIM. It never overrides a caller already resolved BY ID;
 * the one name comparison here is the claim against that resolved agent's own
 * stored label. Eight rows, each pinned in both directions where it has both:
 *
 *   1. no caller                       -> refused (absence is never authority)
 *   2. agent credential                -> claim equals the agent's label, else mismatch
 *   3. seat resolved to an agent by ID -> the same equality
 *   4. master bearer (HTTP)            -> refused in EVERY mode
 *   5. master scope (trusted local)    -> passes
 *   6. permissive mode                 -> passes, only when asked for explicitly
 *   7. seat naming its own single allowlisted label (transitional) -> passes
 *   8. everything else                 -> agent credential required
 */

const CRED = { kind: "agent-credential", agentId: "agent_ada", agentLabel: "Ada", orgSlug: "acme" } as const;
const SEAT = { kind: "seat", agentId: "agent_ada", agentLabel: "Ada", orgId: "org_acme" } as const;
const MODES = [undefined, "strict", "permissive"] as const;

function decide(claimed: string, caller: unknown, mode?: unknown, door?: string) {
  return decideActingClaim({
    claimed,
    caller,
    ...(mode !== undefined ? { mode } : {}),
    ...(door !== undefined ? { door } : {}),
  } as never);
}

function refusalOf(r: ReturnType<typeof decide>) {
  if (r.ok) throw new Error("expected a refusal, got ok");
  return r.refusal;
}

describe("row 1: no caller is refused", () => {
  it.each(MODES)("null caller refused, mode %s", (mode) => {
    const r = refusalOf(decide("ada", null, mode));
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe("no-context");
  });

  it("an absent (undefined) caller is refused the same way", () => {
    expect(refusalOf(decide("ada", undefined, "permissive")).reason).toBe("no-context");
  });

  it("a caller of an unknown kind is refused, never passed", () => {
    const r = refusalOf(decide("ada", { kind: "root" }, "permissive"));
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe("caller-invalid");
  });
});

describe("row 2: agent credential", () => {
  it.each(MODES)("its own label passes, mode %s", (mode) => {
    const r = decide("Ada", CRED, mode);
    expect(r.ok).toBe(true);
    expect(r.ok && r.via).toBe("resolved-agent");
  });

  it.each(["ada", "ADA", "  Ada  ", "\tada\n"])("differing only by case or space (%j) passes", (claimed) => {
    expect(decide(claimed, CRED).ok).toBe(true);
  });

  it("differing only by Unicode composition form passes (NFC)", () => {
    const withAccent = { ...CRED, agentLabel: "Café" };
    expect(decide("Café", withAccent).ok).toBe(true);
    expect(decide("Café", { ...CRED, agentLabel: "Café" }).ok).toBe(true);
  });

  it("an accent is NOT folded: elan is not the agent elan-with-accent", () => {
    const r = refusalOf(decide("elan", { ...CRED, agentLabel: "élan" }));
    expect(r.code).toBe("AGENT_IDENTITY_MISMATCH");
  });

  it.each(MODES)("another agent's name is refused, mode %s (permissive never overrides a resolved identity)", (mode) => {
    const r = refusalOf(decide("bob", CRED, mode));
    expect(r.code).toBe("AGENT_IDENTITY_MISMATCH");
    expect(r.reason).toBe("agent-identity-mismatch");
  });

  it("the mismatch refusal carries what was claimed and who the credential resolves to", () => {
    const r = refusalOf(decide("bob", CRED));
    expect(r.claimed).toBe("bob");
    expect(r.resolved).toEqual({ agentId: "agent_ada", agentLabel: "Ada", org: "acme" });
    expect(r.detail).toContain("bob");
  });

  it("an empty claim is not the agent", () => {
    expect(refusalOf(decide("", CRED, "permissive")).code).toBe("AGENT_IDENTITY_MISMATCH");
  });

  it("a resolved agent with an empty label or ID is not an identity: refused, an empty claim does not equal it", () => {
    for (const bad of [
      { ...CRED, agentLabel: "" },
      { ...CRED, agentLabel: "   " },
      { ...CRED, agentId: "" },
    ]) {
      const r = refusalOf(decide("", bad, "permissive"));
      expect(r.code).toBe("RBAC_DENIED");
      expect(r.reason).toBe("caller-invalid");
    }
  });
});

describe("row 3: seat resolved to an agent by ID", () => {
  it.each(MODES)("its agent's label passes, mode %s", (mode) => {
    const r = decide("ada", SEAT, mode);
    expect(r.ok).toBe(true);
    expect(r.ok && r.via).toBe("resolved-agent");
  });

  it.each(["ADA", " ada ", "Ada"])("differing only by case or space (%j) passes", (claimed) => {
    expect(decide(claimed, SEAT).ok).toBe(true);
  });

  it("differing only by Unicode composition form passes (NFC)", () => {
    expect(decide("Café", { ...SEAT, agentLabel: "Café" }).ok).toBe(true);
  });

  it.each(MODES)("another agent's name is refused, mode %s", (mode) => {
    const r = refusalOf(decide("bob", SEAT, mode));
    expect(r.code).toBe("AGENT_IDENTITY_MISMATCH");
    expect(r.resolved).toEqual({ agentId: "agent_ada", agentLabel: "Ada", org: "org_acme" });
  });

  it("a seat with an empty label or ID is not an identity", () => {
    expect(refusalOf(decide("", { ...SEAT, agentLabel: "" }, "permissive")).reason).toBe("caller-invalid");
    expect(refusalOf(decide("x", { ...SEAT, agentId: "" }, "permissive")).reason).toBe("caller-invalid");
  });
});

describe("row 4: master bearer", () => {
  it.each(MODES)("is refused, mode %s (permissive never admits it)", (mode) => {
    const r = refusalOf(decide("ada", { kind: "master-bearer" }, mode));
    expect(r.code).toBe("AGENT_CREDENTIAL_REQUIRED");
    expect(r.reason).toBe("agent-credential-required");
    expect(r.claimed).toBe("ada");
  });
});

describe("row 5: master scope (trusted local context)", () => {
  it.each(MODES)("passes any claim, mode %s", (mode) => {
    const r = decide("anyone", { kind: "master-scope" }, mode);
    expect(r.ok).toBe(true);
    expect(r.ok && r.via).toBe("master-scope");
  });
});

describe("row 6: permissive mode is an explicit input", () => {
  const MEMBER = { kind: "org-member" } as const;

  it("an organisation member passes ONLY when mode is explicitly permissive, and is marked unattributed", () => {
    const r = decide("anyone", MEMBER, "permissive");
    expect(r.ok).toBe(true);
    expect(r.ok && r.via).toBe("permissive-unattributed");
  });

  it("mode ABSENT is strict: the same call is refused", () => {
    const r = refusalOf(decide("anyone", MEMBER));
    expect(r.code).toBe("AGENT_CREDENTIAL_REQUIRED");
  });

  it("mode strict refuses", () => {
    expect(refusalOf(decide("anyone", MEMBER, "strict")).code).toBe("AGENT_CREDENTIAL_REQUIRED");
  });

  it.each(["Permissive", "PERMISSIVE", " permissive", "yes", "", 1, true, null])(
    "an unrecognised mode (%j) is strict, never permissive",
    (mode) => {
      const r = decideActingClaim({ claimed: "anyone", caller: MEMBER, mode } as never);
      expect(refusalOf(r).code).toBe("AGENT_CREDENTIAL_REQUIRED");
    },
  );

  it("permissive also admits an unresolved seat that is not naming its own label", () => {
    const seat = { kind: "seat-unresolved", allowlist: ["ada", "bob"] } as const;
    expect(decide("anyone", seat, "permissive").ok).toBe(true);
    expect(refusalOf(decide("anyone", seat)).code).toBe("AGENT_CREDENTIAL_REQUIRED");
  });
});

describe("row 7: an unresolved seat naming its own single allowlisted label", () => {
  it.each(MODES)("passes, mode %s, and is not marked unattributed", (mode) => {
    const r = decide("Ada", { kind: "seat-unresolved", allowlist: ["ada"] }, mode);
    expect(r.ok).toBe(true);
    expect(r.ok && r.via).toBe("seat-own-label");
  });

  it("compares after normalisation", () => {
    expect(decide("  ADA ", { kind: "seat-unresolved", allowlist: ["Ada"] }).ok).toBe(true);
  });

  it("another label is refused in strict mode", () => {
    expect(refusalOf(decide("bob", { kind: "seat-unresolved", allowlist: ["ada"] })).code).toBe(
      "AGENT_CREDENTIAL_REQUIRED",
    );
  });

  it.each([
    ["wildcard", ["*"]],
    ["empty list", []],
    ["two entries", ["ada", "bob"]],
    ["blank entry", [""]],
    ["whitespace entry", ["  "]],
  ])("an allowlist that is not exactly one real label (%s) exempts nothing", (_n, allowlist) => {
    const caller = { kind: "seat-unresolved", allowlist } as const;
    for (const claimed of ["ada", "*", ""]) {
      expect(refusalOf(decide(claimed, caller)).code).toBe("AGENT_CREDENTIAL_REQUIRED");
    }
  });

  it("an organisation member has no such exemption: the label alone is not enough", () => {
    expect(refusalOf(decide("ada", { kind: "org-member" })).code).toBe("AGENT_CREDENTIAL_REQUIRED");
  });
});

describe("row 8: everything else needs an agent credential", () => {
  it("the refusal names the claim", () => {
    const r = refusalOf(decide("ada", { kind: "org-member" }, "strict"));
    expect(r.reason).toBe("agent-credential-required");
    expect(r.claimed).toBe("ada");
    expect(r.detail).toContain("ada");
  });
});

describe("the refusal and the claim", () => {
  it("carries the door the consumer named, and a default when none is named", () => {
    expect(refusalOf(decide("bob", CRED, undefined, "send_message")).door).toBe("send_message");
    expect(refusalOf(decide("bob", CRED)).door).toBe("decideActingClaim");
  });

  it("a claim that is not a string is refused for every caller, master scope included", () => {
    for (const caller of [CRED, SEAT, { kind: "master-scope" }, { kind: "master-bearer" }, { kind: "org-member" }]) {
      const r = decideActingClaim({ claimed: 42, caller, mode: "permissive" } as never);
      const refusal = refusalOf(r);
      expect(refusal.code).toBe("RBAC_DENIED");
      expect(refusal.reason).toBe("claim-invalid");
    }
  });

  it("no refusal echoes more than the claim and the resolved agent (no credential material)", () => {
    const r = refusalOf(decide("bob", { ...CRED, secret: "s3cr3t-value" }));
    expect(JSON.stringify(r)).not.toContain("s3cr3t-value");
  });
});
