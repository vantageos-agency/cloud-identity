import { describe, it, expect } from "vitest";
import { mapRoleClaim } from "../src/index.js";

const MAPPING = { "org:admin": "admin", "org:member": "editor" } as const;

describe("mapRoleClaim — mapping is data, fallback is the caller's explicit choice", () => {
  it("serves a mapped claim", () => {
    expect(mapRoleClaim({ claim: "org:admin", mapping: MAPPING })).toEqual({
      ok: true,
      role: "admin",
      source: "mapped",
    });
  });

  it("a mapped claim wins over a supplied fallback", () => {
    const r = mapRoleClaim({ claim: "org:member", mapping: MAPPING, fallback: "viewer" });
    expect(r).toEqual({ ok: true, role: "editor", source: "mapped" });
  });

  it("uses the EXPLICIT fallback for an unmapped claim", () => {
    const r = mapRoleClaim({ claim: "org:billing", mapping: MAPPING, fallback: "viewer" });
    expect(r).toEqual({ ok: true, role: "viewer", source: "fallback" });
  });

  it("uses the explicit fallback for an absent claim", () => {
    for (const claim of [undefined, null, ""]) {
      const r = mapRoleClaim({ claim, mapping: MAPPING, fallback: "viewer" });
      expect(r).toEqual({ ok: true, role: "viewer", source: "fallback" });
    }
  });

  it("REFUSES an absent claim when no fallback was supplied", () => {
    for (const claim of [undefined, null, ""]) {
      const r = mapRoleClaim({ claim, mapping: MAPPING });
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.refusal.code).toBe("RBAC_DENIED");
        expect(r.refusal.reason).toBe("role-claim-absent");
      }
    }
  });

  it("REFUSES an unmapped claim when no fallback was supplied", () => {
    const r = mapRoleClaim({ claim: "org:billing", mapping: MAPPING });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal.reason).toBe("role-claim-unmapped");
  });

  it("an empty-string fallback is not a fallback", () => {
    expect(mapRoleClaim({ claim: undefined, mapping: MAPPING, fallback: "" }).ok).toBe(false);
  });

  it("a non-string claim is absent, never coerced", () => {
    for (const claim of [["org:admin"], { a: 1 }, 7, true]) {
      const r = mapRoleClaim({ claim, mapping: MAPPING });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("role-claim-absent");
    }
  });

  it("prototype keys are not mapped", () => {
    for (const claim of ["constructor", "__proto__", "toString"]) {
      expect(mapRoleClaim({ claim, mapping: MAPPING }).ok).toBe(false);
    }
  });

  it("refuses a malformed mapping or a mapping holding a non-string role", () => {
    const bad1 = mapRoleClaim({ claim: "x", mapping: null as never, fallback: "viewer" });
    expect(bad1.ok).toBe(false);
    const bad2 = mapRoleClaim({ claim: "x", mapping: { x: 5 } as never, fallback: "viewer" });
    expect(bad2.ok).toBe(false);
    if (!bad2.ok) expect(bad2.refusal.reason).toBe("invalid-role-mapping");
  });
});
