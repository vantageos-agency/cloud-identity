import { describe, expect, it } from "vitest";
import {
  type PresentedBearerDeps,
  type PresentedBearerInternalReason,
  resolvePresentedDigest,
  type StoredBearerRow,
  sha256Hex,
  validatePresentedBearer,
} from "../src/index.js";

/**
 * 0.37.0: the bearer seam binds a workspace and honours an active flag. The
 * application owns the token store (`lookupBySecretHash`); the package owns
 * the decision: constant-time digest compare, revocation, `active`, expiry,
 * and now the expected tenant (the consumer's "workspace").
 *
 * The named scoped identity: a token bound to tenant `ws_a` holding scope
 * `read` (a "crm-reader" token). No secret value is asserted on.
 */
const FIXTURE_TOKEN = "synthetic-placeholder-token-not-a-credential";
const FIXED_NOW = 1_700_000_000_000;

async function row(extra: Partial<StoredBearerRow> = {}): Promise<StoredBearerRow> {
  return {
    tenantId: "ws_a",
    secretHash: await sha256Hex(FIXTURE_TOKEN),
    scopes: ["read"],
    ...extra,
  };
}

function deps(
  r: StoredBearerRow | null,
  extra: Partial<PresentedBearerDeps> = {},
): PresentedBearerDeps & { reasons: PresentedBearerInternalReason[] } {
  const reasons: PresentedBearerInternalReason[] = [];
  return {
    reasons,
    now: () => FIXED_NOW,
    onRefusal: (reason) => reasons.push(reason),
    lookupBySecretHash: async () => r,
    ...extra,
  };
}

const HEADER = `Bearer ${FIXTURE_TOKEN}`;

describe("expectedTenantId: both directions", () => {
  it("a token bound to ws_a resolves when ws_a is expected", async () => {
    const result = await validatePresentedBearer(HEADER, deps(await row(), { expectedTenantId: "ws_a" }));
    expect(result.ok).toBe(true);
    expect(result.identity?.tenantId).toBe("ws_a");
    expect(result.identity?.scopes).toEqual(["read"]);
  });

  it("a token bound to ws_a is refused when ws_b is expected, with the collapsed refusal", async () => {
    const d = deps(await row(), { expectedTenantId: "ws_b" });
    const result = await validatePresentedBearer(HEADER, d);
    expect(result).toEqual({ ok: false, error: "mismatch" });
    expect(d.reasons).toEqual(["tenant-mismatch"]);
  });

  it("the digest entry point binds the tenant through the same decision", async () => {
    const digest = await sha256Hex(FIXTURE_TOKEN);
    expect((await resolvePresentedDigest(digest, deps(await row(), { expectedTenantId: "ws_a" }))).ok).toBe(true);
    const d = deps(await row(), { expectedTenantId: "ws_b" });
    expect(await resolvePresentedDigest(digest, d)).toEqual({ ok: false, error: "mismatch" });
    expect(d.reasons).toEqual(["tenant-mismatch"]);
  });
});

describe("expectedTenantId: an omitted or malformed expectation never broadens", () => {
  it("omitted: the token resolves to its own bound tenant only (unchanged behaviour)", async () => {
    const result = await validatePresentedBearer(HEADER, deps(await row()));
    expect(result.ok).toBe(true);
    expect(result.identity?.tenantId).toBe("ws_a");
  });

  it("presented but empty or not a string: refused, the lookup result notwithstanding", async () => {
    for (const expectedTenantId of ["", 7, null, ["ws_a"]]) {
      const d = deps(await row(), { expectedTenantId: expectedTenantId as unknown as string });
      expect(await validatePresentedBearer(HEADER, d)).toEqual({ ok: false, error: "mismatch" });
      expect(d.reasons).toEqual(["expected-tenant-invalid"]);
    }
  });

  it("matching is exact: case differs is a mismatch", async () => {
    const d = deps(await row(), { expectedTenantId: "WS_A" });
    expect((await validatePresentedBearer(HEADER, d)).ok).toBe(false);
  });
});

describe("active flag", () => {
  it("active: false is refused with the collapsed refusal", async () => {
    const d = deps(await row({ active: false }));
    expect(await validatePresentedBearer(HEADER, d)).toEqual({ ok: false, error: "mismatch" });
    expect(d.reasons).toEqual(["inactive-token"]);
  });

  it("active: true resolves", async () => {
    expect((await validatePresentedBearer(HEADER, deps(await row({ active: true })))).ok).toBe(true);
  });

  it("a non-boolean active is a malformed row, never read as active", async () => {
    const d = deps({ ...(await row()), active: "yes" } as unknown as StoredBearerRow);
    expect(await validatePresentedBearer(HEADER, d)).toEqual({ ok: false, error: "mismatch" });
    expect(d.reasons).toEqual(["row-shape-invalid"]);
  });
});

describe("order: the tenant is judged only after the credential itself", () => {
  it("an expired token bound to the expected tenant is refused as expired", async () => {
    const d = deps(await row({ expiresAt: FIXED_NOW }), { expectedTenantId: "ws_a" });
    expect((await validatePresentedBearer(HEADER, d)).ok).toBe(false);
    expect(d.reasons).toEqual(["expired-token"]);
  });

  it("an unknown token is refused as unknown even when a tenant is expected", async () => {
    const d = deps(null, { expectedTenantId: "ws_a" });
    expect((await validatePresentedBearer(HEADER, d)).ok).toBe(false);
    expect(d.reasons).toEqual(["unknown-token"]);
  });
});
