import { describe, it, expect } from "vitest";
import {
  validatePresentedBearer,
  requireAgentScopedIdentity,
  sha256Hex,
  type PresentedBearerDeps,
  type PresentedBearerInternalReason,
  type StoredBearerRow,
} from "../src/index.js";

/**
 * Presented-bearer resolution — both poles per property.
 *
 * @security NO SECRET VALUE IS EVER PRINTED OR ASSERTED ON. The fixtures below
 * are obviously synthetic placeholders, and no test asserts on the value of a
 * token or of a digest: only on which FIELD or which ARGUMENT KIND was used
 * (e.g. "the callback received the digest, not the token" is asserted by
 * comparing the callback's argument to the independently-computed digest of the
 * same fixture, which is a shape claim, not a disclosure of a live secret).
 */

// Obviously-synthetic, never a real credential.
const FIXTURE_TOKEN = "synthetic-placeholder-token-not-a-credential";
const OTHER_FIXTURE_TOKEN = "synthetic-placeholder-other-not-a-credential";

const TENANT = "tenant-fixture";
const AGENT = "agent-fixture";

const FIXED_NOW = 1_700_000_000_000;
const clock = () => FIXED_NOW;

function header(token: string): string {
  return `Bearer ${token}`;
}

/**
 * Builds deps around a single row, recording every argument the callback saw
 * and every internal reason reported.
 */
function depsFor(
  row: StoredBearerRow | null,
  overrides: Partial<PresentedBearerDeps> = {},
): PresentedBearerDeps & {
  seen: string[];
  reasons: PresentedBearerInternalReason[];
} {
  const seen: string[] = [];
  const reasons: PresentedBearerInternalReason[] = [];
  return {
    seen,
    reasons,
    now: clock,
    onRefusal: (reason) => reasons.push(reason),
    lookupBySecretHash: async (digest) => {
      seen.push(digest);
      return row;
    },
    ...overrides,
  };
}

async function validRow(
  extra: Partial<StoredBearerRow> = {},
): Promise<StoredBearerRow> {
  return {
    tenantId: TENANT,
    agentId: AGENT,
    secretHash: await sha256Hex(FIXTURE_TOKEN),
    ...extra,
  };
}

// ---------------------------------------------------------------------------
// RESOLVES — the withheld-grant pole. A primitive that refuses everything
// passes every refusal test below and is useless.
// ---------------------------------------------------------------------------

describe("validatePresentedBearer — resolves a legitimate caller", () => {
  it("a known, unexpired, unrevoked row resolves to tenant + agent", async () => {
    const deps = depsFor(await validRow({ expiresAt: FIXED_NOW + 60_000 }));
    const result = await validatePresentedBearer(header(FIXTURE_TOKEN), deps);

    expect(result.ok).toBe(true);
    if (!result.ok) throw new Error("expected a resolved identity");
    expect(result.identity.tenantId).toBe(TENANT);
    expect(result.identity.agent).toEqual({ present: true, agentId: AGENT });
    expect(result.identity.scopes).toEqual([]);
  });

  it("carries the row's scopes through unchanged", async () => {
    const deps = depsFor(await validRow({ scopes: ["read", "write"] }));
    const result = await validatePresentedBearer(header(FIXTURE_TOKEN), deps);
    if (!result.ok) throw new Error("expected a resolved identity");
    expect(result.identity.scopes).toEqual(["read", "write"]);
  });

  it("a row with no expiry resolves (absent expiry is not an expired token)", async () => {
    const deps = depsFor(await validRow({ expiresAt: null }));
    const result = await validatePresentedBearer(header(FIXTURE_TOKEN), deps);
    expect(result.ok).toBe(true);
  });

  it("the scheme prefix is matched case-insensitively", async () => {
    const deps = depsFor(await validRow());
    const result = await validatePresentedBearer(
      `bEaReR ${FIXTURE_TOKEN}`,
      deps,
    );
    expect(result.ok).toBe(true);
  });

  it("no refusal is reported on the success path", async () => {
    const deps = depsFor(await validRow());
    await validatePresentedBearer(header(FIXTURE_TOKEN), deps);
    expect(deps.reasons).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// THE COLLAPSE — constraint 2. This is the pole that cannot be waved through.
// ---------------------------------------------------------------------------

describe("validatePresentedBearer — unknown, revoked and expired are INDISTINGUISHABLE", () => {
  it("the three refusals are deep-equal to each other", async () => {
    const unknown = await validatePresentedBearer(
      header(FIXTURE_TOKEN),
      depsFor(null),
    );
    const revoked = await validatePresentedBearer(
      header(FIXTURE_TOKEN),
      depsFor(await validRow({ revoked: true })),
    );
    const expired = await validatePresentedBearer(
      header(FIXTURE_TOKEN),
      depsFor(await validRow({ expiresAt: FIXED_NOW - 1 })),
    );

    // Deep equality against EACH OTHER, not merely "each is a refusal".
    expect(unknown).toEqual(revoked);
    expect(revoked).toEqual(expired);
    expect(unknown).toEqual(expired);

    // And no extra own property can distinguish them either.
    const keysOf = (r: unknown) => Object.keys(r as object).sort();
    expect(keysOf(unknown)).toEqual(keysOf(revoked));
    expect(keysOf(revoked)).toEqual(keysOf(expired));

    // Serialised form — what actually crosses a wire — is identical too.
    expect(JSON.stringify(unknown)).toBe(JSON.stringify(revoked));
    expect(JSON.stringify(revoked)).toBe(JSON.stringify(expired));

    expect(unknown).toEqual({ ok: false, error: "mismatch" });
  });

  it("a row whose stored digest does not match collapses into the same refusal", async () => {
    const wrongRow = await validRow({
      secretHash: await sha256Hex(OTHER_FIXTURE_TOKEN),
    });
    const mismatched = await validatePresentedBearer(
      header(FIXTURE_TOKEN),
      depsFor(wrongRow),
    );
    const unknown = await validatePresentedBearer(
      header(FIXTURE_TOKEN),
      depsFor(null),
    );
    expect(mismatched).toEqual(unknown);
  });

  it("a row of invalid shape collapses into the same refusal, never a grant", async () => {
    const badRow = { tenantId: "", secretHash: "" } as unknown as StoredBearerRow;
    const invalid = await validatePresentedBearer(
      header(FIXTURE_TOKEN),
      depsFor(badRow),
    );
    expect(invalid).toEqual({ ok: false, error: "mismatch" });
  });

  it("expiry is evaluated against the injected clock, not the wall clock", async () => {
    const row = await validRow({ expiresAt: FIXED_NOW + 1 });
    const beforeExpiry = await validatePresentedBearer(
      header(FIXTURE_TOKEN),
      depsFor(row, { now: () => FIXED_NOW }),
    );
    const afterExpiry = await validatePresentedBearer(
      header(FIXTURE_TOKEN),
      depsFor(row, { now: () => FIXED_NOW + 2 }),
    );
    expect(beforeExpiry.ok).toBe(true);
    expect(afterExpiry).toEqual({ ok: false, error: "mismatch" });
  });

  it("internally the three ARE distinguished, for the consumer's own logs only", async () => {
    const unknownDeps = depsFor(null);
    await validatePresentedBearer(header(FIXTURE_TOKEN), unknownDeps);
    const revokedDeps = depsFor(await validRow({ revoked: true }));
    await validatePresentedBearer(header(FIXTURE_TOKEN), revokedDeps);
    const expiredDeps = depsFor(await validRow({ expiresAt: FIXED_NOW - 1 }));
    await validatePresentedBearer(header(FIXTURE_TOKEN), expiredDeps);

    expect(unknownDeps.reasons).toEqual(["unknown-token"]);
    expect(revokedDeps.reasons).toEqual(["revoked-token"]);
    expect(expiredDeps.reasons).toEqual(["expired-token"]);
  });

  it("a throwing observability sink cannot change the outcome", async () => {
    const result = await validatePresentedBearer(
      header(FIXTURE_TOKEN),
      depsFor(null, {
        onRefusal: () => {
          throw new Error("sink is broken");
        },
      }),
    );
    expect(result).toEqual({ ok: false, error: "mismatch" });
  });
});

// ---------------------------------------------------------------------------
// ORG-WIDE TOKEN ON A PER-AGENT SURFACE — constraint 1.
// ---------------------------------------------------------------------------

describe("an organization-wide token is never widened into an agent", () => {
  it("resolves, with the agent as an EXPLICIT absence rather than a nullable field", async () => {
    const deps = depsFor(await validRow({ agentId: null }));
    const result = await validatePresentedBearer(header(FIXTURE_TOKEN), deps);
    if (!result.ok) throw new Error("an organization-wide token is legitimate");
    expect(result.identity.tenantId).toBe(TENANT);
    expect(result.identity.agent).toEqual({
      present: false,
      code: "AGENT_ABSENT",
      reason: "organization-wide-token",
    });
  });

  it("an absent agentId key behaves identically to an explicit null", async () => {
    const row = await validRow();
    delete (row as { agentId?: unknown }).agentId;
    const result = await validatePresentedBearer(
      header(FIXTURE_TOKEN),
      depsFor(row),
    );
    if (!result.ok) throw new Error("expected a resolved identity");
    expect(result.identity.agent.present).toBe(false);
  });

  it("the per-agent surface REFUSES it", async () => {
    const deps = depsFor(await validRow({ agentId: null }));
    const result = await validatePresentedBearer(header(FIXTURE_TOKEN), deps);
    if (!result.ok) throw new Error("expected a resolved identity");

    const scoped = requireAgentScopedIdentity(result.identity);
    expect(scoped).toEqual({ ok: false, error: "no-agent-on-token" });
  });

  it("the per-agent surface ADMITS a token that carries an agent (withheld-grant pole)", async () => {
    const deps = depsFor(await validRow());
    const result = await validatePresentedBearer(header(FIXTURE_TOKEN), deps);
    if (!result.ok) throw new Error("expected a resolved identity");

    const scoped = requireAgentScopedIdentity(result.identity);
    expect(scoped.ok).toBe(true);
    if (!scoped.ok) throw new Error("expected an agent-scoped identity");
    expect(scoped.identity.agentId).toBe(AGENT);
    expect(scoped.identity.tenantId).toBe(TENANT);
  });

  it("the per-agent refusal is DISTINGUISHABLE from a bad credential, by design", async () => {
    const deps = depsFor(await validRow({ agentId: null }));
    const result = await validatePresentedBearer(header(FIXTURE_TOKEN), deps);
    if (!result.ok) throw new Error("expected a resolved identity");
    const scoped = requireAgentScopedIdentity(result.identity);
    // 403 (wrong surface for a good token) must not collapse into 401.
    expect(scoped).not.toEqual({ ok: false, error: "mismatch" });
  });
});

// ---------------------------------------------------------------------------
// THE CALLBACK SEES A DIGEST, NEVER THE TOKEN.
// ---------------------------------------------------------------------------

describe("the raw token never leaves this module", () => {
  it("the lookup callback is called with the digest, not the token", async () => {
    const deps = depsFor(await validRow());
    await validatePresentedBearer(header(FIXTURE_TOKEN), deps);

    expect(deps.seen).toHaveLength(1);
    const argument = deps.seen[0]!;
    // Compared as BOOLEANS so that a failure message prints `false` rather
    // than echoing a digest — a failing test must not become a disclosure,
    // even with a synthetic fixture.
    expect(argument === (await sha256Hex(FIXTURE_TOKEN))).toBe(true);
    expect(argument === FIXTURE_TOKEN).toBe(false);
    expect(argument.includes(FIXTURE_TOKEN)).toBe(false);
    // Shape claim only: 64 lower-case hex characters.
    expect(argument).toMatch(/^[0-9a-f]{64}$/);
  });

  it("neither the resolved identity nor a refusal carries the token or the digest", async () => {
    const deps = depsFor(await validRow());
    const ok = await validatePresentedBearer(header(FIXTURE_TOKEN), deps);
    const refused = await validatePresentedBearer(
      header(FIXTURE_TOKEN),
      depsFor(null),
    );
    const digest = await sha256Hex(FIXTURE_TOKEN);
    for (const serialised of [JSON.stringify(ok), JSON.stringify(refused)]) {
      expect(serialised.includes(FIXTURE_TOKEN)).toBe(false);
      expect(serialised.includes(digest)).toBe(false);
    }
  });

  it("no lookup happens at all for a missing or malformed header", async () => {
    const deps = depsFor(await validRow());
    await validatePresentedBearer(undefined, deps);
    await validatePresentedBearer("", deps);
    await validatePresentedBearer("Basic something", deps);
    await validatePresentedBearer("Bearer    ", deps);
    expect(deps.seen).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// COARSE HEADER ERRORS — the vocabulary of validateMasterBearer.
// ---------------------------------------------------------------------------

describe("coarse header errors", () => {
  it("a missing header is 'missing'", async () => {
    const deps = depsFor(await validRow());
    expect(await validatePresentedBearer(undefined, deps)).toEqual({
      ok: false,
      error: "missing",
    });
    expect(await validatePresentedBearer(null, deps)).toEqual({
      ok: false,
      error: "missing",
    });
    expect(await validatePresentedBearer("", deps)).toEqual({
      ok: false,
      error: "missing",
    });
  });

  it("a non-Bearer scheme is 'malformed'", async () => {
    const deps = depsFor(await validRow());
    expect(await validatePresentedBearer("Basic abc", deps)).toEqual({
      ok: false,
      error: "malformed",
    });
    expect(await validatePresentedBearer(FIXTURE_TOKEN, deps)).toEqual({
      ok: false,
      error: "malformed",
    });
  });

  it("an empty token after the scheme is 'malformed'", async () => {
    const deps = depsFor(await validRow());
    expect(await validatePresentedBearer("Bearer ", deps)).toEqual({
      ok: false,
      error: "malformed",
    });
    expect(await validatePresentedBearer("Bearer      ", deps)).toEqual({
      ok: false,
      error: "malformed",
    });
  });

  it("a header refusal is NOT the collapsed refusal — a client learns 400-class from 401-class", async () => {
    const deps = depsFor(await validRow());
    const malformed = await validatePresentedBearer("Basic abc", deps);
    const unknown = await validatePresentedBearer(
      header(FIXTURE_TOKEN),
      depsFor(null),
    );
    expect(malformed).not.toEqual(unknown);
  });
});

// ---------------------------------------------------------------------------
// A LOOKUP FAILURE IS A REFUSAL, NEVER AN IMPLICIT ALLOW.
// ---------------------------------------------------------------------------

describe("a failing lookup refuses", () => {
  it("a throwing lookup yields 'unavailable', not a grant", async () => {
    const result = await validatePresentedBearer(header(FIXTURE_TOKEN), {
      now: clock,
      lookupBySecretHash: async () => {
        throw new Error("datastore unreachable");
      },
    });
    expect(result).toEqual({ ok: false, error: "unavailable" });
    expect(result.ok).toBe(false);
  });

  it("'unavailable' is deliberately distinct from the collapsed refusal", async () => {
    const unavailable = await validatePresentedBearer(header(FIXTURE_TOKEN), {
      lookupBySecretHash: async () => {
        throw new Error("datastore unreachable");
      },
    });
    const unknown = await validatePresentedBearer(
      header(FIXTURE_TOKEN),
      depsFor(null),
    );
    expect(unavailable).not.toEqual(unknown);
  });

  it("a missing lookup callback is a programming error, not a credential verdict", async () => {
    await expect(
      validatePresentedBearer(header(FIXTURE_TOKEN), {} as PresentedBearerDeps),
    ).rejects.toThrow(TypeError);
  });
});
