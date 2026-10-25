import { describe, expect, it, vi } from "vitest";
import {
  type PresentedBearerDeps,
  type PresentedBearerInternalReason,
  type StoredBearerRow,
  resolveConvexMachineCaller,
  resolveConvexMachineCallerFromDigest,
  resolvePresentedDigest,
  sha256Hex,
} from "../src/index.js";
import { resolvePresentedToken } from "../src/presented-bearer.js";

/**
 * The digest entry points. A raw bearer passed as a Convex function argument
 * leaks: on an argument-validation failure Convex echoes the whole argument
 * object into the caller's error and the deployment log. So a Convex consumer
 * hashes at the HTTP boundary and passes only the SHA-256 hex digest; these
 * tests pin that the digest path decides exactly as the raw path does.
 */

const ORG = "org_ALPHA1";
const OTHER_ORG = "org_BETA2";
const DOOR = "engine:world.step";
const NOW = 1_700_000_000_000;

type Table = Map<string, unknown>;

async function tableWith(token: string, row: Record<string, unknown> = {}): Promise<Table> {
  const secretHash = await sha256Hex(token);
  return new Map<string, unknown>([[secretHash, { tenantId: ORG, secretHash, ...row }]]);
}

function depsFor(table: Table, opts: { throws?: boolean } = {}) {
  const reasons: PresentedBearerInternalReason[] = [];
  const lookupBySecretHash = vi.fn(async (digest: string) => {
    if (opts.throws) throw new Error("datastore down");
    return (table.get(digest) ?? null) as StoredBearerRow | null;
  });
  const deps: PresentedBearerDeps = {
    lookupBySecretHash,
    now: () => NOW,
    onRefusal: (r) => reasons.push(r),
  };
  return { deps, reasons, lookupBySecretHash };
}

const MALFORMED_DIGESTS: unknown[] = [
  "",
  "abc",
  "a".repeat(63),
  "a".repeat(65),
  "A".repeat(64),
  `${"0".repeat(63)}g`,
  ` ${"0".repeat(63)}`,
  `${"0".repeat(64)}\n`,
  undefined,
  null,
  42,
  {},
];

describe("resolvePresentedDigest", () => {
  it("resolves the correct digest", async () => {
    const table = await tableWith("tok_valid", { agentId: "agent_7", scopes: ["memory:read"] });
    const { deps } = depsFor(table);
    const result = await resolvePresentedDigest(await sha256Hex("tok_valid"), deps);
    expect(result).toEqual({
      ok: true,
      identity: {
        tenantId: ORG,
        agent: { present: true, agentId: "agent_7" },
        scopes: ["memory:read"],
      },
    });
  });

  it("a wrong digest of the right shape refuses with the collapsed refusal", async () => {
    const table = await tableWith("tok_valid");
    const { deps, reasons } = depsFor(table);
    const result = await resolvePresentedDigest(await sha256Hex("tok_wrong"), deps);
    expect(result).toEqual({ ok: false, error: "mismatch" });
    expect(Object.keys(result).sort()).toEqual(["error", "ok"]);
    expect(reasons).toEqual(["unknown-token"]);
  });

  it("a malformed digest refuses identically, without calling the lookup", async () => {
    const table = await tableWith("tok_valid");
    const wrong = await resolvePresentedDigest(await sha256Hex("tok_wrong"), depsFor(table).deps);
    for (const bad of MALFORMED_DIGESTS) {
      const { deps, lookupBySecretHash } = depsFor(table);
      const result = await resolvePresentedDigest(bad as string, deps);
      // The very same frozen value as a wrong digest: no field, no code, no
      // reason tells a prober the digest's shape was the problem.
      expect(result).toBe(wrong);
      expect(lookupBySecretHash).not.toHaveBeenCalled();
    }
  });

  it("the uppercase form of a VALID digest is refused (only sha256Hex output is accepted)", async () => {
    const table = await tableWith("tok_valid");
    const { deps } = depsFor(table);
    const upper = (await sha256Hex("tok_valid")).toUpperCase();
    expect(await resolvePresentedDigest(upper, deps)).toEqual({ ok: false, error: "mismatch" });
  });

  it("a revoked row is refused via digest with the collapsed refusal", async () => {
    const table = await tableWith("tok_revoked", { revoked: true });
    const { deps, reasons } = depsFor(table);
    const result = await resolvePresentedDigest(await sha256Hex("tok_revoked"), deps);
    expect(result).toEqual({ ok: false, error: "mismatch" });
    expect(reasons).toEqual(["revoked-token"]);
  });

  it("an expired row is refused via digest with the collapsed refusal", async () => {
    const table = await tableWith("tok_expired", { expiresAt: NOW });
    const { deps, reasons } = depsFor(table);
    const result = await resolvePresentedDigest(await sha256Hex("tok_expired"), deps);
    expect(result).toEqual({ ok: false, error: "mismatch" });
    expect(reasons).toEqual(["expired-token"]);
  });

  it("a lookup that returns a row whose stored digest differs is refused (constant-time re-compare kept)", async () => {
    const digest = await sha256Hex("tok_valid");
    const table: Table = new Map([[digest, { tenantId: ORG, secretHash: await sha256Hex("other") }]]);
    const { deps, reasons } = depsFor(table);
    expect(await resolvePresentedDigest(digest, deps)).toEqual({ ok: false, error: "mismatch" });
    expect(reasons).toEqual(["stored-digest-mismatch"]);
  });

  it("a non-function lookup is a programming error, not a refusal", async () => {
    await expect(
      resolvePresentedDigest("0".repeat(64), {} as unknown as PresentedBearerDeps),
    ).rejects.toBeInstanceOf(TypeError);
  });
});

// ---------------------------------------------------------------------------
// One decision path: raw and digest agree on every outcome
// ---------------------------------------------------------------------------

type Scenario = { name: string; token: string; table: () => Promise<Table>; throws?: boolean };

const SCENARIOS: Scenario[] = [
  { name: "valid, agent-scoped", token: "tok_a", table: () => tableWith("tok_a", { agentId: "agent_7", scopes: ["s"] }) },
  { name: "valid, organisation-wide", token: "tok_b", table: () => tableWith("tok_b") },
  { name: "unknown", token: "tok_c", table: () => tableWith("tok_other") },
  { name: "revoked", token: "tok_d", table: () => tableWith("tok_d", { revoked: true }) },
  { name: "expired", token: "tok_e", table: () => tableWith("tok_e", { expiresAt: NOW - 1 }) },
  { name: "not yet expired", token: "tok_f", table: () => tableWith("tok_f", { expiresAt: NOW + 1 }) },
  { name: "row of invalid shape", token: "tok_g", table: () => tableWith("tok_g", { tenantId: "" }) },
  {
    name: "stored digest mismatch",
    token: "tok_h",
    table: async () => new Map([[await sha256Hex("tok_h"), { tenantId: ORG, secretHash: await sha256Hex("x") }]]),
  },
  { name: "lookup threw", token: "tok_i", table: () => tableWith("tok_i"), throws: true },
];

describe("raw-path and digest-path equivalence", () => {
  for (const s of SCENARIOS) {
    it(`resolvePresentedToken and resolvePresentedDigest agree: ${s.name}`, async () => {
      const table = await s.table();
      const raw = depsFor(table, { throws: s.throws });
      const dig = depsFor(table, { throws: s.throws });
      const rawResult = await resolvePresentedToken(s.token, raw.deps);
      const digResult = await resolvePresentedDigest(await sha256Hex(s.token), dig.deps);
      expect(digResult).toEqual(rawResult);
      if (!rawResult.ok) expect(digResult).toBe(rawResult); // same frozen refusal
      expect(dig.reasons).toEqual(raw.reasons);
      expect(dig.lookupBySecretHash.mock.calls).toEqual(raw.lookupBySecretHash.mock.calls);
    });

    it(`resolveConvexMachineCaller and resolveConvexMachineCallerFromDigest agree: ${s.name}`, async () => {
      const table = await s.table();
      for (const claimedOrgId of [ORG, OTHER_ORG]) {
        const raw = depsFor(table, { throws: s.throws });
        const dig = depsFor(table, { throws: s.throws });
        const rawResult = await resolveConvexMachineCaller(
          { credential: s.token, claimedOrgId },
          { ...raw.deps, door: DOOR },
        );
        const digResult = await resolveConvexMachineCallerFromDigest(
          { credentialDigest: await sha256Hex(s.token), claimedOrgId },
          { ...dig.deps, door: DOOR },
        );
        expect(digResult).toEqual(rawResult);
        expect(dig.reasons).toEqual(raw.reasons);
        expect(dig.lookupBySecretHash.mock.calls).toEqual(raw.lookupBySecretHash.mock.calls);
      }
    });
  }
});

// ---------------------------------------------------------------------------
// resolveConvexMachineCallerFromDigest
// ---------------------------------------------------------------------------

describe("resolveConvexMachineCallerFromDigest", () => {
  it("resolves the correct digest for the claimed organisation", async () => {
    const table = await tableWith("vpmc_valid", { agentId: "agent_7", scopes: ["world:step"] });
    const { deps } = depsFor(table);
    const result = await resolveConvexMachineCallerFromDigest(
      { credentialDigest: await sha256Hex("vpmc_valid"), claimedOrgId: ORG },
      { ...deps, door: DOOR },
    );
    expect(result).toEqual({
      ok: true,
      tenantId: ORG,
      agent: { present: true, agentId: "agent_7" },
      scopes: ["world:step"],
    });
  });

  it("a wrong digest and a malformed digest refuse identically (credential-invalid)", async () => {
    const table = await tableWith("vpmc_valid");
    const wrong = await resolveConvexMachineCallerFromDigest(
      { credentialDigest: await sha256Hex("vpmc_wrong"), claimedOrgId: ORG },
      { ...depsFor(table).deps, door: DOOR },
    );
    expect(wrong).toMatchObject({
      ok: false,
      refusal: { code: "CREDENTIAL_REFUSED", reason: "credential-invalid", door: DOOR },
    });
    for (const bad of MALFORMED_DIGESTS) {
      const { deps, lookupBySecretHash } = depsFor(table);
      const result = await resolveConvexMachineCallerFromDigest(
        { credentialDigest: bad as string, claimedOrgId: ORG },
        { ...deps, door: DOOR },
      );
      expect(result).toEqual(wrong);
      expect(lookupBySecretHash).not.toHaveBeenCalled();
    }
  });

  it("revoked and expired rows are refused via digest as credential-invalid", async () => {
    for (const row of [{ revoked: true }, { expiresAt: NOW }]) {
      const table = await tableWith("vpmc_x", row);
      const { deps } = depsFor(table);
      const result = await resolveConvexMachineCallerFromDigest(
        { credentialDigest: await sha256Hex("vpmc_x"), claimedOrgId: ORG },
        { ...deps, door: DOOR },
      );
      expect(result).toMatchObject({
        ok: false,
        refusal: { code: "CREDENTIAL_REFUSED", reason: "credential-invalid" },
      });
    }
  });

  it("the refusal never carries the digest", async () => {
    const table = await tableWith("vpmc_valid");
    const digest = await sha256Hex("vpmc_valid");
    const result = await resolveConvexMachineCallerFromDigest(
      { credentialDigest: digest, claimedOrgId: OTHER_ORG },
      { ...depsFor(table).deps, door: DOOR },
    );
    expect(result.ok).toBe(false);
    expect(JSON.stringify(result)).not.toContain(digest);
  });
});
