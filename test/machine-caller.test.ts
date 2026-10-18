import { describe, expect, it, vi } from "vitest";
import {
  type IdentityRefusal,
  mintMachineCredential,
  resolveConvexMachineCaller,
  type StoredBearerRow,
  sha256Hex,
} from "../src/index.js";

const DOOR = "engine:world.step";
const ORG = "org_ALPHA1";
const OTHER_ORG = "org_BETA2";
const NOW = 1_700_000_000_000;

async function store(credential: string, row: Partial<StoredBearerRow> = {}) {
  const secretHash = await sha256Hex(credential);
  const table = new Map<string, unknown>([[secretHash, { tenantId: ORG, secretHash, ...row }]]);
  const lookupBySecretHash = vi.fn(async (digest: string) => (table.get(digest) ?? null) as StoredBearerRow | null);
  return { secretHash, lookupBySecretHash };
}

function refusalOf(result: Awaited<ReturnType<typeof resolveConvexMachineCaller>>): IdentityRefusal {
  if (result.ok) throw new Error("expected a refusal");
  return result.refusal;
}

describe("resolveConvexMachineCaller: a machine credential passed as a Convex function argument", () => {
  it("resolves a valid credential whose row belongs to the claimed organisation", async () => {
    const { lookupBySecretHash } = await store("vpmc_valid", { agentId: "agent_7", scopes: ["world:step"] });
    const result = await resolveConvexMachineCaller(
      { credential: "vpmc_valid", claimedOrgId: ORG },
      { door: DOOR, lookupBySecretHash, now: () => NOW },
    );
    expect(result).toEqual({
      ok: true,
      tenantId: ORG,
      agent: { present: true, agentId: "agent_7" },
      scopes: ["world:step"],
    });
  });

  it("resolves an organisation-wide credential with the agent as an explicit absence", async () => {
    const { lookupBySecretHash } = await store("vpmc_orgwide");
    const result = await resolveConvexMachineCaller(
      { credential: "vpmc_orgwide", claimedOrgId: ORG },
      { door: DOOR, lookupBySecretHash },
    );
    expect(result).toMatchObject({
      ok: true,
      tenantId: ORG,
      agent: { present: false, code: "AGENT_ABSENT", reason: "organization-wide-token" },
      scopes: [],
    });
  });

  it("refuses the same valid credential claimed for another organisation: RBAC_DENIED other-organisation", async () => {
    const { lookupBySecretHash } = await store("vpmc_valid");
    const refusal = refusalOf(
      await resolveConvexMachineCaller(
        { credential: "vpmc_valid", claimedOrgId: OTHER_ORG },
        { door: DOOR, lookupBySecretHash },
      ),
    );
    expect(refusal).toMatchObject({ code: "RBAC_DENIED", reason: "other-organisation", door: DOOR });
    expect(refusal.detail).not.toContain(OTHER_ORG);
    expect(refusal.detail).not.toContain(ORG);
    expect(refusal.detail).not.toContain("vpmc_valid");
  });

  it("refuses unknown, revoked, expired, wrong-stored-digest and malformed rows with ONE identical refusal", async () => {
    const credential = "vpmc_probe";
    const digest = await sha256Hex(credential);
    const rows: Record<string, unknown> = {
      unknown: null,
      revoked: { tenantId: ORG, secretHash: digest, revoked: true },
      expired: { tenantId: ORG, secretHash: digest, expiresAt: NOW },
      wrongDigest: { tenantId: ORG, secretHash: "0".repeat(64) },
      malformed: { tenantId: "", secretHash: digest },
    };
    const refusals: IdentityRefusal[] = [];
    for (const row of Object.values(rows)) {
      const lookupBySecretHash = vi.fn(async () => row as StoredBearerRow | null);
      refusals.push(
        refusalOf(
          await resolveConvexMachineCaller(
            { credential, claimedOrgId: ORG },
            { door: DOOR, lookupBySecretHash, now: () => NOW },
          ),
        ),
      );
      expect(lookupBySecretHash).toHaveBeenCalledWith(digest);
    }
    expect(refusals).toHaveLength(5);
    expect(refusals[0]).toMatchObject({ code: "CREDENTIAL_REFUSED", reason: "credential-invalid", door: DOOR });
    for (const r of refusals) {
      expect(r).toEqual(refusals[0]);
      expect(r.detail).not.toContain(credential);
      expect(r.detail).not.toContain(digest);
      expect(r.detail).not.toContain(ORG);
    }
  });

  it("still reports the internal reason of each collapsed refusal to onRefusal", async () => {
    const credential = "vpmc_probe";
    const digest = await sha256Hex(credential);
    const reasons: string[] = [];
    await resolveConvexMachineCaller(
      { credential, claimedOrgId: ORG },
      {
        door: DOOR,
        lookupBySecretHash: async () => ({ tenantId: ORG, secretHash: digest, revoked: true }),
        onRefusal: (r) => reasons.push(r),
      },
    );
    expect(reasons).toEqual(["revoked-token"]);
  });

  it("refuses a lookup that throws with a DISTINCT refusal, never a grant", async () => {
    const refusal = refusalOf(
      await resolveConvexMachineCaller(
        { credential: "vpmc_valid", claimedOrgId: ORG },
        {
          door: DOOR,
          lookupBySecretHash: async () => {
            throw new Error("db down vpmc_valid");
          },
        },
      ),
    );
    expect(refusal).toMatchObject({ code: "RBAC_DENIED", reason: "principal-lookup-failed", door: DOOR });
    expect(refusal.reason).not.toBe("credential-invalid");
    expect(refusal.detail).not.toContain("vpmc_valid");
  });

  for (const [label, input] of [
    ["an empty credential", { credential: "", claimedOrgId: ORG }],
    ["a non-string credential", { credential: 42, claimedOrgId: ORG }],
    ["an absent credential", { claimedOrgId: ORG }],
    ["an empty claimed organisation", { credential: "vpmc_valid", claimedOrgId: "" }],
    ["a non-string claimed organisation", { credential: "vpmc_valid", claimedOrgId: { id: ORG } }],
    ["no input at all", null],
  ] as const) {
    it(`refuses ${label} without calling the lookup`, async () => {
      const lookupBySecretHash = vi.fn(async () => null);
      const refusal = refusalOf(
        await resolveConvexMachineCaller(input as unknown as { credential: string; claimedOrgId: string }, {
          door: DOOR,
          lookupBySecretHash,
        }),
      );
      expect(refusal).toMatchObject({ code: "CREDENTIAL_REFUSED", reason: "credential-invalid", door: DOOR });
      expect(lookupBySecretHash).not.toHaveBeenCalled();
    });
  }

  it("throws a TypeError, not a refusal, when the consumer supplies no lookup", async () => {
    await expect(
      resolveConvexMachineCaller(
        { credential: "vpmc_valid", claimedOrgId: ORG },
        { door: DOOR } as unknown as Parameters<typeof resolveConvexMachineCaller>[1],
      ),
    ).rejects.toBeInstanceOf(TypeError);
  });
});

describe("mintMachineCredential", () => {
  it("mints a vpmc_ credential of 32 random bytes, base64url, with its sha256 digest", async () => {
    const { credential, secretHash } = await mintMachineCredential();
    expect(credential.startsWith("vpmc_")).toBe(true);
    const body = credential.slice("vpmc_".length);
    expect(body.length).toBeGreaterThanOrEqual(43);
    expect(body).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(secretHash).toBe(await sha256Hex(credential));
  });

  it("two mints differ", async () => {
    const a = await mintMachineCredential();
    const b = await mintMachineCredential();
    expect(a.credential).not.toBe(b.credential);
    expect(a.secretHash).not.toBe(b.secretHash);
  });

  it("round trip: mint, store the digest only, resolve ok", async () => {
    const { credential, secretHash } = await mintMachineCredential();
    const table = new Map<string, StoredBearerRow>([[secretHash, { tenantId: ORG, secretHash, agentId: "agent_w" }]]);
    const result = await resolveConvexMachineCaller(
      { credential, claimedOrgId: ORG },
      { door: DOOR, lookupBySecretHash: async (d) => table.get(d) ?? null },
    );
    expect(result).toMatchObject({ ok: true, tenantId: ORG, agent: { present: true, agentId: "agent_w" } });
  });
});
