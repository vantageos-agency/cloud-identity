import { describe, expect, it } from "vitest";
import type { ActingPrincipal } from "../src/principal-by-id.js";
import {
  buildSupportGrant,
  resolveSupportAccess,
  type SupportAccessEvent,
  type StoredSupportGrant,
} from "../src/support-access.js";

const NOW = 1_000_000;
const HOUR = 3_600_000;
const OPERATOR_ORG = "org_operator";
const CLIENT_ORG = "org_client";
const PERSON = "person_support";
const CREATOR = "person_admin"; // differs from PERSON on purpose

const person: ActingPrincipal = { principalId: PERSON, orgId: OPERATOR_ORG, kind: "person" };

function row(over: Partial<StoredSupportGrant> = {}): StoredSupportGrant {
  return {
    personId: PERSON,
    orgId: CLIENT_ORG,
    reason: "client asked for help with import",
    grantedBy: CREATOR,
    grantedAt: NOW - 1000,
    expiresAt: NOW + HOUR,
    revokedAt: null,
    ...over,
  };
}

function run(
  principal: ActingPrincipal,
  target: string,
  lookup: (p: string, o: string) => Promise<StoredSupportGrant | null | undefined>,
  events: SupportAccessEvent[] = [],
  now = NOW,
) {
  return resolveSupportAccess(
    principal,
    target,
    { lookupSupportGrant: lookup, now: () => now, onSupportAccess: (e) => void events.push(e) },
    { door: "tasks:list" },
  );
}

describe("support access: resolveSupportAccess", () => {
  it("support access: no grant is refused (deny by default)", async () => {
    for (const none of [null, undefined]) {
      const r = await run(person, CLIENT_ORG, async () => none);
      expect(r).toMatchObject({ ok: false, refusal: { code: "RBAC_DENIED", reason: "support-grant-absent", door: "tasks:list" } });
    }
  });

  it("support access: a valid grant is allowed and audited with reason and expiry", async () => {
    const events: SupportAccessEvent[] = [];
    const r = await run(person, CLIENT_ORG, async () => row(), events);
    expect(r).toEqual({
      ok: true,
      orgId: CLIENT_ORG,
      grant: { reason: "client asked for help with import", grantedBy: CREATOR, expiresAt: NOW + HOUR },
    });
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({
      outcome: "granted",
      personId: PERSON,
      orgId: CLIENT_ORG,
      door: "tasks:list",
      reason: "client asked for help with import",
      expiresAt: NOW + HOUR,
      at: NOW,
    });
  });

  it("support access: expired at now == expiresAt and after is refused", async () => {
    for (const at of [NOW + HOUR, NOW + HOUR + 1]) {
      const r = await run(person, CLIENT_ORG, async () => row(), [], at);
      expect(r).toMatchObject({ ok: false, refusal: { reason: "support-grant-expired" } });
    }
    const still = await run(person, CLIENT_ORG, async () => row(), [], NOW + HOUR - 1);
    expect(still.ok).toBe(true);
  });

  it("support access: a revoked grant is refused", async () => {
    const r = await run(person, CLIENT_ORG, async () => row({ revokedAt: NOW - 5 }));
    expect(r).toMatchObject({ ok: false, refusal: { code: "RBAC_DENIED", reason: "support-grant-revoked" } });
  });

  it("support access: a row for another person or another org is refused", async () => {
    for (const wrong of [row({ personId: "person_other" }), row({ orgId: "org_other" })]) {
      const r = await run(person, CLIENT_ORG, async () => wrong);
      expect(r).toMatchObject({ ok: false, refusal: { reason: "support-grant-mismatch" } });
      if (!r.ok) {
        expect(JSON.stringify(r.refusal)).not.toContain("person_other");
        expect(JSON.stringify(r.refusal)).not.toContain("org_other");
        expect(JSON.stringify(r.refusal)).not.toContain("client asked");
      }
    }
  });

  it("support access: agent, service and fleet principals are refused even with a matching row", async () => {
    for (const kind of ["agent", "service", "fleet"] as const) {
      const p: ActingPrincipal = { principalId: PERSON, orgId: OPERATOR_ORG, kind };
      const r = await run(p, CLIENT_ORG, async () => row());
      expect(r).toMatchObject({ ok: false, refusal: { reason: "support-grant-not-a-person" } });
    }
  });

  it("support access: the principal's own organisation is not a support access", async () => {
    let looked = false;
    const r = await run(person, OPERATOR_ORG, async () => {
      looked = true;
      return row({ orgId: OPERATOR_ORG });
    });
    expect(r).toMatchObject({ ok: false, refusal: { reason: "support-grant-own-organisation" } });
    expect(looked).toBe(false);
  });

  it("support access: a throwing lookup is lookup-failed, never a grant, and does not echo the error", async () => {
    const r = await run(person, CLIENT_ORG, async () => {
      throw new Error("db password=hunter2");
    });
    expect(r).toMatchObject({ ok: false, refusal: { code: "RBAC_DENIED", reason: "support-grant-lookup-failed" } });
    if (!r.ok) expect(JSON.stringify(r.refusal)).not.toContain("hunter2");
  });

  it("support access: a throwing audit sink does not flip a grant or a refusal", async () => {
    const deps = (lookup: () => Promise<StoredSupportGrant | null>) => ({
      lookupSupportGrant: lookup,
      now: () => NOW,
      onSupportAccess: () => {
        throw new Error("sink down");
      },
    });
    const granted = await resolveSupportAccess(person, CLIENT_ORG, deps(async () => row()), { door: "d" });
    expect(granted.ok).toBe(true);
    const refused = await resolveSupportAccess(person, CLIENT_ORG, deps(async () => null), { door: "d" });
    expect(refused).toMatchObject({ ok: false, refusal: { reason: "support-grant-absent" } });
  });

  it("support access: refusals are audited with outcome refused and the reason", async () => {
    const events: SupportAccessEvent[] = [];
    await run(person, CLIENT_ORG, async () => null, events);
    expect(events).toHaveLength(1);
    expect(events[0]).toMatchObject({ outcome: "refused", reason: "support-grant-absent", personId: PERSON, orgId: CLIENT_ORG, door: "tasks:list" });
  });

  it("support access: a row with a malformed shape is refused, not granted", async () => {
    const bad = { ...row(), expiresAt: "soon" } as unknown as StoredSupportGrant;
    const r = await run(person, CLIENT_ORG, async () => bad);
    expect(r.ok).toBe(false);
  });

  it("support access: an empty target organisation is refused as invalid", async () => {
    const r = await run(person, "", async () => row());
    expect(r).toMatchObject({ ok: false, refusal: { reason: "support-grant-invalid" } });
  });
});

describe("support access: buildSupportGrant", () => {
  const input = {
    personId: PERSON,
    orgId: CLIENT_ORG,
    reason: "client asked for help with import",
    grantedBy: CREATOR,
    now: NOW,
    durationMs: HOUR,
  };
  const policy = { maxDurationMs: 8 * HOUR };

  it("support access: builds the exact row", () => {
    expect(buildSupportGrant(input, policy)).toEqual({
      ok: true,
      grant: {
        personId: PERSON,
        orgId: CLIENT_ORG,
        reason: "client asked for help with import",
        grantedBy: CREATOR,
        grantedAt: NOW,
        expiresAt: NOW + HOUR,
        revokedAt: null,
      },
    });
    expect(buildSupportGrant({ ...input, durationMs: 8 * HOUR }, policy).ok).toBe(true);
  });

  it("support access: rejects a short reason, bad durations and missing ids", () => {
    const cases: Array<Partial<typeof input>> = [
      { reason: "too short" },
      { reason: "         " },
      { durationMs: 0 },
      { durationMs: -1 },
      { durationMs: 8 * HOUR + 1 },
      { durationMs: Number.NaN },
      { grantedBy: "" },
      { personId: "" },
      { orgId: "" },
    ];
    for (const c of cases) {
      const r = buildSupportGrant({ ...input, ...c }, policy);
      expect(r).toMatchObject({ ok: false, refusal: { code: "RBAC_DENIED", reason: "support-grant-invalid" } });
    }
  });

  it("support access: requires a positive maxDurationMs policy", () => {
    expect(buildSupportGrant(input, { maxDurationMs: 0 }).ok).toBe(false);
    expect(buildSupportGrant(input, {} as { maxDurationMs: number }).ok).toBe(false);
  });
});
