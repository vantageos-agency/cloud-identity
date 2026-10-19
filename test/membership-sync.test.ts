import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
  clerkMembershipEvent,
  decideMembershipEvent,
  membershipPersonLookups,
  planMembershipReconcile,
  resolveActingPrincipal,
  verifySvixWebhook,
} from "../src/index.js";

const SECRET_BYTES = Buffer.from("clerk-webhook-test-secret-bytes!");
const SECRET = `whsec_${SECRET_BYTES.toString("base64")}`;
const NOW_MS = 1_760_000_000_000;
const NOW_S = NOW_MS / 1000;
const BODY = '{"type":"organizationMembership.created"}';

function sign(id: string, ts: string, body: string, key: Buffer = SECRET_BYTES): string {
  return `v1,${createHmac("sha256", key).update(`${id}.${ts}.${body}`).digest("base64")}`;
}

function delivery(over: Partial<{ id: string; timestamp: string; signature: string; rawBody: string }> = {}) {
  const id = over.id ?? "msg_1";
  const timestamp = over.timestamp ?? String(NOW_S);
  const rawBody = over.rawBody ?? BODY;
  return { id, timestamp, signature: over.signature ?? sign(id, timestamp, rawBody), rawBody };
}

describe("verifySvixWebhook", () => {
  it("accepts a correctly signed delivery inside the window", async () => {
    expect(await verifySvixWebhook(delivery(), { secret: SECRET, now: NOW_MS })).toEqual({ ok: true });
  });

  it("accepts when one of several candidates matches (secret rotation)", async () => {
    const good = sign("msg_1", String(NOW_S), BODY);
    const signature = `v1,AAAA ${good} v2,ignored`;
    expect(await verifySvixWebhook(delivery({ signature }), { secret: SECRET, now: NOW_MS })).toEqual({ ok: true });
  });

  it("refuses a signature made with a different secret (wrong-secret pole)", async () => {
    const signature = sign("msg_1", String(NOW_S), BODY, Buffer.from("another-secret-entirely-different"));
    const r = await verifySvixWebhook(delivery({ signature }), { secret: SECRET, now: NOW_MS });
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal.reason).toBe("webhook-signature-mismatch");
      expect(r.refusal.code).toBe("CREDENTIAL_REFUSED");
    }
  });

  it("refuses a tampered body, id or timestamp", async () => {
    const good = delivery();
    for (const d of [
      { ...good, rawBody: `${BODY} ` },
      { ...good, id: "msg_2" },
      { ...good, timestamp: String(NOW_S + 1) },
    ]) {
      const r = await verifySvixWebhook(d, { secret: SECRET, now: NOW_MS });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("webhook-signature-mismatch");
    }
  });

  it("refuses an empty, non-v1 or non-base64 signature header as a mismatch", async () => {
    for (const signature of ["v1,", "v2,AAAA", "garbage", "v1,@@@@"]) {
      const r = await verifySvixWebhook(delivery({ signature }), { secret: SECRET, now: NOW_MS });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("webhook-signature-mismatch");
    }
  });

  it("refuses a timestamp older than the window and one in the future (off-window poles)", async () => {
    for (const ts of [NOW_S - 301, NOW_S + 301]) {
      const r = await verifySvixWebhook(delivery({ timestamp: String(ts) }), { secret: SECRET, now: NOW_MS });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("webhook-timestamp-out-of-window");
    }
  });

  it("accepts exactly at the window edge in both directions", async () => {
    for (const ts of [NOW_S - 300, NOW_S + 300]) {
      expect(await verifySvixWebhook(delivery({ timestamp: String(ts) }), { secret: SECRET, now: NOW_MS })).toEqual({
        ok: true,
      });
    }
  });

  it("honours toleranceSeconds", async () => {
    const d = delivery({ timestamp: String(NOW_S - 60) });
    expect((await verifySvixWebhook(d, { secret: SECRET, now: NOW_MS, toleranceSeconds: 30 })).ok).toBe(false);
    expect((await verifySvixWebhook(d, { secret: SECRET, now: NOW_MS, toleranceSeconds: 120 })).ok).toBe(true);
  });

  it("refuses a non-numeric timestamp as out of window", async () => {
    const r = await verifySvixWebhook(delivery({ timestamp: "yesterday" }), { secret: SECRET, now: NOW_MS });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal.reason).toBe("webhook-timestamp-out-of-window");
  });

  it("refuses an absent or malformed secret with webhook-secret-invalid", async () => {
    for (const secret of [undefined, "", "   ", "not-a-whsec", "whsec_", "whsec_!!!notbase64"]) {
      const r = await verifySvixWebhook(delivery(), { secret, now: NOW_MS });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("webhook-secret-invalid");
    }
  });

  it("refuses a missing header with webhook-headers-missing, each header on its own", async () => {
    const d = delivery();
    for (const bad of [
      { ...d, id: undefined },
      { ...d, id: "" },
      { ...d, timestamp: null },
      { ...d, signature: undefined },
    ]) {
      const r = await verifySvixWebhook(bad, { secret: SECRET, now: NOW_MS });
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.refusal.reason).toBe("webhook-headers-missing");
    }
  });

  it("no refusal echoes the secret, the signature or the body", async () => {
    const wrong = sign("msg_1", String(NOW_S), BODY, Buffer.from("another-secret-entirely-different"));
    const cases = [
      await verifySvixWebhook(delivery({ signature: wrong }), { secret: SECRET, now: NOW_MS }),
      await verifySvixWebhook(delivery({ timestamp: "1" }), { secret: SECRET, now: NOW_MS }),
      await verifySvixWebhook(delivery(), { secret: "whsec_!!!", now: NOW_MS }),
      await verifySvixWebhook({ ...delivery(), id: null }, { secret: SECRET, now: NOW_MS }),
    ];
    for (const r of cases) {
      expect(r.ok).toBe(false);
      if (!r.ok) {
        const text = JSON.stringify(r.refusal);
        expect(text).not.toContain(SECRET_BYTES.toString("base64"));
        expect(text).not.toContain(wrong.slice(3));
        expect(text).not.toContain(BODY);
        expect(r.refusal.door).toBeTruthy();
      }
    }
  });

  it("does not stop at the first matching candidate (every candidate is decoded)", async () => {
    const good = sign("msg_1", String(NOW_S), BODY);
    const spy = vi.spyOn(globalThis, "atob");
    await verifySvixWebhook(delivery({ signature: `${good} v1,AAAA v1,BBBB` }), { secret: SECRET, now: NOW_MS });
    // one call for the secret, three for the candidates
    expect(spy.mock.calls.length).toBe(4);
    spy.mockRestore();
  });
});

const fixture = JSON.parse(
  readFileSync(join(__dirname, "fixtures", "clerk-organizationMembership-deleted.example.json"), "utf8"),
) as { _source: string; payload: { timestamp: number; type: string; data: Record<string, unknown> } };

function created(over: Record<string, unknown> = {}, type = "organizationMembership.created") {
  return {
    type,
    data: {
      id: "orgmem_1",
      role: "org:member",
      organization: { id: "org_A", slug: "acme" },
      public_user_data: { user_id: "user_1" },
      ...over,
    },
  };
}

describe("clerkMembershipEvent", () => {
  it("parses the documented Clerk deleted payload; updated_at == created_at, delete time is max(updated_at, svix)", () => {
    expect(fixture._source).toContain("updated_at == data.created_at");
    expect(fixture.payload.data.updated_at).toBe(fixture.payload.data.created_at);
    const r = clerkMembershipEvent(fixture.payload, { svixTimestampSeconds: 1716883200 });
    expect(r).toEqual({
      ok: true,
      kind: "delete",
      orgId: "org_2g7np7Hrk0SN6kj5EDMLDaKNL0S",
      personId: "user_2h8op3Isl1QR7tKu5FGNfaLKEoU",
      orgSlug: "acme-corp",
      role: "member",
      eventAt: 1716883200000,
    });
  });

  it("a delete is timed no earlier than the delivery: svix later than updated_at wins, and the reverse", () => {
    const later = clerkMembershipEvent(fixture.payload, { svixTimestampSeconds: 1716883200 + 90 });
    expect(later).toMatchObject({ kind: "delete", eventAt: 1716883290000 });
    const earlier = clerkMembershipEvent(fixture.payload, { svixTimestampSeconds: 1716883200 - 90 });
    expect(earlier).toMatchObject({ kind: "delete", eventAt: 1716883200000 });
  });

  it("a delete with no updated_at is timed at the delivery", () => {
    const p = created({}, "organizationMembership.deleted");
    expect(clerkMembershipEvent(p, { svixTimestampSeconds: 100 })).toMatchObject({ kind: "delete", eventAt: 100000 });
  });

  it("created and updated are upserts timed at data.updated_at, else the delivery", () => {
    const a = clerkMembershipEvent(created({ updated_at: 5000 }), { svixTimestampSeconds: 100 });
    expect(a).toEqual({
      ok: true,
      kind: "upsert",
      orgId: "org_A",
      personId: "user_1",
      orgSlug: "acme",
      role: "member",
      eventAt: 5000,
    });
    const b = clerkMembershipEvent(created({}, "organizationMembership.updated"), { svixTimestampSeconds: 100 });
    expect(b).toMatchObject({ kind: "upsert", eventAt: 100000 });
  });

  it("org:admin maps to admin, every other role to member", () => {
    expect(clerkMembershipEvent(created({ role: "org:admin" }), { svixTimestampSeconds: 1 })).toMatchObject({
      role: "admin",
    });
    for (const role of ["org:member", "org:billing", "admin", undefined, 7]) {
      expect(clerkMembershipEvent(created({ role }), { svixTimestampSeconds: 1 })).toMatchObject({ role: "member" });
    }
  });

  it("omits orgSlug when the payload has none", () => {
    const r = clerkMembershipEvent(created({ organization: { id: "org_A" } }), { svixTimestampSeconds: 1 });
    expect(r.ok).toBe(true);
    expect(r).not.toHaveProperty("orgSlug");
  });

  it("any other event type is ignored, not refused", () => {
    for (const type of ["user.created", "organization.deleted", "organizationMembership.other", undefined, 3]) {
      expect(clerkMembershipEvent({ ...created(), type }, { svixTimestampSeconds: 1 })).toEqual({
        ok: true,
        kind: "ignore",
      });
    }
  });

  it("refuses membership-event-invalid when an id is missing, empty or not a string", () => {
    const bad = [
      created({ organization: {} }),
      created({ organization: { id: "", slug: "x" } }),
      created({ organization: undefined }),
      created({ public_user_data: {} }),
      created({ public_user_data: { user_id: 5 } }),
      created({ public_user_data: undefined }),
      { type: "organizationMembership.deleted" },
      { type: "organizationMembership.created", data: null },
    ];
    for (const p of bad) {
      const r = clerkMembershipEvent(p, { svixTimestampSeconds: 1 });
      expect(r.ok).toBe(false);
      if (!r.ok) {
        expect(r.refusal.reason).toBe("membership-event-invalid");
        expect(JSON.stringify(r.refusal)).not.toContain("user_1");
      }
    }
  });

  it("ignores a payload with no readable type, and refuses a non-finite delivery time", () => {
    for (const p of [null, undefined, "x", 3, []]) {
      expect(clerkMembershipEvent(p, { svixTimestampSeconds: 1 })).toMatchObject({ ok: true, kind: "ignore" });
    }
    const r = clerkMembershipEvent(created(), { svixTimestampSeconds: Number.NaN });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.refusal.reason).toBe("membership-event-invalid");
  });

  it("ignores a non-finite updated_at and falls back to the delivery time", () => {
    const r = clerkMembershipEvent(created({ updated_at: "soon" }), { svixTimestampSeconds: 7 });
    expect(r).toMatchObject({ kind: "upsert", eventAt: 7000 });
  });
});

describe("decideMembershipEvent", () => {
  const up = (eventAt: number) => ({ kind: "upsert" as const, eventAt });
  const del = (eventAt: number) => ({ kind: "delete" as const, eventAt });

  it("no stored row: both kinds apply, nothing to revive", () => {
    expect(decideMembershipEvent(null, up(1))).toEqual({ apply: true, revive: false });
    expect(decideMembershipEvent(null, del(1))).toEqual({ apply: true, revive: false });
  });

  it("a row never stamped is not stale", () => {
    expect(decideMembershipEvent({}, up(1))).toEqual({ apply: true, revive: false });
  });

  it("upsert: stale at a tie and below, applies above", () => {
    expect(decideMembershipEvent({ lastEventAt: 10 }, up(9)).apply).toBe(false);
    expect(decideMembershipEvent({ lastEventAt: 10 }, up(10)).apply).toBe(false);
    expect(decideMembershipEvent({ lastEventAt: 10 }, up(11))).toEqual({ apply: true, revive: false });
  });

  it("delete: stale only strictly below; the removal wins a tie", () => {
    expect(decideMembershipEvent({ lastEventAt: 10 }, del(9)).apply).toBe(false);
    expect(decideMembershipEvent({ lastEventAt: 10 }, del(10)).apply).toBe(true);
    expect(decideMembershipEvent({ lastEventAt: 10 }, del(11)).apply).toBe(true);
  });

  it("a stale upsert after a delete does not revive; a tie does not revive either", () => {
    const tomb = { lastEventAt: 10, deletedAt: 10 };
    expect(decideMembershipEvent(tomb, up(5))).toEqual({ apply: false, revive: false });
    expect(decideMembershipEvent(tomb, up(10))).toEqual({ apply: false, revive: false });
  });

  it("an upsert newer than the tombstone revives", () => {
    expect(decideMembershipEvent({ lastEventAt: 10, deletedAt: 10 }, up(11))).toEqual({ apply: true, revive: true });
  });

  it("a tombstone with no lastEventAt is still ordered by its deletedAt", () => {
    expect(decideMembershipEvent({ deletedAt: 10 }, up(10)).apply).toBe(false);
    expect(decideMembershipEvent({ deletedAt: 10 }, up(11)).revive).toBe(true);
  });

  it("a second delete on a tombstone applies without reviving", () => {
    expect(decideMembershipEvent({ lastEventAt: 10, deletedAt: 10 }, del(12))).toEqual({ apply: true, revive: false });
  });

  it("removing a member created at the same time (documented payload) applies", () => {
    const ev = clerkMembershipEvent(fixture.payload, { svixTimestampSeconds: 1716883200 });
    if (!ev.ok || ev.kind === "ignore") throw new Error("fixture must parse");
    // the row was written by the create event at updated_at == created_at
    expect(decideMembershipEvent({ lastEventAt: 1716883200000 }, ev).apply).toBe(true);
    // and a create at that same instant, arriving after the removal, is stale
    expect(decideMembershipEvent({ lastEventAt: ev.eventAt, deletedAt: ev.eventAt }, up(1716883200000)).apply).toBe(
      false,
    );
  });
});

describe("membershipPersonLookups", () => {
  it("a live row is an active person in that org", async () => {
    const read = vi.fn(() => ({ role: "member" as const }));
    const { personById } = membershipPersonLookups(read);
    expect(await personById("user_1", "org_A")).toEqual({ id: "user_1", orgId: "org_A", active: true });
    expect(read).toHaveBeenCalledWith("org_A", "user_1");
  });

  it("an absent row is null", async () => {
    const { personById } = membershipPersonLookups(async () => null);
    expect(await personById("user_1", "org_A")).toBeNull();
  });

  it("a tombstoned row is null", async () => {
    const { personById } = membershipPersonLookups(async () => ({ deletedAt: 5 }));
    expect(await personById("user_1", "org_A")).toBeNull();
  });

  it("a throwing read propagates so the resolver can refuse principal-lookup-failed", async () => {
    const { personById } = membershipPersonLookups(() => {
      throw new Error("db down");
    });
    await expect(personById("user_1", "org_A")).rejects.toThrow("db down");
  });

  it("plugs into resolveActingPrincipal: live resolves, tombstone refuses", async () => {
    const org = { id: "org_A", active: true };
    const base = { organisationById: async () => org, orgKindOf: async () => "tenant" as never };
    const live = await resolveActingPrincipal(
      { personId: "user_1", verifiedOrgId: "org_A" },
      { ...base, ...membershipPersonLookups(() => ({})) },
      "test:door",
    );
    expect(live.ok).toBe(true);
    const gone = await resolveActingPrincipal(
      { personId: "user_1", verifiedOrgId: "org_A" },
      { ...base, ...membershipPersonLookups(() => ({ deletedAt: 1 })) },
      "test:door",
    );
    expect(gone.ok).toBe(false);
  });
});

describe("planMembershipReconcile", () => {
  const AT = 1000;
  const row = (personId: string, extra: Record<string, unknown> = {}, orgId = "org_A") => ({
    orgId,
    personId,
    role: "member" as const,
    ...extra,
  });
  const fromClerk = (personId: string, extra: Record<string, unknown> = {}, orgId = "org_A") => ({
    orgId,
    personId,
    role: "member" as const,
    orgSlug: "acme",
    ...extra,
  });

  it("upserts what Clerk reports and nothing is tombstoned when stored == Clerk", () => {
    const plan = planMembershipReconcile([row("u1")], [fromClerk("u1")], { at: AT, fullyReadOrgIds: ["org_A"] });
    expect(plan.tombstones).toEqual([]);
    expect(plan.upserts).toEqual([
      { orgId: "org_A", personId: "u1", role: "member", orgSlug: "acme", eventAt: AT, revive: false },
    ]);
  });

  it("inserts a member Clerk reports that is not stored, and carries a role change", () => {
    const plan = planMembershipReconcile([row("u1")], [fromClerk("u1", { role: "admin" }), fromClerk("u2")], {
      at: AT,
      fullyReadOrgIds: ["org_A"],
    });
    expect(plan.upserts.map((u) => [u.personId, u.role])).toEqual([
      ["u1", "admin"],
      ["u2", "member"],
    ]);
  });

  it("tombstones a stored member Clerk no longer reports, in a fully read org", () => {
    const plan = planMembershipReconcile([row("u1"), row("u2")], [fromClerk("u1")], {
      at: AT,
      fullyReadOrgIds: ["org_A"],
    });
    expect(plan.tombstones).toEqual([{ orgId: "org_A", personId: "u2", eventAt: AT }]);
  });

  it("partial-read safety: never tombstones in an org that was not fully read", () => {
    const stored = [row("u1"), row("u2", {}, "org_B")];
    const plan = planMembershipReconcile(stored, [fromClerk("u1")], { at: AT, fullyReadOrgIds: [] });
    expect(plan.tombstones).toEqual([]);
    const only = planMembershipReconcile(stored, [fromClerk("u1")], { at: AT, fullyReadOrgIds: ["org_A"] });
    expect(only.tombstones).toEqual([]);
    const b = planMembershipReconcile(stored, [], { at: AT, fullyReadOrgIds: ["org_B"] });
    expect(b.tombstones).toEqual([{ orgId: "org_B", personId: "u2", eventAt: AT }]);
  });

  it("an empty Clerk read of a fully read org tombstones every stored member of it", () => {
    const plan = planMembershipReconcile([row("u1"), row("u2")], [], { at: AT, fullyReadOrgIds: ["org_A"] });
    expect(plan.tombstones.map((t) => t.personId)).toEqual(["u1", "u2"]);
  });

  it("never touches a row an event stamped after the read", () => {
    const stored = [row("u1", { lastEventAt: AT + 1 }), row("u2", { lastEventAt: AT + 1 })];
    const plan = planMembershipReconcile(stored, [fromClerk("u1", { role: "admin" })], {
      at: AT,
      fullyReadOrgIds: ["org_A"],
    });
    expect(plan.upserts).toEqual([]);
    expect(plan.tombstones).toEqual([]);
  });

  it("a row stamped exactly at the read is not overwritten by an upsert, but is removed (removal wins a tie)", () => {
    const stored = [row("u1", { lastEventAt: AT }), row("u2", { lastEventAt: AT })];
    const plan = planMembershipReconcile(stored, [fromClerk("u1")], { at: AT, fullyReadOrgIds: ["org_A"] });
    expect(plan.upserts).toEqual([]);
    expect(plan.tombstones).toEqual([{ orgId: "org_A", personId: "u2", eventAt: AT }]);
  });

  it("does not tombstone an already tombstoned row", () => {
    const plan = planMembershipReconcile([row("u1", { deletedAt: 5, lastEventAt: 5 })], [], {
      at: AT,
      fullyReadOrgIds: ["org_A"],
    });
    expect(plan.tombstones).toEqual([]);
  });

  it("revives a tombstoned row Clerk reports, unless an event is newer than the read", () => {
    const plan = planMembershipReconcile([row("u1", { deletedAt: 5, lastEventAt: 5 })], [fromClerk("u1")], {
      at: AT,
      fullyReadOrgIds: ["org_A"],
    });
    expect(plan.upserts).toEqual([
      { orgId: "org_A", personId: "u1", role: "member", orgSlug: "acme", eventAt: AT, revive: true },
    ]);
    const newer = planMembershipReconcile([row("u1", { deletedAt: AT + 5, lastEventAt: AT + 5 })], [fromClerk("u1")], {
      at: AT,
      fullyReadOrgIds: ["org_A"],
    });
    expect(newer.upserts).toEqual([]);
  });

  it("the same person in two orgs is two rows", () => {
    const stored = [row("u1"), row("u1", {}, "org_B")];
    const plan = planMembershipReconcile(stored, [fromClerk("u1")], { at: AT, fullyReadOrgIds: ["org_A", "org_B"] });
    expect(plan.tombstones).toEqual([{ orgId: "org_B", personId: "u1", eventAt: AT }]);
  });
});
