/**
 * Clerk membership sync, store-agnostic.
 *
 * Five pure pieces a consumer composes around its own HTTP route and tables:
 * verify the Svix signature, parse the membership event, decide whether it
 * applies to the stored row, answer "is this person a live member" from that
 * row, and plan a backfill against a full read of Clerk. Nothing here reads or
 * writes a store, and no refusal carries the secret, the signature or the body.
 */

import { type IdentityRefusal, refusal } from "./identity-refusal.js";
import type { PrincipalLookups } from "./principal-by-id.js";

// ---------------------------------------------------------------------------
// Svix signature
// ---------------------------------------------------------------------------

const DEFAULT_TOLERANCE_SECONDS = 300;

/** The three Svix headers and the raw request body, exactly as received. */
export type SvixDelivery = {
  /** `svix-id` */
  id?: string | null;
  /** `svix-timestamp`, seconds since the epoch, as sent. */
  timestamp?: string | null;
  /** `svix-signature`: space-separated `v1,<base64>` candidates. */
  signature?: string | null;
  /** The body bytes as text, before any JSON parse. */
  rawBody: string;
};

export type VerifySvixWebhookOptions = {
  /** `whsec_<base64>`. Absent or malformed refuses `webhook-secret-invalid`. */
  secret?: string | null;
  /** Current time in milliseconds. Defaults to `Date.now()`. */
  now?: number;
  /** Accepted distance from `now` in seconds, in both directions. Default 300. */
  toleranceSeconds?: number;
};

export type VerifySvixWebhookResult = { ok: true } | { ok: false; refusal: IdentityRefusal };

function base64ToBytes(b64: string): Uint8Array | null {
  try {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  } catch {
    return null;
  }
}

/** Constant-time over equal-length arrays; unequal length is false. */
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * Verifies a Clerk (Svix) webhook delivery with Web Crypto: HMAC-SHA256 over
 * `${id}.${timestamp}.${rawBody}`, keyed by the base64 part of `whsec_<base64>`.
 * Every `v1,<base64>` candidate is decoded and compared, with no early exit, so
 * the time taken does not say which candidate was right. A timestamp that is
 * not a plain number of seconds is outside the window.
 */
export async function verifySvixWebhook(
  delivery: SvixDelivery,
  options: VerifySvixWebhookOptions,
): Promise<VerifySvixWebhookResult> {
  const door = "membership-sync:verifySvixWebhook";
  const deny = (reason: Parameters<typeof refusal>[1], detail: string): VerifySvixWebhookResult => ({
    ok: false,
    refusal: refusal("CREDENTIAL_REFUSED", reason, door, detail),
  });

  const secret = options.secret;
  const keyBytes =
    typeof secret === "string" && secret.startsWith("whsec_") ? base64ToBytes(secret.slice("whsec_".length)) : null;
  if (keyBytes === null || keyBytes.length === 0) {
    return deny("webhook-secret-invalid", "The webhook secret is absent or is not in whsec_<base64> form.");
  }

  const { id, timestamp, signature, rawBody } = delivery;
  if (!id || !timestamp || !signature) {
    return deny("webhook-headers-missing", "A required svix-id, svix-timestamp or svix-signature header is absent.");
  }

  const now = options.now ?? Date.now();
  const tolerance = options.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  if (!/^\d{1,12}$/.test(timestamp) || Math.abs(now / 1000 - Number(timestamp)) > tolerance) {
    return deny("webhook-timestamp-out-of-window", "The delivery timestamp is outside the accepted window.");
  }

  const key = await crypto.subtle.importKey("raw", keyBytes as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, [
    "sign",
  ]);
  const expected = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(`${id}.${timestamp}.${rawBody}`)),
  );

  let matched = false;
  for (const candidate of signature.split(" ")) {
    const [version, sig] = candidate.split(",");
    const bytes = version === "v1" && sig ? base64ToBytes(sig) : null;
    if (bytes !== null && timingSafeEqual(expected, bytes)) matched = true;
  }
  return matched ? { ok: true } : deny("webhook-signature-mismatch", "No signature candidate matches the delivery.");
}

// ---------------------------------------------------------------------------
// The membership event
// ---------------------------------------------------------------------------

/** A parsed Clerk membership event. IDs are Clerk's permanent ones. */
export type MembershipEvent = {
  /** `created` and `updated` are upserts, `deleted` is a delete. */
  kind: "upsert" | "delete";
  orgId: string;
  personId: string;
  /** The organisation's renamable label, when the payload carries one. */
  orgSlug?: string;
  /** `org:admin` is `admin`; every other role is `member`. */
  role: "admin" | "member";
  /** Event time in milliseconds. Ordering is decided on this, never on arrival. */
  eventAt: number;
};

export type ClerkMembershipEventResult =
  | ({ ok: true } & MembershipEvent)
  | { ok: true; kind: "ignore" }
  | { ok: false; refusal: IdentityRefusal };

const MEMBERSHIP_EVENT_TYPES = {
  "organizationMembership.created": "upsert",
  "organizationMembership.updated": "upsert",
  "organizationMembership.deleted": "delete",
} as const;

const isRecord = (v: unknown): v is Record<string, unknown> => typeof v === "object" && v !== null && !Array.isArray(v);
const nonEmptyString = (v: unknown): v is string => typeof v === "string" && v.length > 0;

/**
 * Parses a Clerk `organizationMembership.created|updated|deleted` payload (the
 * JSON already verified by `verifySvixWebhook`). Any other event type is
 * `{ ok: true, kind: "ignore" }`. A membership event without an organisation or
 * user ID refuses `membership-event-invalid`.
 *
 * Event time: an upsert is `data.updated_at`, else the delivery time. A delete is
 * `max(data.updated_at, delivery time)`: Clerk does not touch `updated_at` on a
 * removal (it equals `created_at`), so a removal is never dated before the
 * moment Clerk sent it and cannot lose to an earlier create or update.
 */
export function clerkMembershipEvent(
  payload: unknown,
  context: { svixTimestampSeconds: number },
): ClerkMembershipEventResult {
  const kind = isRecord(payload) ? (MEMBERSHIP_EVENT_TYPES as Record<string, "upsert" | "delete">)[String(payload.type)] : undefined;
  if (kind === undefined || !isRecord(payload)) return { ok: true, kind: "ignore" };

  const door = "membership-sync:clerkMembershipEvent";
  const invalid = (detail: string): ClerkMembershipEventResult => ({
    ok: false,
    refusal: refusal("RBAC_DENIED", "membership-event-invalid", door, detail),
  });

  const data = isRecord(payload.data) ? payload.data : {};
  const organization = isRecord(data.organization) ? data.organization : {};
  const user = isRecord(data.public_user_data) ? data.public_user_data : {};
  const orgId = organization.id;
  const personId = user.user_id;
  if (!nonEmptyString(orgId) || !nonEmptyString(personId)) {
    return invalid("The membership event does not carry an organisation ID and a user ID.");
  }
  if (!Number.isFinite(context.svixTimestampSeconds)) {
    return invalid("The delivery time is not a finite number of seconds.");
  }

  const deliveredAt = context.svixTimestampSeconds * 1000;
  const updatedAt = typeof data.updated_at === "number" && Number.isFinite(data.updated_at) ? data.updated_at : undefined;
  const eventAt = kind === "delete" ? Math.max(updatedAt ?? 0, deliveredAt) : (updatedAt ?? deliveredAt);

  return {
    ok: true,
    kind,
    orgId,
    personId,
    ...(nonEmptyString(organization.slug) ? { orgSlug: organization.slug } : {}),
    role: data.role === "org:admin" ? "admin" : "member",
    eventAt,
  };
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

/** What the decision reads from a stored membership row. */
export type StoredMembershipState = { lastEventAt?: number; deletedAt?: number };

export type DecideMembershipEventResult = {
  /** False: the event is stale, write nothing. */
  apply: boolean;
  /** True: apply the event AND clear the row's tombstone. */
  revive: boolean;
};

/**
 * Whether an event applies to the stored row. An upsert at or before the last
 * applied time is stale (replay or late). A delete is stale only when strictly
 * older: at a tie the removal wins, so a removed member never stays live because
 * a create or update carried the same time. An upsert newer than a tombstone
 * revives. A tombstone that lost its `lastEventAt` is ordered by `deletedAt`.
 */
export function decideMembershipEvent(
  existing: StoredMembershipState | null,
  event: Pick<MembershipEvent, "kind" | "eventAt">,
): DecideMembershipEventResult {
  const last = existing === null ? undefined : (existing.lastEventAt ?? existing.deletedAt);
  const stale = last !== undefined && (event.kind === "delete" ? event.eventAt < last : event.eventAt <= last);
  if (stale) return { apply: false, revive: false };
  return { apply: true, revive: event.kind === "upsert" && existing?.deletedAt !== undefined };
}

// ---------------------------------------------------------------------------
// The owner-membership lookup
// ---------------------------------------------------------------------------

/** What `membershipPersonLookups` reads from a stored membership row. */
export type StoredMembershipRead = {
  deletedAt?: number;
  /** The role as the consumer stored it (for Clerk: `"org:admin"`). Never interpreted here. */
  role?: string | null;
  /** The organisation the row names, when it carries one; re-checked by the membership resolver. */
  orgId?: string | null;
};

/** The membership of ONE person in ONE organisation, in the shape `buildAgentLink` and `resolveMembership` read. */
export type MembershipLookupResult = { active: boolean; role: string | null; orgId?: string };

/**
 * The lookups answered from the consumer's own membership row, from ONE closure.
 * `readMembership` returns the row for (org ID, person ID) or null; an absent row
 * and a tombstoned one (`deletedAt` set) are both a removed member.
 *
 * - `personById` is for `resolveActingPrincipal`: `{ id, orgId, active: true }`
 *   for a live row, `null` otherwise.
 * - `lookupMembership(personId, orgId)` is for `buildAgentLink`, `resolveAgentLink`
 *   and `resolveMembership`: `{ active, role, orgId? }` with the STORED role for a
 *   live row, `{ active: false, role: null }` for a tombstone (a removed member's
 *   stale role is never surfaced), `null` for an absent row. The role is returned
 *   as stored and decided elsewhere (`adminRoles`, matched exactly).
 *
 * A throwing read propagates from both, so a failure is never taken for an
 * absence: the resolver refuses `principal-lookup-failed`, the membership
 * resolver `membership-lookup-failed`.
 */
export function membershipPersonLookups(
  readMembership: (
    orgId: string,
    personId: string,
  ) => StoredMembershipRead | null | undefined | Promise<StoredMembershipRead | null | undefined>,
): Pick<PrincipalLookups, "personById"> & {
  lookupMembership: (personId: string, orgId: string) => Promise<MembershipLookupResult | null>;
} {
  return {
    personById: async (personId, orgId) => {
      const row = await readMembership(orgId, personId);
      return row === null || row === undefined || row.deletedAt !== undefined
        ? null
        : { id: personId, orgId, active: true };
    },
    lookupMembership: async (personId, orgId) => {
      const row = await readMembership(orgId, personId);
      if (row === null || row === undefined) return null;
      if (row.deletedAt !== undefined) return { active: false, role: null };
      const named = typeof row.orgId === "string" && row.orgId.length > 0 ? { orgId: row.orgId } : {};
      return { active: true, role: row.role ?? null, ...named };
    },
  };
}

// ---------------------------------------------------------------------------
// Backfill plan
// ---------------------------------------------------------------------------

export type MembershipRow = StoredMembershipState & {
  orgId: string;
  personId: string;
  role: "admin" | "member";
};

export type ClerkMembershipRow = {
  orgId: string;
  personId: string;
  role: "admin" | "member";
  orgSlug?: string;
};

export type PlanMembershipReconcileOptions = {
  /** The time of the Clerk read, in milliseconds: the event time of everything planned. */
  at: number;
  /** Organisations whose member list was read to the end. Only these may lose a member. */
  fullyReadOrgIds: readonly string[];
};

export type MembershipUpsert = ClerkMembershipRow & { eventAt: number; revive: boolean };
export type MembershipTombstone = { orgId: string; personId: string; eventAt: number };
export type MembershipReconcilePlan = { upserts: MembershipUpsert[]; tombstones: MembershipTombstone[] };

/**
 * Plans the reconcile of stored memberships against what Clerk reports, as data:
 * the consumer applies it. Every member Clerk reports is upserted (a tombstoned
 * one is revived); a stored member Clerk does not report is tombstoned only in
 * an organisation whose list was read to the end, so a partial read never
 * removes anyone. A row stamped after the read is never touched: an upsert
 * follows `decideMembershipEvent` (stale at a tie), a tombstone is stale only
 * when strictly older.
 */
export function planMembershipReconcile(
  stored: readonly MembershipRow[],
  fromClerk: readonly ClerkMembershipRow[],
  options: PlanMembershipReconcileOptions,
): MembershipReconcilePlan {
  const key = (orgId: string, personId: string) => `${orgId}\u0000${personId}`;
  const storedByKey = new Map(stored.map((r) => [key(r.orgId, r.personId), r]));
  const fullyRead = new Set(options.fullyReadOrgIds);
  const reported = new Set<string>();

  const upserts: MembershipUpsert[] = [];
  for (const c of fromClerk) {
    const k = key(c.orgId, c.personId);
    if (reported.has(k)) continue;
    reported.add(k);
    const decision = decideMembershipEvent(storedByKey.get(k) ?? null, { kind: "upsert", eventAt: options.at });
    if (!decision.apply) continue;
    upserts.push({ ...c, eventAt: options.at, revive: decision.revive });
  }

  const tombstones: MembershipTombstone[] = [];
  for (const r of stored) {
    if (!fullyRead.has(r.orgId) || reported.has(key(r.orgId, r.personId)) || r.deletedAt !== undefined) continue;
    if (!decideMembershipEvent(r, { kind: "delete", eventAt: options.at }).apply) continue;
    tombstones.push({ orgId: r.orgId, personId: r.personId, eventAt: options.at });
  }
  return { upserts, tombstones };
}
