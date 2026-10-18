/**
 * Support access: a time-bounded, audited grant instead of membership.
 *
 * A person principal of the operator organisation does not belong to a client
 * organisation, so client data is not visible to him by default. When a client
 * asks for help, the operator activates a SUPPORT GRANT: who (the person's
 * stored ID), which organisation (the client's stored ID), why (a reason),
 * until when. Absent a live grant the answer is a refusal.
 *
 * The identity decision lives here; the consumer supplies storage only:
 *
 *   - `buildSupportGrant` validates the activation and returns the row to store.
 *   - `resolveSupportAccess` decides, per read, whether a person principal may
 *     act inside a target organisation under a stored grant, and reports every
 *     attempt (granted or refused) to the consumer's audit sink.
 *
 * Revocation is setting `revokedAt` on the stored row. Expiry needs no write.
 * Nothing here reads a name: persons and organisations are identified by ID.
 *
 * @security The refusals never echo another row's ids or its reason text, and a
 * lookup error is reported by kind only, never by its message.
 */

import { type IdentityRefusal, refusal } from "./identity-refusal.js";
import type { ActingPrincipal } from "./principal-by-id.js";

/** Minimum length of the reason an operator must give. */
const MIN_REASON_LENGTH = 10;

/** The row the consumer stores. */
export type StoredSupportGrant = {
  personId: string;
  orgId: string;
  reason: string;
  grantedBy: string;
  grantedAt: number;
  expiresAt: number;
  revokedAt: number | null;
};

export type BuildSupportGrantInput = {
  /** The person principal's stored ID that receives the access. */
  personId: string;
  /** The client organisation's stored ID. */
  orgId: string;
  /** Why the access is activated; at least 10 characters. */
  reason: string;
  /** The stored ID of the person who activates the grant. */
  grantedBy: string;
  /** Epoch milliseconds at activation. */
  now: number;
  /** How long the grant lives, in milliseconds. */
  durationMs: number;
};

export type BuildSupportGrantPolicy = {
  /** The consumer's ceiling on a grant's duration. Required, no default. */
  maxDurationMs: number;
};

export type BuildSupportGrantResult =
  | { ok: true; grant: StoredSupportGrant }
  | { ok: false; refusal: IdentityRefusal };

export type SupportAccessEvent =
  | {
      outcome: "granted";
      personId: string;
      orgId: string;
      door: string;
      reason: string;
      expiresAt: number;
      at: number;
    }
  | {
      outcome: "refused";
      personId: string;
      orgId: string;
      door: string;
      /** The refusal reason word, e.g. `support-grant-expired`. */
      reason: string;
      at: number;
    };

export type SupportAccessDeps = {
  /** Reads the stored grant for exactly this (person, organisation), or nothing. */
  lookupSupportGrant: (
    personId: string,
    orgId: string,
  ) => Promise<StoredSupportGrant | null | undefined>;
  /** Injectable clock, epoch milliseconds. */
  now?: () => number;
  /** Audit sink. Must not throw; if it does, the throw is swallowed and the outcome stands. */
  onSupportAccess?: (event: SupportAccessEvent) => void;
};

export type SupportAccessOptions = {
  /** The consumer's own name for the entry point asking. */
  door: string;
};

export type SupportAccessResult =
  | {
      ok: true;
      orgId: string;
      grant: { reason: string; grantedBy: string; expiresAt: number };
    }
  | { ok: false; refusal: IdentityRefusal };

function nonEmpty(v: unknown): v is string {
  return typeof v === "string" && v.trim().length > 0;
}

function deny(
  reason: Parameters<typeof refusal>[1],
  door: string,
  detail: string,
): { ok: false; refusal: IdentityRefusal } {
  return { ok: false, refusal: refusal("RBAC_DENIED", reason, door, detail) };
}

/**
 * Validates a support-grant activation and returns the row to store.
 * The consumer's policy ceiling `maxDurationMs` is required and has no default.
 */
export function buildSupportGrant(
  input: BuildSupportGrantInput,
  policy: BuildSupportGrantPolicy,
): BuildSupportGrantResult {
  const door = "buildSupportGrant";
  const invalid = (detail: string) => deny("support-grant-invalid", door, detail);
  if (
    !policy ||
    typeof policy.maxDurationMs !== "number" ||
    !Number.isFinite(policy.maxDurationMs) ||
    policy.maxDurationMs <= 0
  ) {
    return invalid("The maximum grant duration is not configured.");
  }
  if (!input || typeof input !== "object") return invalid("The grant input is missing.");
  if (!nonEmpty(input.personId)) return invalid("The person ID is required.");
  if (!nonEmpty(input.orgId)) return invalid("The organisation ID is required.");
  if (!nonEmpty(input.grantedBy)) return invalid("The granting person ID is required.");
  if (typeof input.reason !== "string" || input.reason.trim().length < MIN_REASON_LENGTH) {
    return invalid(`A reason of at least ${MIN_REASON_LENGTH} characters is required.`);
  }
  if (typeof input.now !== "number" || !Number.isFinite(input.now)) {
    return invalid("The activation time is required.");
  }
  if (
    typeof input.durationMs !== "number" ||
    !Number.isFinite(input.durationMs) ||
    input.durationMs <= 0 ||
    input.durationMs > policy.maxDurationMs
  ) {
    return invalid("The duration must be positive and within the configured maximum.");
  }
  return {
    ok: true,
    grant: {
      personId: input.personId,
      orgId: input.orgId,
      reason: input.reason,
      grantedBy: input.grantedBy,
      grantedAt: input.now,
      expiresAt: input.now + input.durationMs,
      revokedAt: null,
    },
  };
}

function isStoredShape(row: unknown): row is StoredSupportGrant {
  if (!row || typeof row !== "object") return false;
  const r = row as Record<string, unknown>;
  return (
    nonEmpty(r.personId) &&
    nonEmpty(r.orgId) &&
    typeof r.reason === "string" &&
    typeof r.grantedBy === "string" &&
    typeof r.expiresAt === "number" &&
    Number.isFinite(r.expiresAt) &&
    (r.revokedAt === null ||
      r.revokedAt === undefined ||
      (typeof r.revokedAt === "number" && Number.isFinite(r.revokedAt)))
  );
}

/**
 * Whether a person principal may act inside `targetOrgId` under a stored
 * support grant. Denied by default: only a live grant for exactly this person
 * and this organisation admits. Every outcome is reported to `onSupportAccess`.
 *
 * @callerResolver — resolves a verified caller; consumers may derive their accepted sinks from this tag.
 */
export async function resolveSupportAccess(
  principal: ActingPrincipal,
  targetOrgId: string,
  deps: SupportAccessDeps,
  opts: SupportAccessOptions,
): Promise<SupportAccessResult> {
  const door = opts.door;
  const clock = typeof deps.now === "function" ? deps.now : Date.now;
  const at = clock();
  const personId = principal && typeof principal.principalId === "string" ? principal.principalId : "";

  const emit = (event: SupportAccessEvent): void => {
    if (typeof deps.onSupportAccess !== "function") return;
    try {
      deps.onSupportAccess(event);
    } catch {
      // A failing audit sink must never change an authorization outcome.
    }
  };
  const refuse = (reason: Parameters<typeof refusal>[1], detail: string): SupportAccessResult => {
    emit({ outcome: "refused", personId, orgId: String(targetOrgId ?? ""), door, reason, at });
    return deny(reason, door, detail);
  };

  if (!principal || !nonEmpty(principal.principalId) || !nonEmpty(principal.orgId)) {
    return refuse("support-grant-invalid", "The acting principal is not resolved.");
  }
  if (principal.kind !== "person") {
    return refuse("support-grant-not-a-person", "Only a person can hold a support access grant.");
  }
  if (!nonEmpty(targetOrgId)) {
    return refuse("support-grant-invalid", "The target organisation ID is required.");
  }
  if (principal.orgId === targetOrgId) {
    return refuse(
      "support-grant-own-organisation",
      "This is the caller's own organisation; use normal membership, not support access.",
    );
  }

  let row: StoredSupportGrant | null | undefined;
  try {
    row = await deps.lookupSupportGrant(principal.principalId, targetOrgId);
  } catch (err) {
    const kind = err instanceof Error ? err.name : typeof err;
    return refuse("support-grant-lookup-failed", `The support grant lookup failed (${kind}).`);
  }
  if (row === null || row === undefined) {
    return refuse("support-grant-absent", "No support access grant exists for this organisation.");
  }
  if (!isStoredShape(row)) {
    return refuse("support-grant-invalid", "The stored support grant is not readable.");
  }
  if (row.personId !== principal.principalId || row.orgId !== targetOrgId) {
    return refuse("support-grant-mismatch", "The stored support grant is not for this person and organisation.");
  }
  if (row.revokedAt !== null && row.revokedAt !== undefined) {
    return refuse("support-grant-revoked", "The support access grant was revoked.");
  }
  if (at >= row.expiresAt) {
    return refuse("support-grant-expired", "The support access grant has expired.");
  }

  emit({
    outcome: "granted",
    personId: principal.principalId,
    orgId: targetOrgId,
    door,
    reason: row.reason,
    expiresAt: row.expiresAt,
    at,
  });
  return {
    ok: true,
    orgId: targetOrgId,
    grant: { reason: row.reason, grantedBy: row.grantedBy, expiresAt: row.expiresAt },
  };
}
