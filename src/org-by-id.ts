/**
 * @vantageos/cloud-identity — an organisation is its permanent ID.
 *
 * Everything here decides "which organisation" from the permanent org ID a
 * verified credential or a stored row carries. A label (the slug an org can be
 * renamed to) is display text: it never selects an org and never proves two
 * references are one org.
 *
 * Refusal by default. The ONE exception is a transitional, opt-in fallback
 * (`labelFallback: true`) for a store that has not filled every ID yet: while
 * either side of a comparison has no ID, labels are compared; two IDs that
 * differ are two orgs whatever the labels say, and an ID a mapping already
 * holds is never overridden by a label. Turn the option off, and the fallback
 * is gone, the day the store reports no ID missing.
 *
 * The store is the consumer's: every read is an adapter it supplies, called
 * with the key as presented, byte for byte. A missing, throwing or malformed
 * adapter refuses. An adapter's error text is never surfaced.
 */

import { z } from "zod";
import { type IdentityRefusal, refusal } from "./identity-refusal.js";
import { resolveTenantIdOrAbsent } from "./org-guard.js";
import type { OrgKind } from "./principal-by-id.js";

// ---------------------------------------------------------------------------
// The organisation reference
// ---------------------------------------------------------------------------

/**
 * An organisation as a row or a caller names it: the permanent ID and the
 * label. Either may be absent. Both absent is "unstamped", which names no
 * organisation.
 */
export type OrgRef = {
  /** The permanent org ID. */
  id?: string | null;
  /** The renamable label (slug). Compared only under `labelFallback`. */
  label?: string | null;
};

export type OrgKeyOptions = {
  /**
   * Transitional. Compare labels while either side has no ID. Default `false`:
   * IDs only.
   */
  labelFallback?: boolean;
};

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function isUnstamped(ref: OrgRef | null | undefined): boolean {
  return (
    ref === null ||
    ref === undefined ||
    ((ref.id === null || ref.id === undefined) &&
      (ref.label === null || ref.label === undefined))
  );
}

// ---------------------------------------------------------------------------
// sameOrg / isFleetStamp / sameTenantStamp
// ---------------------------------------------------------------------------

/**
 * Do two references name the same organisation? By ID when both carry one.
 * Under `labelFallback`, by label while either side has no ID. Absence is not
 * a match: two unstamped references are NOT the same organisation here.
 */
export function sameOrg(
  a: OrgRef | null | undefined,
  b: OrgRef | null | undefined,
  options?: OrgKeyOptions,
): boolean {
  if (!a || !b) return false;
  if (nonEmpty(a.id) && nonEmpty(b.id)) return a.id === b.id;
  if (options?.labelFallback !== true) return false;
  return nonEmpty(a.label) && a.label === b.label;
}

/**
 * Is a stamp the fleet's: unstamped, or the operator organisation's? The
 * operator is read from stored data by the caller (see `findOperatorOrg`);
 * pass `undefined` when there is not exactly one, and only an unstamped stamp
 * is the fleet's. An empty-string stamp is neither unstamped nor the operator.
 */
export function isFleetStamp(
  stamp: OrgRef | null | undefined,
  operator: OrgRef | null | undefined,
  options?: OrgKeyOptions,
): boolean {
  if (isUnstamped(stamp)) return true;
  return operator !== null && operator !== undefined && sameOrg(stamp, operator, options);
}

/**
 * Do two stamps name the same tenant: the same organisation, or both the
 * fleet's? Two IDs that differ are two tenants even under one label.
 */
export function sameTenantStamp(
  a: OrgRef | null | undefined,
  b: OrgRef | null | undefined,
  operator: OrgRef | null | undefined,
  options?: OrgKeyOptions,
): boolean {
  if (isFleetStamp(a, operator, options) && isFleetStamp(b, operator, options)) return true;
  return sameOrg(a, b, options);
}

// ---------------------------------------------------------------------------
// The stored mapping row
// ---------------------------------------------------------------------------

/**
 * The consumer's organisation mapping row, as an adapter returns it. `id` is
 * the permanent org ID and may be absent while the store is being filled;
 * `label` is the slug. Extra fields are allowed and ignored.
 */
export const orgMappingRowSchema = z.object({
  id: z.string().min(1).nullish(),
  label: z.string().min(1),
  active: z.boolean(),
  allowedOrchestrators: z.array(z.string()),
  scopes: z.array(z.string()),
  orgKind: z.string().nullish(),
});
export type OrgMappingRow = z.input<typeof orgMappingRowSchema>;

type Lookup<A extends unknown[], R> = (
  ...args: A
) => Promise<R | null | undefined> | R | null | undefined;

/** Indexed reads of the mapping store. Only the lookups of the path taken are called. */
export type OrgMappingLookups = {
  /** The mapping row whose permanent ID is exactly the one asked for. */
  orgById?: Lookup<[orgId: string], OrgMappingRow>;
  /** The mapping row whose label is exactly the one asked for. */
  orgByLabel?: Lookup<[label: string], OrgMappingRow>;
};

function kindOf(raw: string | null | undefined): OrgKind | null {
  return raw === "operator" || raw === "client" ? raw : null;
}

type ParsedRow = z.output<typeof orgMappingRowSchema>;
type Called<T> = { called: true; row: T | null } | { called: false };

/** Calls an adapter; a missing or throwing one is `called: false`. */
async function call<A extends unknown[], R>(
  lookup: Lookup<A, R> | undefined,
  ...args: A
): Promise<Called<R>> {
  if (typeof lookup !== "function") return { called: false };
  try {
    const raw = await lookup(...args);
    return { called: true, row: raw ?? null };
  } catch {
    return { called: false };
  }
}

// ---------------------------------------------------------------------------
// resolveOrgFromClaim
// ---------------------------------------------------------------------------

/** The org a credential resolves to, with the roster and scopes of its mapping row. */
export type ResolvedOrg = {
  /** The permanent org ID; absent only for a label-resolved mapping with no ID yet. */
  id: string | undefined;
  /** The org's CURRENT label. Display text. */
  label: string;
  allowedOrchestrators: string[];
  scopes: string[];
  orgKind: OrgKind | null;
  /** How the mapping was reached: by the credential's ID, or by the fallback label. */
  source: "id" | "label";
};

export type ResolveOrgFromClaimOptions = OrgKeyOptions & {
  /** The consumer's name for the door; carried on every refusal. */
  door?: string;
};

export type ResolveOrgFromClaimResult =
  | { ok: true; org: ResolvedOrg }
  | { ok: false; refusal: IdentityRefusal };

const CLERK_ORG_ID_SHAPE = /^org_[A-Za-z0-9]+$/;
const ID_CLAIMS = ["org_id", "organizationId", "orgId"] as const;
const LABEL_CLAIMS = ["organizationSlug", "org_slug", "organizationId", "org_id"] as const;

/** The first claim that is shaped like a Clerk org ID and resolves as a tenant. */
function claimedOrgId(claims: Record<string, unknown>): string | undefined {
  for (const name of ID_CLAIMS) {
    const value = claims[name];
    if (typeof value !== "string" || !CLERK_ORG_ID_SHAPE.test(value)) continue;
    const resolved = resolveTenantIdOrAbsent({ kind: "session", identity: { orgId: value } });
    if (resolved.present) return resolved.tenantId;
  }
  return undefined;
}

/** The first non-empty string label claim, slug spellings before legacy id spellings. */
function claimedLabel(claims: Record<string, unknown>): string | undefined {
  for (const name of LABEL_CLAIMS) {
    const value = claims[name];
    if (nonEmpty(value)) return value;
  }
  return undefined;
}

/**
 * Resolves a VERIFIED credential's claims to the stored mapping row of its
 * organisation, or refuses. The claim's org ID selects the row; nothing the
 * request supplies does.
 *
 * With `labelFallback` off (the default) a credential carrying no usable org ID
 * is refused (`no-verified-organisation`) and an ID no mapping holds is refused
 * (`org-mapping-not-found`). With it on, a credential with no ID, or one whose
 * ID no mapping holds yet, may be served by the mapping its label names, but
 * only while that mapping has no ID filled; a filled ID that is not the
 * credential's is refused (`org-id-contradicts-label`).
 *
 * `claims` is the verified identity's own claim record, never a request field.
 */
export async function resolveOrgFromClaim(
  claims: Record<string, unknown> | null | undefined,
  lookups: OrgMappingLookups | null | undefined,
  options?: ResolveOrgFromClaimOptions,
): Promise<ResolveOrgFromClaimResult> {
  const door = options?.door ?? "resolveOrgFromClaim";
  const fallback = options?.labelFallback === true;
  const deny = (
    reason: Parameters<typeof refusal>[1],
    detail: string,
  ): ResolveOrgFromClaimResult => ({
    ok: false,
    refusal: refusal("RBAC_DENIED", reason, door, detail),
  });

  const record = claims && typeof claims === "object" ? claims : {};
  const orgId = claimedOrgId(record);
  const label = fallback ? claimedLabel(record) : undefined;
  if (orgId === undefined && label === undefined) {
    return deny("no-verified-organisation", "The credential carries no verified organisation.");
  }

  const served = (row: ParsedRow, source: "id" | "label"): ResolveOrgFromClaimResult => {
    if (row.active !== true) {
      return deny("organisation-not-active", "The organisation is not mapped or not active.");
    }
    return {
      ok: true,
      org: {
        id: row.id ?? undefined,
        label: row.label,
        allowedOrchestrators: row.allowedOrchestrators,
        scopes: row.scopes,
        orgKind: kindOf(row.orgKind),
        source,
      },
    };
  };
  const invalid = deny("org-mapping-record-invalid", "The organisation mapping record is not well formed.");
  const unreadable = deny(
    "org-mapping-lookup-failed",
    "The organisation mapping could not be read, so none is resolved.",
  );

  if (orgId !== undefined) {
    const found = await call(lookups?.orgById, orgId);
    if (!found.called) return unreadable;
    if (found.row !== null) {
      const parsed = orgMappingRowSchema.safeParse(found.row);
      if (!parsed.success || parsed.data.id !== orgId) return invalid;
      return served(parsed.data, "id");
    }
    if (!fallback) {
      return deny("org-mapping-not-found", "No organisation mapping holds the credential's organisation ID.");
    }
  }

  // Transitional label path: reached only under `labelFallback`.
  if (label === undefined) {
    return deny("no-verified-organisation", "The credential carries no verified organisation.");
  }
  const byLabel = await call(lookups?.orgByLabel, label);
  if (!byLabel.called) return unreadable;
  if (byLabel.row === null) {
    return deny("org-mapping-not-found", "No organisation mapping holds this organisation label.");
  }
  const parsed = orgMappingRowSchema.safeParse(byLabel.row);
  if (!parsed.success || parsed.data.label !== label) return invalid;
  if (orgId !== undefined && parsed.data.id !== undefined && parsed.data.id !== null) {
    return deny(
      "org-id-contradicts-label",
      "The credential's organisation ID is not the organisation this label names.",
    );
  }
  return served(parsed.data, "label");
}

// ---------------------------------------------------------------------------
// resolveOrgIdForLabelBackfillOnly — one-off backfill path only
// ---------------------------------------------------------------------------

export type OrgIdAbsenceReason =
  | "no-label"
  | "lookup-failed"
  | "not-mapped"
  | "record-invalid"
  | "id-not-filled";

/** The typed absence of an ID. A non-empty object: never mistaken for an ID or for nothing. */
export type OrgIdAbsence = { code: "ORG_ID_ABSENT"; reason: OrgIdAbsenceReason };

export type OrgIdResolution =
  | { present: true; orgId: string }
  | { present: false; absence: OrgIdAbsence };

/**
 * BACKFILL ONLY. Derives the permanent org ID of the organisation a label
 * names, from the consumer's stored mapping, so a one-off migration can stamp
 * rows written before IDs existed.
 *
 * MUST NEVER be called on a request path. A request decides its organisation
 * from the verified credential's `org_id` claim (`resolveOrgFromClaim`); a miss
 * there is a refusal, never a retry by label. A label is renamable display
 * text: resolving an org from it on a request is the name-to-ID defect this
 * module exists to close, and the export name carries that restriction so a
 * reviewer sees it at every call site.
 *
 * A derivation and not an authorization: it answers for an inactive mapping
 * too. It never invents an ID: a mapping with none filled is `id-not-filled`.
 */
export async function resolveOrgIdForLabelBackfillOnly(
  label: string | null | undefined,
  lookups: OrgMappingLookups | null | undefined,
): Promise<OrgIdResolution> {
  const absent = (reason: OrgIdAbsenceReason): OrgIdResolution => ({
    present: false,
    absence: { code: "ORG_ID_ABSENT", reason },
  });
  if (!nonEmpty(label)) return absent("no-label");
  const found = await call(lookups?.orgByLabel, label);
  if (!found.called) return absent("lookup-failed");
  if (found.row === null) return absent("not-mapped");
  const parsed = orgMappingRowSchema.safeParse(found.row);
  if (!parsed.success || parsed.data.label !== label) return absent("record-invalid");
  if (parsed.data.id === undefined || parsed.data.id === null) return absent("id-not-filled");
  return { present: true, orgId: parsed.data.id };
}

// ---------------------------------------------------------------------------
// findOperatorOrg
// ---------------------------------------------------------------------------

export type OperatorOrgLookups = {
  /**
   * The ACTIVE organisation mapping rows, at most `limit` of them. Called with
   * `cap + 1` so a filled read is recognisable as over the cap.
   */
  activeOrganisations?: (limit: number) => unknown;
};

export type FindOperatorOrgOptions = {
  /** Read bound. Default 1000. A read over the cap is never decided from. */
  cap?: number;
};

export type OperatorOrgResult =
  | { kind: "one"; org: { id: string | undefined; label: string } }
  | { kind: "none" }
  | { kind: "many"; count: number }
  | { kind: "overCap" }
  | { kind: "unreadable" };

const DEFAULT_OPERATOR_READ_CAP = 1000;

/**
 * Finds the operator organisation (the fleet) from stored mapping rows: the
 * single ACTIVE row whose kind is exactly `"operator"`. None, several, an
 * over-cap read, an unreadable store and a malformed row are each a typed
 * non-answer, so the caller can only treat the fleet as "no single operator"
 * (fail closed) and never widen from a guess.
 */
export async function findOperatorOrg(
  lookups: OperatorOrgLookups | null | undefined,
  options?: FindOperatorOrgOptions,
): Promise<OperatorOrgResult> {
  const cap = options?.cap ?? DEFAULT_OPERATOR_READ_CAP;
  const read = lookups?.activeOrganisations;
  if (typeof read !== "function") return { kind: "unreadable" };
  let raw: unknown;
  try {
    raw = await read(cap + 1);
  } catch {
    return { kind: "unreadable" };
  }
  if (!Array.isArray(raw)) return { kind: "unreadable" };
  if (raw.length > cap) return { kind: "overCap" };
  const operators: ParsedRow[] = [];
  for (const item of raw) {
    const parsed = orgMappingRowSchema.safeParse(item);
    if (!parsed.success) return { kind: "unreadable" };
    if (parsed.data.active === true && parsed.data.orgKind === "operator") {
      operators.push(parsed.data);
    }
  }
  if (operators.length === 0) return { kind: "none" };
  if (operators.length > 1) return { kind: "many", count: operators.length };
  const [only] = operators;
  return { kind: "one", org: { id: only.id ?? undefined, label: only.label } };
}
