/**
 * @vantageos/cloud-identity — an organisation is its permanent ID.
 *
 * Everything here decides "which organisation" from the permanent org ID a
 * verified credential or a stored row carries. A label (the slug an org can be
 * renamed to) is display text: it never selects an org and never proves two
 * references are one org.
 *
 * Refusal, always. There is no option that compares or resolves by label: a
 * reference or credential without an org ID names no organisation, and a
 * mapping is reached only by an ID.
 *
 * The store is the consumer's: every read is an adapter it supplies, called
 * with the key as presented, byte for byte. A missing, throwing or malformed
 * adapter refuses. An adapter's error text is never surfaced.
 */

import { z } from "zod";
import { type IdentityRefusal, refusal } from "./identity-refusal.js";
import { claimedOrgId } from "./claimed-org-id.js";
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
  /** The renamable label (slug). Display text; never compared. */
  label?: string | null;
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
 * Do two references name the same organisation? Only by ID, when both carry
 * one. A label never matches, and absence is not a match: two unstamped
 * references are NOT the same organisation here.
 */
export function sameOrg(
  a: OrgRef | null | undefined,
  b: OrgRef | null | undefined,
): boolean {
  if (!a || !b) return false;
  return nonEmpty(a.id) && nonEmpty(b.id) && a.id === b.id;
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
): boolean {
  if (isUnstamped(stamp)) return true;
  return operator !== null && operator !== undefined && sameOrg(stamp, operator);
}

/**
 * Do two stamps name the same tenant: the same organisation, or both the
 * fleet's? Two IDs that differ are two tenants even under one label.
 */
export function sameTenantStamp(
  a: OrgRef | null | undefined,
  b: OrgRef | null | undefined,
  operator: OrgRef | null | undefined,
): boolean {
  if (isFleetStamp(a, operator) && isFleetStamp(b, operator)) return true;
  return sameOrg(a, b);
}

// ---------------------------------------------------------------------------
// The stored mapping row
// ---------------------------------------------------------------------------

/**
 * The consumer's organisation mapping row, as an adapter returns it. `id` is
 * the permanent org ID and may be absent while the store is being filled;
 * `label` is the slug. Extra fields are allowed and ignored.
 *
 * Both rosters are optional (since 0.24.0): `allowedOrchestrators` is the
 * legacy NAME roster, `allowedAgentIds` the roster by agent ID. A roster that
 * is present must be well formed, or the row is refused.
 */
export const orgMappingRowSchema = z.object({
  id: z.string().min(1).nullish(),
  label: z.string().min(1),
  active: z.boolean(),
  allowedOrchestrators: z.array(z.string()).optional(),
  allowedAgentIds: z.array(z.string().min(1)).optional(),
  scopes: z.array(z.string()),
  orgKind: z.string().nullish(),
  /**
   * The ID of the service account this organisation names as its own (0.27.0),
   * when the row stores one. Read only by `resolveAgentWriterFromIdentity`: a
   * service-account row its organisation does not name here is not that
   * organisation's service account, whatever subject it carries.
   */
  serviceAccountId: z.string().min(1).nullish(),
});
export type OrgMappingRow = z.input<typeof orgMappingRowSchema>;

type Lookup<A extends unknown[], R> = (
  ...args: A
) => Promise<R | null | undefined> | R | null | undefined;

/** Indexed reads of the mapping store. Only the lookups of the path taken are called. */
export type OrgMappingLookups = {
  /** The mapping row whose permanent ID is exactly the one asked for. */
  orgById?: Lookup<[orgId: string], OrgMappingRow>;
  /** The mapping row whose label is exactly the one asked for. Read only by `resolveOrgIdForLabelBackfillOnly` and `resolveProvisioningLabel`. */
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
  /** The permanent org ID: the one the credential carried and the mapping holds. */
  id: string;
  /** The org's CURRENT label. Display text. */
  label: string;
  /**
   * The mapping row's NAME roster, present when the row has one.
   *
   * @deprecated Since 0.24.0. Names are labels, not identity. Read
   * `allowedAgentIds`. Optional so a consumer can remove the field from its
   * rows; absent means the row stores no name roster.
   */
  allowedOrchestrators?: string[];
  /**
   * The mapping row's roster by agent ID, present when the row has one
   * (an empty list is returned as empty). Absent means the row stores no ID
   * roster: nothing is admitted by it.
   */
  allowedAgentIds?: string[];
  scopes: string[];
  orgKind: OrgKind | null;
};

export type ResolveOrgFromClaimOptions = {
  /** The consumer's name for the door; carried on every refusal. */
  door?: string;
};

export type ResolveOrgFromClaimResult =
  | { ok: true; org: ResolvedOrg }
  | { ok: false; refusal: IdentityRefusal };

/**
 * Resolves a VERIFIED credential's claims to the stored mapping row of its
 * organisation, or refuses. The claim's org ID selects the row; nothing the
 * request supplies does.
 *
 * A credential carrying no usable org ID is refused
 * (`no-verified-organisation`) and an ID no mapping holds is refused
 * (`org-mapping-not-found`). A label claim (a slug) is never read: it neither
 * selects a mapping nor rescues a missing ID.
 *
 * `claims` is the verified identity's own claim record, never a request field.
 */
export async function resolveOrgFromClaim(
  claims: Record<string, unknown> | null | undefined,
  lookups: OrgMappingLookups | null | undefined,
  options?: ResolveOrgFromClaimOptions,
): Promise<ResolveOrgFromClaimResult> {
  const door = options?.door ?? "resolveOrgFromClaim";
  const deny = (
    reason: Parameters<typeof refusal>[1],
    detail: string,
  ): ResolveOrgFromClaimResult => ({
    ok: false,
    refusal: refusal("RBAC_DENIED", reason, door, detail),
  });

  const record = claims && typeof claims === "object" ? claims : {};
  const orgId = claimedOrgId(record);
  if (orgId === undefined) {
    return deny("no-verified-organisation", "The credential carries no verified organisation.");
  }

  const served = (row: ParsedRow, id: string): ResolveOrgFromClaimResult => {
    if (row.active !== true) {
      return deny("organisation-not-active", "The organisation is not mapped or not active.");
    }
    return {
      ok: true,
      org: {
        id,
        label: row.label,
        ...(row.allowedOrchestrators !== undefined
          ? { allowedOrchestrators: row.allowedOrchestrators }
          : {}),
        ...(row.allowedAgentIds !== undefined ? { allowedAgentIds: row.allowedAgentIds } : {}),
        scopes: row.scopes,
        orgKind: kindOf(row.orgKind),
      },
    };
  };
  const invalid = deny("org-mapping-record-invalid", "The organisation mapping record is not well formed.");
  const unreadable = deny(
    "org-mapping-lookup-failed",
    "The organisation mapping could not be read, so none is resolved.",
  );

  const found = await call(lookups?.orgById, orgId);
  if (!found.called) return unreadable;
  if (found.row === null) {
    return deny("org-mapping-not-found", "No organisation mapping holds the credential's organisation ID.");
  }
  const parsed = orgMappingRowSchema.safeParse(found.row);
  if (!parsed.success || parsed.data.id !== orgId) return invalid;
  return served(parsed.data, orgId);
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
// resolveProvisioningLabel — the provisioning boundary (0.20.0)
// ---------------------------------------------------------------------------

export type ProvisioningLabelResult =
  /** No mapping holds this label: the organisation does not exist yet. */
  | { kind: "unmapped" }
  /** A mapping holds this label; every decision after this point is by `orgId`. */
  | { kind: "mapped"; orgId: string; active: boolean }
  /** A mapping holds this label but its permanent ID is not filled yet. */
  | { kind: "mapped-without-id"; active: boolean }
  /** No answer could be read: never treated as "unmapped". */
  | { kind: "unreadable"; reason: "no-label" | "lookup-failed" | "record-invalid" };

/**
 * The ONE place a provisioning input (an operator typing an organisation's
 * label to create or configure it) is translated to the organisation's
 * permanent ID. A label is accepted here and nowhere after: the caller decides
 * from `orgId`, and from `kind` whether the organisation already exists.
 *
 * Request paths decide their organisation from the verified credential
 * (`resolveOrgFromClaim`), never from a label. An unreadable store is its own
 * answer, never "unmapped", so a failing read can never authorise a creation.
 */
export async function resolveProvisioningLabel(
  label: string | null | undefined,
  lookups: OrgMappingLookups | null | undefined,
): Promise<ProvisioningLabelResult> {
  if (!nonEmpty(label)) return { kind: "unreadable", reason: "no-label" };
  const found = await call(lookups?.orgByLabel, label);
  if (!found.called) return { kind: "unreadable", reason: "lookup-failed" };
  if (found.row === null) return { kind: "unmapped" };
  const parsed = orgMappingRowSchema.safeParse(found.row);
  if (!parsed.success || parsed.data.label !== label) return { kind: "unreadable", reason: "record-invalid" };
  if (parsed.data.id === undefined || parsed.data.id === null) {
    return { kind: "mapped-without-id", active: parsed.data.active };
  }
  return { kind: "mapped", orgId: parsed.data.id, active: parsed.data.active };
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
