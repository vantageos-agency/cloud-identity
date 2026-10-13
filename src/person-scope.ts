/**
 * Person-scope row filter: within the caller's organisation, keep only the
 * rows whose scope key belongs to the person's presented scope.
 *
 * Organisation isolation is NOT re-implemented here. `filterTargetsInPersonScope`
 * first calls `filterTargetsBelongingTo` (./principal-by-id) and returns its
 * refusal unchanged; the person scope only ever narrows the rows that filter
 * kept. A row of another organisation is dropped whatever its scope key.
 *
 * Who sees which scope keys is the CONSUMER's data. The package supplies the
 * mechanism only: the consumer's `scopeOf(principal)` returns the scope the
 * person presents, and `rowScopeKeys(row)` returns the key(s) a row carries
 * (for example the ID of the portfolio a record belongs to).
 *
 * A right is PRESENTED, never inferred from an absence:
 *
 *   - `scopeOf` returning `null` / `undefined` is no scope: refused
 *     (`person-scope-absent`), never "everything" and never an empty success.
 *   - `{ kind: "keys" }` with an empty set is refused (`person-scope-empty`):
 *     an empty grant is not a grant.
 *   - `{ kind: "all" }` is an explicit grant (for example a management role)
 *     and must name it in a non-empty `grantedBy`; an empty or missing
 *     reason is refused (`person-scope-grant-unreasoned`).
 *   - Any other value (an unknown `kind`, a `keys` that is not a set) is
 *     refused (`person-scope-malformed`), never read as a broader scope.
 *   - `scopeOf` or `rowScopeKeys` throwing is refused
 *     (`person-scope-lookup-failed`); the refusal names the error KIND
 *     (its constructor name) and never its message.
 *
 * Every principal the organisation filter admits reaches this step, whatever
 * its kind. A `"fleet"` or `"service"` principal holds no implicit `"all"`:
 * it needs a presented scope like a person, and `fleetCrossOrg` widens only
 * the organisations, never the scope keys.
 *
 * Keys are compared as exact strings: no trimming, no case folding, no
 * normalisation. A scope key is an ID (identity by ID); a name or a label is
 * never a key, and folding would let two distinct IDs that differ only by case
 * stand for each other.
 *
 * A row with no scope key (`undefined`, `null`, `""`, an empty array) cannot be
 * proven in scope and is dropped, under a key set and under an `"all"` grant
 * alike. An empty string is never a key, even if the set contains one. A row
 * key of any other form (a number, an object, an array holding a non-string)
 * refuses the whole call (`person-scope-malformed`): a key the filter cannot
 * read is never a silent drop.
 *
 * A row is kept exactly when it passes the organisation filter AND at least
 * one of its keys is in the set (or the scope is a reasoned `"all"`). Kept rows
 * keep the input order.
 */

import { type IdentityRefusal, refusal } from "./identity-refusal.js";
import {
  type ActingPrincipal,
  type AssertTargetOptions,
  filterTargetsBelongingTo,
  type FilterTargetsResult,
  type OrgKindLookups,
  type TargetIds,
} from "./principal-by-id.js";

/** The scope a person presents. A discriminated union; nothing else is a scope. */
export type PersonScope =
  | { kind: "keys"; keys: ReadonlySet<string> }
  | { kind: "all"; grantedBy: string };

export type PersonScopeDeps<T> = OrgKindLookups & {
  /** The consumer's read of the principal's presented scope. */
  scopeOf: (
    principal: ActingPrincipal,
  ) => Promise<PersonScope | null | undefined> | PersonScope | null | undefined;
  /** The scope key(s) a row carries. No key: the row is dropped. */
  rowScopeKeys: (row: T) => string | readonly string[] | null | undefined;
};

export type PersonScopeOptions = AssertTargetOptions;

export type PersonScopeResult<T> = FilterTargetsResult<T>;

type Refused = { ok: false; refusal: IdentityRefusal };

function denied(reason: Parameters<typeof refusal>[1], door: string, detail: string): Refused {
  return { ok: false, refusal: refusal("RBAC_DENIED", reason, door, detail) };
}

/** The error's kind (its constructor name), never its message. */
function errorKind(err: unknown): string {
  const name = err instanceof Error ? err.name : typeof err;
  return /^[A-Za-z_$][\w$]{0,63}$/.test(name) ? name : "unknown";
}

function isStringSet(value: unknown): value is ReadonlySet<string> {
  return (
    value !== null &&
    typeof value === "object" &&
    typeof (value as ReadonlySet<string>).has === "function" &&
    typeof (value as ReadonlySet<string>).size === "number"
  );
}

type ReadScope = { ok: true; keys: ReadonlySet<string> | "all" } | Refused;

function readScope(scope: unknown, door: string): ReadScope {
  if (scope === null || scope === undefined) {
    return denied("person-scope-absent", door, "No scope is presented for this principal, so no row is in scope.");
  }
  if (typeof scope !== "object") {
    return denied("person-scope-malformed", door, "The presented scope is not a known scope form.");
  }
  const s = scope as { kind?: unknown; keys?: unknown; grantedBy?: unknown };
  switch (s.kind) {
    case "keys":
      if (!isStringSet(s.keys)) {
        return denied("person-scope-malformed", door, "The presented key scope carries no key set.");
      }
      if (s.keys.size === 0) {
        return denied("person-scope-empty", door, "The presented key set is empty; an empty grant is not a grant.");
      }
      return { ok: true, keys: s.keys };
    case "all":
      if (typeof s.grantedBy !== "string" || s.grantedBy.trim().length === 0) {
        return denied(
          "person-scope-grant-unreasoned",
          door,
          "A scope over every key must name the right that grants it.",
        );
      }
      return { ok: true, keys: "all" };
    default:
      return denied("person-scope-malformed", door, "The presented scope is not a known scope form.");
  }
}

type RowKeys = { ok: true; keys: readonly string[] } | Refused;

function readRowKeys(raw: unknown, door: string): RowKeys {
  if (raw === null || raw === undefined) return { ok: true, keys: [] };
  if (typeof raw === "string") return { ok: true, keys: raw.length > 0 ? [raw] : [] };
  if (Array.isArray(raw)) {
    if (!raw.every((k) => typeof k === "string")) {
      return denied("person-scope-malformed", door, "A row carries a scope key that is not a string.");
    }
    return { ok: true, keys: (raw as string[]).filter((k) => k.length > 0) };
  }
  return denied("person-scope-malformed", door, "A row carries a scope key that is not a string.");
}

/**
 * Keeps the rows of the principal's organisation (via `filterTargetsBelongingTo`)
 * whose scope key is in the principal's presented scope. Returns
 * `{ ok: true, rows }` or a typed `RBAC_DENIED` refusal naming the door
 * (default `"filterTargetsInPersonScope"`). `opts` are those of
 * `filterTargetsBelongingTo` and are passed to it unchanged, door included.
 */
export async function filterTargetsInPersonScope<T extends TargetIds>(
  principal: ActingPrincipal | null | undefined,
  rows: readonly T[],
  deps: PersonScopeDeps<T>,
  opts: PersonScopeOptions = {},
): Promise<PersonScopeResult<T>> {
  const door = opts.door ?? "filterTargetsInPersonScope";

  const inOrg = await filterTargetsBelongingTo(principal, rows, deps, { ...opts, door });
  if (!inOrg.ok) return inOrg;
  // filterTargetsBelongingTo admitted the principal, so it is resolved here.
  const who = principal as ActingPrincipal;

  let presented: unknown;
  try {
    presented = await deps.scopeOf(who);
  } catch (err) {
    return denied(
      "person-scope-lookup-failed",
      door,
      `The principal's scope could not be read (${errorKind(err)}), so none is presented.`,
    );
  }
  const scope = readScope(presented, door);
  if (!scope.ok) return scope;

  const kept: T[] = [];
  for (const row of inOrg.rows) {
    let raw: unknown;
    try {
      raw = deps.rowScopeKeys(row);
    } catch (err) {
      return denied(
        "person-scope-lookup-failed",
        door,
        `A row's scope key could not be read (${errorKind(err)}).`,
      );
    }
    const rowKeys = readRowKeys(raw, door);
    if (!rowKeys.ok) return rowKeys;
    if (rowKeys.keys.length === 0) continue;
    if (scope.keys === "all" || rowKeys.keys.some((k) => (scope.keys as ReadonlySet<string>).has(k))) {
      kept.push(row);
    }
  }
  return { ok: true, rows: kept };
}
