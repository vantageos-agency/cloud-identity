/**
 * Scope-aware row filter.
 *
 * The behaviour was preserved verbatim from an earlier in-tree
 * implementation; the only change was replacing a framework-specific context
 * type with the framework-agnostic `OAuthCtx` from `./types`.
 *
 * Contract (0.5.0 — additive, widening only, vs. 0.4.0):
 *   - Every exported predicate/filter now accepts an OPTIONAL `grantFields`
 *     parameter: `readonly string[]`, defaulting to `[]`. Each entry names a
 *     property on the row that the CALLER declares as a per-row grant (e.g.
 *     "agents", "pilot", "fulfilledBy"). The package never hardcodes which
 *     fields are grants for which table — that declaration is data supplied
 *     by the caller at the call site, not business knowledge baked into this
 *     shared module (no-hardcoded-business-knowledge).
 *   - A row passes for a non-master caller if createdBy/namespace already
 *     passed (0.4.0 behaviour, unchanged) OR if ANY declared grant field's
 *     value names an identity in `oauthCtx.fromAllowList` — the field may be
 *     a single string (e.g. "pilot") or a string[] (e.g. "agents"): a string
 *     value matches by equality, an array value matches if any element is in
 *     `fromAllowList`.
 *   - `grantFields` defaulting to `[]` means a caller that declares NO grants
 *     gets EXACTLY the 0.4.0 behaviour, byte-for-byte — this is a pure
 *     widening, no existing caller's behaviour changes without an explicit
 *     opt-in declaration at its own call site.
 *   - This closes the OTHER pole of the fail-closed defect: 0.3.0/0.4.0
 *     closed "a right granted by ABSENCE" (missing oauthCtx silently passing
 *     everything); this closes "a right REFUSED by absence" — a grant that
 *     IS present on the row (a named agent, pilot, or fulfiller) but that the
 *     filter was structurally blind to because it only ever consulted
 *     createdBy/namespace.
 *
 * Contract (0.3.0 — BREAKING vs. 0.2.0):
 *   - `oauthCtx` is now MANDATORY. A right is never granted by absence: the
 *     0.2.0 behaviour of `oauthCtx === undefined` silently passing everything
 *     (as if the caller were master-scoped) was the exact defect class this
 *     release closes. Every exported function below now requires `OAuthCtx`
 *     at the type level — an omitted argument breaks the caller's build,
 *     it never falls through to a more permissive runtime path.
 *   - Callers that genuinely need the old legacy-bearer wildcard behaviour
 *     MUST import and pass `LEGACY_WILDCARD_CTX` explicitly — the compat
 *     path is requested by name, never inferred from a missing argument.
 *   - As defense-in-depth against callers that bypass the type system
 *     (untyped JS, `as any`), every function also throws at runtime if
 *     `oauthCtx` is nullish, instead of silently granting access.
 *   - Master scope (scope === "master" OR fromAllowList includes "*") = wildcard pass.
 *   - Non-master scope = row passes iff:
 *       row.createdBy ∈ oauthCtx.fromAllowList
 *       OR
 *       row.namespace startsWith one of oauthCtx.namespaceReadPrefixes
 *           (prefix matched as exact-equal OR followed by '/' boundary)
 *   - Row missing BOTH `createdBy` and `namespace` = denied for non-master.
 *
 * NOTE: this module is intentionally framework-agnostic — no McpServer / Hono
 * imports — to keep the helpers trivially unit-testable.
 */

import type { OAuthCtx } from "./types.js";

/**
 * Explicit legacy-compat sentinel. Passing this constant reproduces the
 * pre-0.3.0 "no oauthCtx" wildcard behaviour — but the caller must import
 * and pass it BY NAME. It is never inferred from an omitted argument.
 */
export const LEGACY_WILDCARD_CTX: OAuthCtx = {
  scope: "master",
  fromAllowList: ["*"],
  namespaceReadPrefixes: [],
  namespaceWritePrefixes: [],
};

function assertOauthCtx(oauthCtx: OAuthCtx): asserts oauthCtx is OAuthCtx {
  if (oauthCtx == null) {
    throw new TypeError(
      "oauthCtx is required — pass an explicit OAuthCtx, or LEGACY_WILDCARD_CTX " +
        "if you deliberately want the pre-0.3.0 legacy-bearer wildcard behaviour.",
    );
  }
}

/**
 * Row shape accepted by the scope filter. All fields optional because real
 * Convex documents from list_peers / list_messages / etc. don't all carry both.
 */
export type ScopeFilterable = {
  createdBy?: string;
  namespace?: string;
};

/**
 * Returns true when the scope profile grants full, wildcard access.
 * Mirrors `isMasterScope` from the source module: `scope === "master"` OR
 * `fromAllowList` contains the `"*"` sentinel.
 */
export function isMasterScope(ctx: OAuthCtx): boolean {
  assertOauthCtx(ctx);
  if (ctx.scope === "master") return true;
  return ctx.fromAllowList.includes("*");
}

/**
 * Names of row properties the CALLER declares as per-row grants. Each named
 * property's runtime value must be a `string` (single identity) or
 * `string[]` (multiple identities) to be consulted — any other runtime shape
 * is silently skipped (not a match), never thrown, since these are duck-typed
 * against arbitrary Convex documents.
 *
 * This is DATA supplied by the call site, never a list hardcoded inside this
 * package: the package does not and must not know that "agents" means
 * missions or "fulfilledBy" means mandates.
 */
export type GrantFieldDeclaration = readonly string[];

const NO_GRANT_FIELDS: GrantFieldDeclaration = [];

function grantFieldMatches(value: unknown, fromAllowList: string[]): boolean {
  if (typeof value === "string") return fromAllowList.includes(value);
  if (Array.isArray(value)) {
    return value.some(
      (entry) => typeof entry === "string" && fromAllowList.includes(entry),
    );
  }
  return false;
}

/**
 * Core predicate. Returns true when the row is visible to the caller.
 *
 *   - Master scope (isMasterScope === true)            → true (wildcard)
 *   - row.createdBy ∈ oauthCtx.fromAllowList           → true
 *   - row.namespace === prefix OR startsWith prefix+'/'
 *     for any prefix ∈ oauthCtx.namespaceReadPrefixes  → true
 *   - row[grantField] (for any declared grantField) names an identity in
 *     oauthCtx.fromAllowList, where the field is a string (equality) or a
 *     string[] (any-element membership)                → true
 *   - otherwise                                        → false
 *
 * `oauthCtx` is mandatory (see module-level contract note above): an omitted
 * argument throws instead of silently granting wildcard access. Callers that
 * need the old legacy-bearer wildcard behaviour must pass `LEGACY_WILDCARD_CTX`
 * explicitly.
 *
 * `grantFields` (0.5.0, optional, defaults to `[]`) lets a caller widen the
 * predicate for its own table without this package hardcoding which fields
 * are grants — see the module-level 0.5.0 contract note above. Omitting it
 * (or passing `[]`) reproduces 0.4.0 behaviour exactly.
 *
 * Substring matches that don't fall on a '/' boundary are explicitly rejected
 * (e.g. namespace="orchestrator/alphabet" does NOT match prefix
 * "orchestrator/alpha"). This avoids the classic prefix-isolation bypass.
 */
export function passesScopeFilter<T extends ScopeFilterable>(
  oauthCtx: OAuthCtx,
  row: T,
  grantFields: GrantFieldDeclaration = NO_GRANT_FIELDS,
): boolean {
  assertOauthCtx(oauthCtx);
  if (isMasterScope(oauthCtx)) return true;
  const { createdBy, namespace } = row;
  if (createdBy && oauthCtx.fromAllowList.includes(createdBy)) return true;
  if (namespace) {
    for (const p of oauthCtx.namespaceReadPrefixes) {
      if (namespace === p) return true;
      if (namespace.startsWith(`${p}/`)) return true;
    }
  }
  for (const field of grantFields) {
    const value = (row as unknown as Record<string, unknown>)[field];
    if (grantFieldMatches(value, oauthCtx.fromAllowList)) return true;
  }
  return false;
}

/**
 * Filter a list of rows (post-query). Used by list_* tools.
 *
 * `grantFields` — see `passesScopeFilter`. Defaults to `[]` (0.4.0-identical
 * behaviour).
 */
export function scopeFilterList<T extends ScopeFilterable>(
  oauthCtx: OAuthCtx,
  rows: T[],
  grantFields: GrantFieldDeclaration = NO_GRANT_FIELDS,
): T[] {
  assertOauthCtx(oauthCtx);
  return rows.filter((r) => passesScopeFilter(oauthCtx, r, grantFields));
}

/**
 * Assert a single row passes (get_* tools). Returns the row when allowed, null
 * otherwise — callers translate null to a 404-equivalent "not found" MCP error
 * to avoid leaking the difference between "absent" and "filtered out".
 *
 * `grantFields` — see `passesScopeFilter`. Defaults to `[]` (0.4.0-identical
 * behaviour).
 */
export function scopeFilterGet<T extends ScopeFilterable>(
  oauthCtx: OAuthCtx,
  row: T | null | undefined,
  grantFields: GrantFieldDeclaration = NO_GRANT_FIELDS,
): T | null {
  assertOauthCtx(oauthCtx);
  if (row == null) return null;
  return passesScopeFilter(oauthCtx, row, grantFields) ? row : null;
}

/**
 * Helper for callers that want a single "is master / legacy" predicate.
 */
export function isWildcardScope(ctx: OAuthCtx): boolean {
  assertOauthCtx(ctx);
  return isMasterScope(ctx);
}
