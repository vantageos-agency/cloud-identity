/**
 * Scope-aware row filter.
 *
 * The behaviour was preserved verbatim from an earlier in-tree
 * implementation; the only change was replacing a framework-specific context
 * type with the framework-agnostic `OAuthCtx` from `./types`.
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
 * Core predicate. Returns true when the row is visible to the caller.
 *
 *   - Master scope (isMasterScope === true)            → true (wildcard)
 *   - row.createdBy ∈ oauthCtx.fromAllowList           → true
 *   - row.namespace === prefix OR startsWith prefix+'/'
 *     for any prefix ∈ oauthCtx.namespaceReadPrefixes  → true
 *   - otherwise                                        → false
 *
 * `oauthCtx` is mandatory (see module-level contract note above): an omitted
 * argument throws instead of silently granting wildcard access. Callers that
 * need the old legacy-bearer wildcard behaviour must pass `LEGACY_WILDCARD_CTX`
 * explicitly.
 *
 * Substring matches that don't fall on a '/' boundary are explicitly rejected
 * (e.g. namespace="orchestrator/alphabet" does NOT match prefix
 * "orchestrator/alpha"). This avoids the classic prefix-isolation bypass.
 */
export function passesScopeFilter(
  oauthCtx: OAuthCtx,
  row: ScopeFilterable,
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
  return false;
}

/**
 * Filter a list of rows (post-query). Used by list_* tools.
 */
export function scopeFilterList<T extends ScopeFilterable>(
  oauthCtx: OAuthCtx,
  rows: T[],
): T[] {
  assertOauthCtx(oauthCtx);
  return rows.filter((r) => passesScopeFilter(oauthCtx, r));
}

/**
 * Assert a single row passes (get_* tools). Returns the row when allowed, null
 * otherwise — callers translate null to a 404-equivalent "not found" MCP error
 * to avoid leaking the difference between "absent" and "filtered out".
 */
export function scopeFilterGet<T extends ScopeFilterable>(
  oauthCtx: OAuthCtx,
  row: T | null | undefined,
): T | null {
  assertOauthCtx(oauthCtx);
  if (row == null) return null;
  return passesScopeFilter(oauthCtx, row) ? row : null;
}

/**
 * Helper for callers that want a single "is master / legacy" predicate.
 */
export function isWildcardScope(ctx: OAuthCtx): boolean {
  assertOauthCtx(ctx);
  return isMasterScope(ctx);
}
