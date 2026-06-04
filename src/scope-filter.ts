/**
 * Sprint S3.1 B2 — scope-aware filter helpers for VP MCP tools.
 *
 * Ported from `vantage-memory/mcp-server/src/scope-filter.ts`. Behaviour is
 * preserved verbatim; only the type dependency on the in-tree `OAuthContext`
 * is replaced by the framework-agnostic `OAuthCtx` from `./types`.
 *
 * Doctrine references:
 *   - decisions/doctrine-scope-aware-filter-2026-05-26.md (D3 base)
 *   - memory j579y6f31g7xzgtgdnpgetdmjx87ztyj (D9-D14 extension)
 *
 * Contract:
 *   - Master scope (scope === "master" OR fromAllowList includes "*") = wildcard pass.
 *   - Legacy bearer (oauthCtx === undefined) = wildcard pass (treated as master-
 *     equivalent for backward-compatibility with mcpTenants Pi/Tau/Phi paths).
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
export function isMasterScope(ctx: OAuthCtx | undefined): boolean {
  if (!ctx) return false;
  if (ctx.scope === "master") return true;
  return ctx.fromAllowList.includes("*");
}

/**
 * Core predicate. Returns true when the row is visible to the caller.
 *
 *   - Master scope (isMasterScope === true)            → true (wildcard)
 *   - Legacy bearer (oauthCtx === undefined)           → true (back-compat)
 *   - row.createdBy ∈ oauthCtx.fromAllowList           → true
 *   - row.namespace === prefix OR startsWith prefix+'/'
 *     for any prefix ∈ oauthCtx.namespaceReadPrefixes  → true
 *   - otherwise                                        → false
 *
 * Substring matches that don't fall on a '/' boundary are explicitly rejected
 * (e.g. namespace="orchestrator/alphabet" does NOT match prefix
 * "orchestrator/alpha"). This avoids the classic prefix-isolation bypass.
 */
export function passesScopeFilter(
  oauthCtx: OAuthCtx | undefined,
  row: ScopeFilterable,
): boolean {
  if (!oauthCtx) return true;
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
  oauthCtx: OAuthCtx | undefined,
  rows: T[],
): T[] {
  return rows.filter((r) => passesScopeFilter(oauthCtx, r));
}

/**
 * Assert a single row passes (get_* tools). Returns the row when allowed, null
 * otherwise — callers translate null to a 404-equivalent "not found" MCP error
 * to avoid leaking the difference between "absent" and "filtered out".
 */
export function scopeFilterGet<T extends ScopeFilterable>(
  oauthCtx: OAuthCtx | undefined,
  row: T | null | undefined,
): T | null {
  if (row == null) return null;
  return passesScopeFilter(oauthCtx, row) ? row : null;
}

/**
 * Helper for callers that want a single "is master / legacy" predicate.
 * Mirrors the legacy-bearer-passes-through convention.
 */
export function isWildcardScope(ctx: OAuthCtx | undefined): boolean {
  if (!ctx) return true;
  return isMasterScope(ctx);
}
