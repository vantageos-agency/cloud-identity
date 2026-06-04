/**
 * @vantageos/cloud-identity — public surface.
 *
 * Framework-agnostic identity + scope-filter primitives for VantagePeers Cloud
 * (multi-tenant MCP). Consumed by `vantage-peers-mcp` and
 * `@vantageos/vantage-crm-mcp`.
 */

export { timingSafeEqual } from "./crypto.js";
export {
  passesScopeFilter,
  scopeFilterList,
  scopeFilterGet,
  isMasterScope,
  isWildcardScope,
  type ScopeFilterable,
} from "./scope-filter.js";
export { validateMasterBearer } from "./bearer-validation.js";
export type {
  OAuthCtx,
  ScopeProfile,
  NamespacePrefix,
  FromAllowListEntry,
  ValidateMasterBearerResult,
} from "./types.js";
