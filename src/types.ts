/**
 * Public type surface for @vantageos/cloud-identity.
 *
 * Framework-agnostic — no Hono, no Convex, no MCP SDK imports.
 */

/**
 * Scope profile name. Master = wildcard. Tenant = scoped via fromAllowList
 * and namespace prefixes. Extensible string for future profiles.
 */
export type ScopeProfile = "master" | "tenant" | (string & {});

/**
 * Namespace prefix (matched as exact-equal OR followed by '/' boundary).
 */
export type NamespacePrefix = string;

/**
 * Identifier allowed on a row's `createdBy` field for non-master scopes.
 */
export type FromAllowListEntry = string;

/**
 * Minimal OAuth context attached to an inbound MCP request.
 *
 * - `fromAllowList`: row.createdBy must be in this list for non-master callers
 *   to see a row. `["*"]` is the master wildcard convention.
 * - `namespaceReadPrefixes`: row.namespace must equal one of these OR start
 *   with prefix + '/' for the row to be readable by non-master callers.
 * - `namespaceWritePrefixes`: same semantics for write paths (enforced by the
 *   caller, this brick only exposes the field on the type).
 * - `scope`: optional scope profile name. `"master"` triggers wildcard pass.
 */
export type OAuthCtx = {
  fromAllowList: FromAllowListEntry[];
  namespaceReadPrefixes: NamespacePrefix[];
  namespaceWritePrefixes: NamespacePrefix[];
  scope?: ScopeProfile;
};

/**
 * Result of `validateMasterBearer`.
 *
 * - `ok: true` → token matched master secret in constant time.
 * - `ok: false` with `error: "missing"` → no Authorization header.
 * - `ok: false` with `error: "malformed"` → header present but not parseable
 *   as `Bearer <non-empty-token>`, OR master secret is empty.
 * - `ok: false` with `error: "mismatch"` → token parsed but did not match.
 */
export type ValidateMasterBearerResult =
  | { ok: true; error?: undefined }
  | { ok: false; error: "missing" | "malformed" | "mismatch" };
