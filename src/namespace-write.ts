/**
 * Namespace WRITE assertion.
 *
 * `OAuthCtx.namespaceWritePrefixes` has always been on the type with the note
 * "enforced by the caller". This is that enforcement, so no consumer carries
 * its own copy. It uses `namespaceMatchesPrefix` from `./scope-filter`, the
 * same boundary rule as the read filter: prefix equality, or prefix + '/'.
 *
 * A write is never granted by a READ prefix, by an empty prefix list (for a
 * non-master) or by an empty-string prefix.
 */

import { IdentityRefusalError, refusal } from "./identity-refusal.js";
import { isMasterScope, namespaceMatchesPrefix } from "./scope-filter.js";
import type { OAuthCtx } from "./types.js";

/**
 * Throws `IdentityRefusalError` unless the caller may write `namespace`.
 * Master scope (`scope === "master"` or `"*"` in `fromAllowList`) passes.
 *
 * @param door The consumer's own name for the entry point, for the refusal.
 */
export function assertNamespaceWrite(
  oauthCtx: OAuthCtx,
  namespace: string,
  door = "assertNamespaceWrite",
): void {
  if (oauthCtx == null) {
    throw new TypeError(
      "assertNamespaceWrite: oauthCtx is required — pass an explicit OAuthCtx.",
    );
  }
  const deny = (
    reason: "namespace-invalid" | "no-write-prefixes" | "namespace-write-denied",
    detail: string,
  ): never => {
    throw new IdentityRefusalError(refusal("RBAC_DENIED", reason, door, detail));
  };

  if (isMasterScope(oauthCtx)) return;

  if (typeof namespace !== "string" || namespace.length === 0) {
    deny("namespace-invalid", "A non-empty namespace is required.");
  }
  const prefixes = (oauthCtx.namespaceWritePrefixes ?? []).filter(
    (p) => typeof p === "string" && p.length > 0,
  );
  if (prefixes.length === 0) {
    deny("no-write-prefixes", "This caller holds no namespace write prefix.");
  }
  if (!prefixes.some((p) => namespaceMatchesPrefix(namespace, p))) {
    deny("namespace-write-denied", "The namespace is outside this caller's write prefixes.");
  }
}
