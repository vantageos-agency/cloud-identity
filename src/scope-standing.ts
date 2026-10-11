/**
 * Standing of a RESOLVED org scope (0.20.0).
 *
 * A consumer's org-scope resolver (VantagePeers `withOrgScope`) returns a scope
 * object; doors then branch on `scope.isMaster` locally. That boolean answers
 * two different questions (may this caller read the whole fleet, and is it the
 * fleet's own service), so each door re-derived its own reading. This module is
 * the one reading:
 *
 *   - "fleet"           a master scope granted to the fleet itself
 *                       (`masterSource` "service-account" or "internal").
 *   - "operator-admin"  a master scope granted to the operator's org:admin
 *                       human: it reads the fleet, it is not the fleet.
 *   - "member"          a non-master scope bound to one organisation
 *                       (`orgClerkId`, or `orgSlug` while ids are being filled).
 *   - "refused"         everything else: absent, malformed, flagged `refused`,
 *                       no organisation, or self-contradicting.
 *
 * Fail closed: a scope is "fleet" or "operator-admin" only when `isMaster`,
 * `fleetWide` and `masterSource` all agree; any disagreement is "refused",
 * never the more powerful reading.
 */

import { IdentityRefusalError, refusal } from "./identity-refusal.js";

export type ScopeStanding = "fleet" | "operator-admin" | "member" | "refused";

/** The fields of a resolved scope this module reads. Other fields are ignored. */
export interface StandingScope {
  isMaster: boolean;
  fleetWide: boolean;
  masterSource?: string;
  orgSlug?: string | null;
  orgClerkId?: string;
  refused?: boolean;
}

const FLEET_SOURCES: ReadonlySet<string> = new Set(["service-account", "internal"]);

function nonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

/** The standing of `scope`; "refused" for anything that is not a well-formed scope. */
export function scopeStanding(scope: unknown): ScopeStanding {
  if (scope === null || typeof scope !== "object" || Array.isArray(scope)) return "refused";
  const s = scope as Record<string, unknown>;
  if (s.refused === true) return "refused";
  if (typeof s.isMaster !== "boolean" || typeof s.fleetWide !== "boolean") return "refused";
  if (s.isMaster !== s.fleetWide) return "refused";

  if (s.isMaster) {
    if (typeof s.masterSource !== "string") return "refused";
    if (FLEET_SOURCES.has(s.masterSource)) return "fleet";
    if (s.masterSource === "operator-admin") return "operator-admin";
    return "refused";
  }

  if (s.masterSource !== undefined) return "refused";
  if (nonEmptyString(s.orgClerkId) || nonEmptyString(s.orgSlug)) return "member";
  return "refused";
}

/** True when the scope may read the whole fleet: "fleet" or "operator-admin". */
export function hasFleetRead(scope: unknown): boolean {
  const standing = scopeStanding(scope);
  return standing === "fleet" || standing === "operator-admin";
}

/**
 * Returns the scope's standing when it is in `allowed`; otherwise throws
 * `IdentityRefusalError` RBAC_DENIED naming `door`:
 *   - "scope-not-resolved"   the scope is "refused";
 *   - "standing-not-allowed" the standing exists but is not in `allowed`.
 * An empty `allowed` is a programming error (TypeError), never a pass.
 */
export function requireStanding(
  scope: unknown,
  door: string,
  allowed: readonly Exclude<ScopeStanding, "refused">[],
): Exclude<ScopeStanding, "refused"> {
  if (!Array.isArray(allowed) || allowed.length === 0) {
    throw new TypeError("requireStanding: `allowed` must name at least one standing.");
  }
  const standing = scopeStanding(scope);
  if (standing === "refused") {
    throw new IdentityRefusalError(
      refusal("RBAC_DENIED", "scope-not-resolved", door, "The caller's scope did not resolve to a standing."),
    );
  }
  if (!allowed.includes(standing)) {
    throw new IdentityRefusalError(
      refusal(
        "RBAC_DENIED",
        "standing-not-allowed",
        door,
        `Standing "${standing}" is not allowed here (allowed: ${allowed.join(", ")}).`,
      ),
    );
  }
  return standing;
}

/** `requireStanding(scope, door, ["fleet"])`: the fleet's own service only. */
export function requireFleetStanding(scope: unknown, door: string): "fleet" {
  return requireStanding(scope, door, ["fleet"]) as "fleet";
}
