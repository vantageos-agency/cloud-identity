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

/**
 * The standing of `scope`; "refused" for anything that is not a well-formed scope.
 *
 * @standingGate — judges a resolved scope or a verified bearer context; consumers may credit a call to it as a delegated gate.
 */
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

/**
 * True when the scope may read the whole fleet: "fleet" or "operator-admin".
 *
 * @standingGate — judges a resolved scope or a verified bearer context; consumers may credit a call to it as a delegated gate.
 */
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
 *
 * @standingGate — judges a resolved scope or a verified bearer context; consumers may credit a call to it as a delegated gate.
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

/**
 * `requireStanding(scope, door, ["fleet"])`: the fleet itself (the service account or the internal opt-in).
 *
 * @standingGate — judges a resolved scope or a verified bearer context; consumers may credit a call to it as a delegated gate.
 */
export function requireFleetStanding(scope: unknown, door: string): "fleet" {
  return requireStanding(scope, door, ["fleet"]) as "fleet";
}

/**
 * True when the scope is the fleet's own SERVICE ACCOUNT: standing "fleet" with
 * `masterSource` "service-account". The internal opt-in is fleet too, but it
 * carries no credential, so a door that must be the service account itself (a
 * verified actor, an agent credential) does not admit it.
 *
 * @standingGate — judges a resolved scope or a verified bearer context; consumers may credit a call to it as a delegated gate.
 */
export function isServiceAccountScope(scope: unknown): boolean {
  if (scopeStanding(scope) !== "fleet") return false;
  return (scope as { masterSource?: unknown }).masterSource === "service-account";
}

/**
 * Returns `"fleet"` when the scope is the service account (`isServiceAccountScope`),
 * the same literal as `requireFleetStanding`; otherwise throws `IdentityRefusalError` RBAC_DENIED naming `door`:
 *   - "scope-not-resolved"   the scope is "refused";
 *   - "standing-not-allowed" any other standing, the internal opt-in included.
 *
 * @standingGate — judges a resolved scope or a verified bearer context; consumers may credit a call to it as a delegated gate.
 */
export function requireServiceAccountStanding(scope: unknown, door: string): "fleet" {
  const standing = scopeStanding(scope);
  if (standing === "refused") {
    throw new IdentityRefusalError(
      refusal("RBAC_DENIED", "scope-not-resolved", door, "The caller's scope did not resolve to a standing."),
    );
  }
  if (!isServiceAccountScope(scope)) {
    throw new IdentityRefusalError(
      refusal(
        "RBAC_DENIED",
        "standing-not-allowed",
        door,
        `Only the fleet service account is allowed here (standing "${standing}").`,
      ),
    );
  }
  return "fleet";
}

/**
 * The standing of a VERIFIED bearer context, as an MCP transport attaches it to
 * a request: `isMaster` for the master population, `viaMasterBearer` set only
 * when that master presented the network master bearer.
 *
 *   - "service-bearer"  master, through the network master bearer (the fleet service account);
 *   - "local-trust"     master with no network bearer (a process-local server, e.g. stdio);
 *   - "caller"          any non-master token (a person or a seat of one organisation);
 *   - "refused"         absent, malformed, or a master-bearer flag on a non-master context.
 */
export type BearerStanding = "service-bearer" | "local-trust" | "caller" | "refused";

/** The fields of a bearer context this module reads. Other fields are ignored. */
export interface StandingBearer {
  isMaster: boolean;
  viaMasterBearer?: boolean;
}

/**
 * The standing of `context`; "refused" for anything that is not a well-formed bearer context.
 *
 * @standingGate — judges a resolved scope or a verified bearer context; consumers may credit a call to it as a delegated gate.
 */
export function bearerStanding(context: unknown): BearerStanding {
  if (context === null || typeof context !== "object" || Array.isArray(context)) return "refused";
  const c = context as Record<string, unknown>;
  if (typeof c.isMaster !== "boolean") return "refused";
  if (c.viaMasterBearer !== undefined && typeof c.viaMasterBearer !== "boolean") return "refused";
  if (!c.isMaster) return c.viaMasterBearer === true ? "refused" : "caller";
  return c.viaMasterBearer === true ? "service-bearer" : "local-trust";
}
