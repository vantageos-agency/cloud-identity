/**
 * Role policy as DATA: a minimum-role check over a caller-supplied order, and a
 * role-claim mapping with no package-chosen default.
 *
 * The package never knows what roles exist. "admin > editor > viewer" is one
 * consumer's vocabulary, passed in at the call site; another consumer passes
 * another. Every absence (no role, unknown role, empty order, no mapping, no
 * fallback) is a refusal, never a default grant.
 *
 * Pure functions: no framework SDK, no I/O.
 */

import {
  IdentityRefusalError,
  refusal,
  type IdentityRefusal,
} from "./identity-refusal.js";

const DOOR_MIN = "resolveMinRole";
const DOOR_MAP = "mapRoleClaim";

// ---------------------------------------------------------------------------
// Minimum role over a caller-supplied order
// ---------------------------------------------------------------------------

export type MinRoleInput = {
  /** The verified role of the caller. null/undefined/"" is "no role". */
  role: string | null | undefined;
  /** The least-privileged role that is admitted. Must appear in `order`. */
  minimum: string;
  /**
   * The caller's ordered role list, MOST privileged FIRST
   * (e.g. `["admin", "editor", "viewer"]`). No empty list, no duplicates.
   */
  order: readonly string[];
  /** The consumer's own name for the entry point. Defaults to the function name. */
  door?: string;
};

export type MinRoleResult =
  | { ok: true; role: string }
  | { ok: false; refusal: IdentityRefusal };

/**
 * Admit `role` when it is at or above `minimum` in `order`.
 *
 * Refuses: an invalid order (empty, duplicated, non-string entries), a
 * `minimum` outside the order, a missing or unknown role, a role below the
 * minimum. Matching is exact (no case-folding), and a role is only ever found
 * by array position, so `"constructor"` or `"__proto__"` are unknown roles.
 */
export function resolveMinRole(input: MinRoleInput): MinRoleResult {
  const door = input.door ?? DOOR_MIN;
  const { order, role, minimum } = input;

  const orderValid =
    Array.isArray(order) &&
    order.length > 0 &&
    order.every((r) => typeof r === "string" && r.length > 0) &&
    new Set(order).size === order.length;
  if (!orderValid) {
    return {
      ok: false,
      refusal: refusal(
        "RBAC_DENIED",
        "invalid-role-order",
        door,
        "The role order must be a non-empty list of distinct role names.",
      ),
    };
  }

  const minIndex = order.indexOf(minimum);
  if (minIndex === -1) {
    return {
      ok: false,
      refusal: refusal(
        "RBAC_DENIED",
        "unknown-minimum-role",
        door,
        "The required minimum role is not part of the role order.",
      ),
    };
  }

  const roleIndex = typeof role === "string" && role.length > 0 ? order.indexOf(role) : -1;
  if (roleIndex === -1) {
    return {
      ok: false,
      refusal: refusal(
        "RBAC_DENIED",
        "unknown-role",
        door,
        "The caller's role is absent or not part of the role order.",
      ),
    };
  }

  if (roleIndex > minIndex) {
    return {
      ok: false,
      refusal: refusal(
        "RBAC_DENIED",
        "role-below-minimum",
        door,
        "The caller's role is below the required minimum.",
      ),
    };
  }
  return { ok: true, role: order[roleIndex] as string };
}

/** Throwing form of {@link resolveMinRole}; returns the role, throws `IdentityRefusalError`. */
export function assertMinRole(input: MinRoleInput): string {
  const result = resolveMinRole(input);
  if (!result.ok) throw new IdentityRefusalError(result.refusal);
  return result.role;
}

// ---------------------------------------------------------------------------
// Role-claim mapping with an explicit fallback
// ---------------------------------------------------------------------------

export type MapRoleClaimInput = {
  /** The raw claim from the verified credential. Only a non-empty string counts. */
  claim: unknown;
  /** Claim value -> consumer role. Data supplied by the caller. */
  mapping: Readonly<Record<string, string>>;
  /**
   * The role to use when the claim is absent or not in `mapping`. The package
   * never picks one: omit it and an absent or unmapped claim is REFUSED.
   * Supply the least-privileged role you have.
   */
  fallback?: string;
  door?: string;
};

export type MapRoleClaimResult =
  | { ok: true; role: string; source: "mapped" | "fallback" }
  | { ok: false; refusal: IdentityRefusal };

/**
 * Map a verified role claim to the consumer's role, with a least-privilege
 * fallback that the CALLER must name. A claim that is not a string (array,
 * object, number) is absent, never coerced. Lookup uses own keys only, so a
 * claim of `"constructor"` is unmapped.
 */
export function mapRoleClaim(input: MapRoleClaimInput): MapRoleClaimResult {
  const door = input.door ?? DOOR_MAP;
  const { claim, mapping, fallback } = input;

  if (mapping === null || typeof mapping !== "object" || Array.isArray(mapping)) {
    return {
      ok: false,
      refusal: refusal(
        "RBAC_DENIED",
        "invalid-role-mapping",
        door,
        "The role mapping must be a plain object of claim to role.",
      ),
    };
  }

  const present = typeof claim === "string" && claim.length > 0;
  if (present && Object.hasOwn(mapping, claim)) {
    const mapped = mapping[claim];
    if (typeof mapped === "string" && mapped.length > 0) {
      return { ok: true, role: mapped, source: "mapped" };
    }
    return {
      ok: false,
      refusal: refusal(
        "RBAC_DENIED",
        "invalid-role-mapping",
        door,
        "The role mapping holds a non-string or empty role.",
      ),
    };
  }

  if (typeof fallback === "string" && fallback.length > 0) {
    return { ok: true, role: fallback, source: "fallback" };
  }

  return {
    ok: false,
    refusal: refusal(
      "RBAC_DENIED",
      present ? "role-claim-unmapped" : "role-claim-absent",
      door,
      present
        ? "The role claim is not in the mapping and no fallback was supplied."
        : "No role claim was presented and no fallback was supplied.",
    ),
  };
}

// ---------------------------------------------------------------------------
// A decision on a SET of token scopes (0.37.0)
// ---------------------------------------------------------------------------

const DOOR_SCOPE = "resolveScopeGrant";

/**
 * The consumer's scope alphabet, as data. The package never knows what scopes
 * exist.
 *
 *   - `ladder`: scopes where a higher rank implies every rank below it, MOST
 *     privileged FIRST (the `resolveMinRole` order convention, e.g.
 *     `["cloud-admin", "admin", "write", "read"]`). May be empty.
 *   - `offLadder`: scopes that no ladder rank implies (e.g.
 *     `"workflow-trigger"`). Each is satisfied only by an exact grant or by a
 *     named superscope.
 *   - `superscopes`: scopes the CALLER names as satisfying every required
 *     scope, off-ladder ones included. Never inferred from the top of the
 *     ladder: omit it and no scope reaches an off-ladder scope except itself.
 *
 * Valid only when every entry is a non-empty string, `ladder` and `offLadder`
 * are distinct and disjoint, their union is non-empty, and every superscope is
 * in that union. An invalid policy refuses every request.
 */
export type ScopePolicy = {
  ladder: readonly string[];
  offLadder?: readonly string[];
  superscopes?: readonly string[];
};

export type ScopeGrantInput = {
  /**
   * The token's scopes, as verified. Only an array counts: a space-delimited
   * string, an object or an absence is `scopes-absent`. Non-string entries are
   * skipped, never coerced. Matching is exact (no case-folding, no trim).
   */
  scopes: unknown;
  /** The scope the entry point requires. Must be in the policy's alphabet. */
  required: string;
  policy: ScopePolicy;
  /** The consumer's own name for the entry point. Defaults to the function name. */
  door?: string;
};

/**
 * `via` says which rule granted: `exact` (the token holds `required`),
 * `ladder` (a higher ladder rank, named in `grantedBy`), `superscope` (a
 * caller-named superscope, named in `grantedBy`).
 */
export type ScopeGrantResult =
  | { ok: true; required: string; via: "exact" | "ladder" | "superscope"; grantedBy: string }
  | { ok: false; refusal: IdentityRefusal };

function distinctNonEmptyStrings(list: unknown): list is readonly string[] {
  return (
    Array.isArray(list) &&
    list.every((s) => typeof s === "string" && s.length > 0) &&
    new Set(list).size === list.length
  );
}

function policyAlphabet(policy: unknown): ReadonlySet<string> | null {
  if (policy === null || typeof policy !== "object") return null;
  const { ladder, offLadder = [], superscopes = [] } = policy as ScopePolicy;
  if (!distinctNonEmptyStrings(ladder)) return null;
  if (!distinctNonEmptyStrings(offLadder)) return null;
  if (!distinctNonEmptyStrings(superscopes)) return null;
  const alphabet = new Set<string>([...ladder, ...offLadder]);
  if (alphabet.size === 0 || alphabet.size !== ladder.length + offLadder.length) return null;
  if (!superscopes.every((s) => alphabet.has(s))) return null;
  return alphabet;
}

/**
 * Decide whether a token's SET of scopes satisfies one required scope.
 *
 * Order: policy valid, required scope in the alphabet, scopes an array; then
 * exact grant, then ladder rank (through `resolveMinRole`, the one ordering
 * decision in this package), then a caller-named superscope. Everything else
 * is `scope-not-granted`.
 *
 * Off-ladder ruling: a required scope that is not on the ladder is satisfied
 * ONLY by holding it exactly or by holding a scope the caller named in
 * `superscopes`. No ladder rank implies it, the top rank included, and holding
 * it implies nothing on the ladder.
 *
 * Refusals (`RBAC_DENIED`): `scope-policy-invalid`, `scope-required-unknown`,
 * `scopes-absent`, `scope-not-granted`. A token scope outside the alphabet
 * (e.g. an unexpanded `"mcp:full"`) grants nothing.
 */
export function resolveScopeGrant(input: ScopeGrantInput): ScopeGrantResult {
  const door = input.door ?? DOOR_SCOPE;
  const { scopes, required, policy } = input;

  const alphabet = policyAlphabet(policy);
  if (alphabet === null) {
    return {
      ok: false,
      refusal: refusal(
        "RBAC_DENIED",
        "scope-policy-invalid",
        door,
        "The scope policy must name distinct, non-empty scopes; superscopes must be among them.",
      ),
    };
  }
  if (typeof required !== "string" || !alphabet.has(required)) {
    return {
      ok: false,
      refusal: refusal(
        "RBAC_DENIED",
        "scope-required-unknown",
        door,
        "The required scope is not part of the scope policy.",
      ),
    };
  }
  if (!Array.isArray(scopes)) {
    return {
      ok: false,
      refusal: refusal("RBAC_DENIED", "scopes-absent", door, "No list of token scopes was presented."),
    };
  }

  const held = scopes.filter((s): s is string => typeof s === "string" && alphabet.has(s));
  if (held.includes(required)) {
    return { ok: true, required, via: "exact", grantedBy: required };
  }

  const ladder = policy.ladder;
  if (ladder.includes(required)) {
    for (const scope of held) {
      if (!ladder.includes(scope)) continue;
      if (resolveMinRole({ role: scope, minimum: required, order: ladder, door }).ok) {
        return { ok: true, required, via: "ladder", grantedBy: scope };
      }
    }
  }

  const superscope = held.find((s) => (policy.superscopes ?? []).includes(s));
  if (superscope !== undefined) {
    return { ok: true, required, via: "superscope", grantedBy: superscope };
  }

  return {
    ok: false,
    refusal: refusal(
      "RBAC_DENIED",
      "scope-not-granted",
      door,
      "The token's scopes do not grant the required scope.",
    ),
  };
}

/** Boolean form of {@link resolveScopeGrant}. */
export function hasScopeGrant(scopes: unknown, required: string, policy: ScopePolicy): boolean {
  return resolveScopeGrant({ scopes, required, policy }).ok;
}

/** Throwing form of {@link resolveScopeGrant}; returns the required scope, throws `IdentityRefusalError`. */
export function assertScopeGrant(input: ScopeGrantInput): string {
  const result = resolveScopeGrant(input);
  if (!result.ok) throw new IdentityRefusalError(result.refusal);
  return result.required;
}

/**
 * Keep the items whose required scope (read by `requiredOf`) the token's
 * scopes grant, in their original order. Identical to deciding each item with
 * {@link resolveScopeGrant}; an item whose required scope is outside the
 * policy is never kept, and absent scopes keep nothing.
 */
export function filterByScopeGrant<T>(
  items: readonly T[],
  scopes: unknown,
  policy: ScopePolicy,
  requiredOf: (item: T) => string,
): T[] {
  return items.filter((item) => hasScopeGrant(scopes, requiredOf(item), policy));
}
