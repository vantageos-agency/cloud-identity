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
