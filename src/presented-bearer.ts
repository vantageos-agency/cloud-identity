/**
 * Presented-bearer resolution — the opaque-token trust boundary.
 * (See package.json "version" for the release this shipped in.)
 *
 * Closes the gap between the two credential paths the package already had:
 *
 *   - `validateMasterBearer` covers the MASTER credential only (one configured
 *     secret, no datastore, no identity beyond "it was the master").
 *   - `decodeUnverifiedBearer` says in its own name that it verifies nothing;
 *     its payload is attacker-controlled and is not a trust boundary.
 *
 * Between them there was no function taking a PRESENTED, NON-MASTER bearer,
 * hashing it, looking the row up and returning a resolved identity or a typed
 * refusal. Consumers therefore wrote that primitive locally — a second
 * authority answering "who is calling", which is exactly what must not exist.
 * This module is the single one.
 *
 * DIVISION OF LABOUR. The package cannot query a datastore, so the row lookup
 * arrives as a caller-supplied callback. Everything that can be got wrong
 * stays here: the header parse, the hashing, the constant-time digest compare,
 * revocation, expiry, row-shape validation, and the SHAPE of the refusal. The
 * caller supplies one indexed read and nothing else.
 *
 * Errors are coarse-grained on purpose — callers should not surface the exact
 * reason to remote clients beyond a generic 401/403. The vocabulary is
 * `validateMasterBearer`'s, unchanged: "missing", "malformed", "mismatch".
 *
 * @security The callback is invoked with the SHA-256 HEX DIGEST of the
 * presented token, never the token. A consumer's datastore query, query log
 * and slow-query log therefore never see a usable secret. The raw token does
 * not appear in any returned value, any refusal, or any logging callback.
 */

import { z } from "zod";
import { sha256Hex, timingSafeEqual } from "./crypto.js";

const BEARER_PREFIX_LOWER = "bearer ";

// ---------------------------------------------------------------------------
// The stored row
// ---------------------------------------------------------------------------

/**
 * Shape of the row a consumer's datastore returns for a given digest.
 *
 * `agentId` ABSENT (undefined or null) means an ORGANIZATION-WIDE token: it
 * carries a tenant but no agent identity. Such a row is valid and resolves
 * successfully; what it may NOT do is stand in for an agent. See
 * `requireAgentScopedIdentity`.
 *
 * `secretHash` is the digest as stored by the consumer. It is re-compared here
 * against the digest computed from the presented token, in constant time, so a
 * lookup that performs a loose match (prefix, LIKE, case-folded index) or that
 * returns the wrong row cannot become an authentication.
 */
export const storedBearerRowSchema = z.object({
  tenantId: z.string().min(1),
  secretHash: z.string().min(1),
  agentId: z.string().min(1).nullish(),
  revoked: z.boolean().nullish(),
  expiresAt: z.number().nullish(),
  scopes: z.array(z.string()).nullish(),
});

export type StoredBearerRow = z.infer<typeof storedBearerRowSchema>;

// ---------------------------------------------------------------------------
// The resolved identity, and the agent as an explicit absence
// ---------------------------------------------------------------------------

/**
 * The agent, present or explicitly absent. A DISCRIMINATED UNION rather than a
 * nullable `agentId?: string`, because a nullable field is a duty to remember
 * and this one was being forgotten: `identity.agent.agentId` does not type-check
 * until the caller has narrowed on `present`.
 */
export type AgentPresence =
  | { present: true; agentId: string }
  | { present: false; code: "AGENT_ABSENT"; reason: "organization-wide-token" };

/**
 * A resolved, verified caller. Carries the tenant always, and the agent as a
 * presence-or-absence. Carries NO secret and no digest.
 */
export type ResolvedBearerIdentity = {
  tenantId: string;
  agent: AgentPresence;
  scopes: readonly string[];
};

/**
 * Brand for `AgentScopedIdentity`. Declared and NOT exported, so the branded
 * type cannot be constructed anywhere outside this module: a per-agent surface
 * that types its parameter as `AgentScopedIdentity` can only be reached through
 * `requireAgentScopedIdentity`. That is what makes the organization-wide-token
 * refusal structural rather than a convention a caller may skip.
 */
declare const agentScopedBrand: unique symbol;

/**
 * A resolved caller that HAS an agent. `agentId` is a plain non-optional
 * string, so per-agent code needs no narrowing and has nothing to forget.
 */
export type AgentScopedIdentity = {
  readonly [agentScopedBrand]: true;
  tenantId: string;
  agentId: string;
  scopes: readonly string[];
};

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

/**
 * Result of `validatePresentedBearer`.
 *
 *   - `ok: true` → the row was found, its digest matched in constant time, it
 *     is neither revoked nor expired, and its shape is valid.
 *   - `error: "missing"` → no Authorization header.
 *   - `error: "malformed"` → header present but not parseable as
 *     `Bearer <non-empty-token>`.
 *   - `error: "mismatch"` → the single, COLLAPSED refusal. An unknown digest,
 *     a revoked row, an expired row, a row of invalid shape and a row whose
 *     stored digest does not match all produce this value and nothing else, so
 *     a prober cannot learn from the response whether a token was ever real.
 *   - `error: "unavailable"` → the lookup callback itself threw or rejected.
 *     Deliberately NOT in the collapsed bucket: a caller must be able to
 *     answer 503 rather than 401 when its datastore is down, and an attacker
 *     cannot induce this state for one chosen token rather than another, so it
 *     discloses nothing about any token. It is a REFUSAL like the others — a
 *     lookup failure never falls through to a grant.
 */
export type ValidatePresentedBearerResult =
  | { ok: true; identity: ResolvedBearerIdentity; error?: undefined }
  | {
      ok: false;
      error: "missing" | "malformed" | "mismatch" | "unavailable";
      identity?: undefined;
    };

/**
 * Result of `requireAgentScopedIdentity`. The refusal is distinguishable from
 * `validatePresentedBearer`'s refusals on purpose: the credential here is
 * known-good, and the caller owes the remote client a 403 (wrong surface for
 * this token), not a 401 (bad token).
 */
export type RequireAgentScopedResult =
  | { ok: true; identity: AgentScopedIdentity; error?: undefined }
  | { ok: false; error: "no-agent-on-token"; identity?: undefined };

// ---------------------------------------------------------------------------
// Internal reasons — for the consumer's own logs, never for a remote client
// ---------------------------------------------------------------------------

/**
 * Why a refusal happened, for the consumer's own observability. Reported
 * through `deps.onRefusal`; NEVER present in a returned value, because a
 * returned distinction is a returned disclosure.
 *
 * @security Carries no token, no digest and no row. Only a reason word.
 */
export type PresentedBearerInternalReason =
  | "no-header"
  | "malformed-header"
  | "unknown-token"
  | "revoked-token"
  | "expired-token"
  | "row-shape-invalid"
  | "stored-digest-mismatch"
  | "lookup-failed";

export type PresentedBearerDeps = {
  /**
   * Indexed read of one row by the SHA-256 HEX DIGEST of the presented token.
   * Returns the row, or null/undefined when no row carries that digest.
   *
   * @security The argument is a digest, never the token. Do not log it, and do
   * not widen this to accept a raw secret.
   */
  lookupBySecretHash: (
    sha256HexDigest: string,
  ) => Promise<StoredBearerRow | null | undefined>;
  /** Injectable clock. Never `Date.now()` inline, so expiry is testable. */
  now?: () => number;
  /** Observability sink for the collapsed refusals. Must not throw; if it does, the throw is swallowed and the refusal stands. */
  onRefusal?: (reason: PresentedBearerInternalReason) => void;
};

// ---------------------------------------------------------------------------
// The refusals, as shared frozen singletons
// ---------------------------------------------------------------------------

const MISSING: ValidatePresentedBearerResult = Object.freeze({
  ok: false as const,
  error: "missing" as const,
});

const MALFORMED: ValidatePresentedBearerResult = Object.freeze({
  ok: false as const,
  error: "malformed" as const,
});

const UNAVAILABLE: ValidatePresentedBearerResult = Object.freeze({
  ok: false as const,
  error: "unavailable" as const,
});

/**
 * THE collapsed refusal. One frozen value, shared by every branch that must be
 * externally indistinguishable — unknown digest, revoked, expired, invalid row
 * shape, stored-digest mismatch. Not five literals that happen to be equal
 * today: one object, so the branches cannot drift apart by an added field.
 */
const COLLAPSED_REFUSAL: ValidatePresentedBearerResult = Object.freeze({
  ok: false as const,
  error: "mismatch" as const,
});

function report(
  deps: PresentedBearerDeps,
  reason: PresentedBearerInternalReason,
): void {
  const sink = deps.onRefusal;
  if (typeof sink !== "function") return;
  try {
    sink(reason);
  } catch {
    // A failing logger must never change an authorization outcome.
  }
}

function collapse(
  deps: PresentedBearerDeps,
  reason: PresentedBearerInternalReason,
): ValidatePresentedBearerResult {
  report(deps, reason);
  return COLLAPSED_REFUSAL;
}

// ---------------------------------------------------------------------------
// validatePresentedBearer
// ---------------------------------------------------------------------------

/**
 * Resolve an `Authorization: Bearer <token>` header presented by a NON-MASTER
 * caller into a verified identity, or into a typed refusal.
 *
 * Order of operations, and why:
 *   1. Parse the header. A missing or malformed header is refused WITHOUT
 *      calling the lookup, so a garbage request costs no datastore read.
 *   2. Hash the token to a SHA-256 hex digest. The raw token goes no further.
 *   3. Look the row up BY THAT DIGEST.
 *   4. Re-compare the row's stored digest against the computed one with
 *      `timingSafeEqual` — never `!==` on a secret or a digest.
 *   5. Validate the row's shape, then revocation, then expiry.
 *   6. Resolve the tenant, and the agent as a presence or an explicit absence.
 *
 * Steps 3–5 all refuse with the SAME frozen value. A right is never granted by
 * absence or by failure: there is no branch that returns `ok: true` without
 * having passed every check above.
 *
 * @example
 * ```ts
 * const result = await validatePresentedBearer(req.headers.get("authorization"), {
 *   lookupBySecretHash: (digest) => db.tokens.byDigest(digest),
 * });
 * if (!result.ok) return respond(result.error === "unavailable" ? 503 : 401);
 * const tenantId = result.identity.tenantId;
 * ```
 */
export async function validatePresentedBearer(
  authHeader: string | null | undefined,
  deps: PresentedBearerDeps,
): Promise<ValidatePresentedBearerResult> {
  if (typeof deps?.lookupBySecretHash !== "function") {
    // A programming error in the consumer, not a claim about any caller: it
    // must not be reported as a credential refusal.
    throw new TypeError(
      "validatePresentedBearer: deps.lookupBySecretHash must be a function.",
    );
  }

  if (authHeader === undefined || authHeader === null || authHeader === "") {
    report(deps, "no-header");
    return MISSING;
  }

  // Case-insensitive scheme match without lower-casing the token bytes
  // (RFC 7235 §2.1), identical to `validateMasterBearer`.
  const lower = authHeader.toLowerCase();
  if (!lower.startsWith(BEARER_PREFIX_LOWER)) {
    report(deps, "malformed-header");
    return MALFORMED;
  }
  const token = authHeader.slice(BEARER_PREFIX_LOWER.length).trim();
  if (token.length === 0) {
    report(deps, "malformed-header");
    return MALFORMED;
  }

  const presentedDigest = await sha256Hex(token);

  let row: StoredBearerRow | null | undefined;
  try {
    row = await deps.lookupBySecretHash(presentedDigest);
  } catch {
    report(deps, "lookup-failed");
    return UNAVAILABLE;
  }

  if (row === null || row === undefined) {
    return collapse(deps, "unknown-token");
  }

  const parsed = storedBearerRowSchema.safeParse(row);
  if (!parsed.success) {
    return collapse(deps, "row-shape-invalid");
  }
  const stored = parsed.data;

  const encoder = new TextEncoder();
  const digestsMatch = await timingSafeEqual(
    encoder.encode(stored.secretHash.toLowerCase()),
    encoder.encode(presentedDigest),
  );
  if (!digestsMatch) {
    return collapse(deps, "stored-digest-mismatch");
  }

  if (stored.revoked === true) {
    return collapse(deps, "revoked-token");
  }

  const nowMs = deps.now ? deps.now() : Date.now();
  if (typeof stored.expiresAt === "number" && stored.expiresAt <= nowMs) {
    return collapse(deps, "expired-token");
  }

  const agent: AgentPresence =
    typeof stored.agentId === "string" && stored.agentId.length > 0
      ? { present: true, agentId: stored.agentId }
      : {
          present: false,
          code: "AGENT_ABSENT",
          reason: "organization-wide-token",
        };

  return {
    ok: true,
    identity: {
      tenantId: stored.tenantId,
      agent,
      scopes: stored.scopes ?? [],
    },
  };
}

// ---------------------------------------------------------------------------
// requireAgentScopedIdentity
// ---------------------------------------------------------------------------

/**
 * Narrow a resolved identity to a PER-AGENT surface, refusing when the token
 * carries no agent.
 *
 * An organization-wide token is a legitimate credential that is simply not an
 * agent; treating it as one would silently widen it into whichever agent the
 * surface happened to be about. So this is a second, mandatory call, and its
 * output type is branded: a per-agent handler declares `AgentScopedIdentity`
 * and the only way to obtain one is here.
 *
 * Grants nothing on its own — it can only ever narrow an identity
 * `validatePresentedBearer` already resolved.
 */
export function requireAgentScopedIdentity(
  identity: ResolvedBearerIdentity,
): RequireAgentScopedResult {
  if (!identity.agent.present) {
    return { ok: false, error: "no-agent-on-token" };
  }
  const scoped = {
    tenantId: identity.tenantId,
    agentId: identity.agent.agentId,
    scopes: identity.scopes,
    // The brand exists only in the type system; there is no runtime field to
    // forge, and no value to construct outside this module.
  } as AgentScopedIdentity;
  return { ok: true, identity: scoped };
}
