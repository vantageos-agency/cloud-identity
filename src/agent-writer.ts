/**
 * The agent behind a write the fleet service account makes on its behalf.
 *
 * A Convex mutation reached through the MCP transport is called by the fleet
 * service account. When the write is an agent's, the transport has already
 * verified which agent (its stored ID and organisation ID) and carries that
 * claim as an argument. The claim is only as good as the caller that presents
 * it, so a door must not decide identity itself: this module is the one
 * decision. It resolves the claim to the stored agent principal, or throws.
 *
 * It only RESOLVES. It writes nothing and returns no permission to write. The
 * door still writes, and still compares the stored IDs of the row it touches
 * with `principalId` / `orgId` of the principal returned here.
 *
 * Every step reuses an existing primitive and adds no rule of its own:
 *
 *   1. the caller must be the fleet service account (`requireServiceAccountStanding`);
 *   2. the claim must be exactly `{ agentId, orgId }`, IDs only (strict: a name beside
 *      the IDs refuses it whole);
 *   3. when the call names its target organisation, the claim must be for it;
 *   4. the agent is read by ID and must be active, stamped with the claim's
 *      organisation, and that organisation active (`resolveActingPrincipal`).
 *
 * Nothing is resolved by a name, and nothing falls back to a default principal.
 *
 * @security `verifiedActor` must be the transport's own result of verifying the
 * agent, never a value the end client chose. This module proves that the caller
 * is the service account and that the IDs name one live agent of that
 * organisation; it cannot prove the transport verified the right agent.
 */

import { z } from "zod";
import {
  type IdentityRefusal,
  IdentityRefusalError,
  type IdentityRefusalReason,
  refusal,
} from "./identity-refusal.js";
import { type OrgMappingLookups, orgMappingRowSchema } from "./org-by-id.js";
import {
  type ActingPrincipal,
  type PrincipalLookups,
  type PrincipalRow,
  resolveActingPrincipal,
} from "./principal-by-id.js";
import { requireServiceAccountStanding } from "./scope-standing.js";
import { requireSubjectFromIdentity } from "./tenant-from-identity.js";

const verifiedActorSchema = z.strictObject({
  agentId: z.string().min(1),
  orgId: z.string().min(1),
});

/** The transport-verified claim: the agent's stored ID and the organisation ID it was verified in. */
export type AgentWriterClaim = z.input<typeof verifiedActorSchema>;

export type AgentWriterInput = {
  /** The caller's resolved scope; it must be the fleet service account's. */
  scope: unknown;
  /** The `verifiedActor` claim the transport carried; absent or malformed is refused. */
  verifiedActor: AgentWriterClaim | null | undefined;
  /** The organisation ID the call acts in, when the call names one; the claim must be for it. */
  targetOrgId?: string | null;
};

export type AgentWriterDeps = {
  /**
   * Indexed reads BY ID. Used: `agentById`, `organisationById`, `orgKindOf`
   * (the same three `resolveActingPrincipal` reads for an agent).
   */
  principalLookups: PrincipalLookups;
};

export type AgentWriterOptions = {
  /** The consumer's name for the door; carried on every refusal. */
  door?: string;
};

/**
 * Resolves a service-account agent write to the stored agent principal
 * `{ principalId, orgId, kind: "agent" }`, or throws `IdentityRefusalError`
 * RBAC_DENIED naming the door:
 *
 *   - "scope-not-resolved" / "standing-not-allowed"  the caller is not the service account
 *     (a member, the internal opt-in and an operator admin are all refused);
 *   - "credential-invalid"       `verifiedActor` is absent, or is not exactly `{ agentId, orgId }`;
 *   - "other-organisation"       the claim is for another organisation than `targetOrgId`, or
 *     the stored agent sits in another organisation than the claim;
 *   - "principal-not-found" / "principal-inactive" / "principal-record-invalid" /
 *     "principal-lookup-failed"  the agent lookup missed, found a deactivated or malformed
 *     row, was not supplied, or threw (its text is never surfaced);
 *   - "organisation-not-active"  the organisation is not mapped or not active.
 *
 * @callerResolver — resolves a verified caller; consumers may derive their accepted sinks from this tag.
 */
export async function resolveAgentWriter(
  input: AgentWriterInput,
  deps: AgentWriterDeps,
  options?: AgentWriterOptions,
): Promise<ActingPrincipal> {
  const door = options?.door ?? "resolveAgentWriter";

  requireServiceAccountStanding(input?.scope, door);

  return resolveClaim(input?.verifiedActor, input?.targetOrgId, deps?.principalLookups, door);
}

/** Steps 2 to 4, shared by both entry points once the caller is proven to be the service account. */
async function resolveClaim(
  verifiedActor: unknown,
  target: string | null | undefined,
  principalLookups: PrincipalLookups,
  door: string,
): Promise<ActingPrincipal> {
  const parsed = verifiedActorSchema.safeParse(verifiedActor);
  if (!parsed.success) {
    throw new IdentityRefusalError(
      refusal("RBAC_DENIED", "credential-invalid", door, "The call carries no verified agent identified by ID."),
    );
  }
  const claim = parsed.data;

  if (target !== undefined && target !== null && target !== claim.orgId) {
    throw new IdentityRefusalError(
      refusal(
        "RBAC_DENIED",
        "other-organisation",
        door,
        "The verified agent belongs to another organisation than the one this call acts in.",
      ),
    );
  }

  const resolved = await resolveActingPrincipal(
    { kind: "agent", agentId: claim.agentId, verifiedOrgId: claim.orgId },
    principalLookups,
    door,
  );
  if (!resolved.ok) throw new IdentityRefusalError(resolved.refusal);
  return resolved.principal;
}

// ---------------------------------------------------------------------------
// From the transport (0.27.0)
// ---------------------------------------------------------------------------

/**
 * A stored service-account row, as the consumer reads it by the verified
 * subject: the row's own ID, organisation and active flag (`PrincipalRow`),
 * and the auth subject the row carries. The package compares `subject`
 * byte-equal with the verified one, so a row the lookup returns for another
 * subject is ignored rather than believed.
 */
export type ServiceAccountRow = PrincipalRow & { subject: string };

type Lookup<A extends unknown[], R> = (
  ...args: A
) => Promise<R | null | undefined> | R | null | undefined;

/** The one service-account read: the stored rows carrying a verified subject. */
export type ServiceAccountIdentityLookups = {
  /** The stored service-account rows carrying `subject` as their auth subject (an indexed read, bounded). */
  serviceAccountsBySubject?: Lookup<[subject: string], readonly ServiceAccountRow[]>;
};

/**
 * The host transport's auth object, as Convex hands it to a function
 * (`ctx.auth`). The package calls `getUserIdentity()` itself; the host has
 * verified the token (signature, issuer) before it answers.
 */
export type TransportAuth = {
  getUserIdentity(): Promise<unknown> | unknown;
};

export type AgentWriterFromIdentityInput = {
  /** The `verifiedActor` claim the transport carried; absent or malformed is refused. */
  verifiedActor: AgentWriterClaim | null | undefined;
  /** The organisation ID the call acts in, when the call names one; the claim must be for it. */
  targetOrgId?: string | null;
};

export type AgentWriterFromIdentityDeps = {
  /**
   * Indexed reads BY ID. Used: `organisationById`, `orgKindOf` (the service
   * account's organisation, which must be the operator's) and `agentById`.
   */
  principalLookups: PrincipalLookups;
  /**
   * The mapping store, read BY organisation ID (`orgById`, the same adapter
   * `resolveCallerFromClaims` reads). The row's `serviceAccountId` must name
   * the service-account row back.
   */
  orgLookups: Pick<OrgMappingLookups, "orgById">;
  /** The service-account read by verified subject. */
  serviceAccountLookups: ServiceAccountIdentityLookups;
};

function deny(reason: IdentityRefusalReason, door: string, detail: string): IdentityRefusalError {
  return new IdentityRefusalError(refusal("RBAC_DENIED", reason, door, detail));
}

function notTheServiceAccount(door: string): IdentityRefusalError {
  return deny(
    "standing-not-allowed",
    door,
    "Only the fleet service account is allowed here; the verified identity is not it.",
  );
}

/** The verified subject, read by the package from the transport. Throws on absence, malformation or failure. */
async function subjectFromTransport(auth: TransportAuth | null | undefined, door: string): Promise<string> {
  if (auth === null || typeof auth !== "object" || typeof auth.getUserIdentity !== "function") {
    throw deny("no-verified-subject", door, "No verified identity was presented.");
  }
  let raw: unknown;
  try {
    raw = await auth.getUserIdentity();
  } catch {
    throw deny("credential-invalid", door, "The transport could not produce a verified identity.");
  }
  const identity =
    raw !== null && typeof raw === "object" && !Array.isArray(raw) ? (raw as Record<string, unknown>) : null;
  return requireSubjectFromIdentity(identity, { door });
}

/** Whether the organisation's own mapping row (read by its ID) names `serviceAccountId` as its service account. */
async function orgNamesServiceAccount(
  orgId: string,
  serviceAccountId: string,
  orgLookups: Pick<OrgMappingLookups, "orgById"> | undefined,
  door: string,
): Promise<boolean> {
  const orgById = orgLookups?.orgById;
  if (typeof orgById !== "function") {
    throw deny("org-mapping-lookup-failed", door, "The organisation lookup was not supplied or failed.");
  }
  let raw: unknown;
  try {
    raw = await orgById(orgId);
  } catch {
    throw deny("org-mapping-lookup-failed", door, "The organisation lookup was not supplied or failed.");
  }
  if (raw === null || raw === undefined) return false;
  const row = orgMappingRowSchema.safeParse(raw);
  if (!row.success || row.data.id !== orgId) {
    throw deny("org-mapping-record-invalid", door, "The organisation record is not a valid record of that organisation.");
  }
  return row.data.serviceAccountId === serviceAccountId;
}

/**
 * Whether the verified subject is the fleet service account, decided from
 * stored rows only: a row carrying the subject, named back by its own
 * organisation's mapping row, that resolves (`resolveActingPrincipal`) to the
 * `fleet` principal. Throws `IdentityRefusalError` RBAC_DENIED naming the door.
 */
async function requireServiceAccountSubject(
  subject: string,
  deps: AgentWriterFromIdentityDeps,
  door: string,
): Promise<void> {
  const bySubject = deps?.serviceAccountLookups?.serviceAccountsBySubject;
  const lookupFailed = () =>
    deny("principal-lookup-failed", door, "The service-account lookup was not supplied or failed.");
  if (typeof bySubject !== "function") throw lookupFailed();

  let rows: unknown;
  try {
    rows = await bySubject(subject);
  } catch {
    throw lookupFailed();
  }
  if (rows === null || rows === undefined) rows = [];
  if (!Array.isArray(rows)) throw lookupFailed();

  const own = rows.filter(
    (r): r is ServiceAccountRow =>
      r !== null && typeof r === "object" && (r as { subject?: unknown }).subject === subject,
  );
  if (own.length === 0) throw notTheServiceAccount(door);

  let last: IdentityRefusalError = notTheServiceAccount(door);
  for (const row of own) {
    const orgId = row.orgId;
    if (typeof orgId !== "string" || orgId.length === 0) {
      last = deny("no-verified-organisation", door, "The service account is stamped with no organisation.");
      continue;
    }
    if (!(await orgNamesServiceAccount(orgId, row.id, deps.orgLookups, door))) {
      last = notTheServiceAccount(door);
      continue;
    }
    const resolved = await resolveActingPrincipal(
      { kind: "service", serviceAccountId: row.id },
      {
        ...deps.principalLookups,
        serviceAccountById: (id) => (id === row.id ? row : null),
      },
      door,
    );
    if (!resolved.ok) {
      last = new IdentityRefusalError(resolved.refusal);
      continue;
    }
    if (resolved.principal.kind === "fleet" && resolved.principal.principalId === row.id) return;
    last = notTheServiceAccount(door);
  }
  throw last;
}

/** The result of `resolveAgentWriterFromIdentity`: the stored agent principal, or the refusal. */
export type AgentWriterFromIdentityResult =
  | { ok: true; principal: ActingPrincipal }
  | { ok: false; refusal: IdentityRefusal };

/**
 * `resolveAgentWriter`, with the caller's standing decided by the package from
 * the TRANSPORT rather than from a scope the consumer resolved. The consumer
 * passes its host's auth object (for Convex, `ctx.auth`) and never reads the
 * identity itself; the package calls `getUserIdentity()`.
 *
 *   1. the transport yields a verified subject (`requireSubjectFromIdentity`);
 *   2. that subject is the fleet service account: a stored service-account row
 *      carries it, the row's organisation names that row as its own
 *      (`orgById(row.orgId).serviceAccountId`), and the row resolves through
 *      `resolveActingPrincipal` to the `fleet` principal (the operator
 *      organisation, active, the row active). An org claim on the identity
 *      plays no part: neither upgrade nor downgrade;
 *   3. then exactly `resolveAgentWriter`'s steps 2 to 4 on the claim.
 *
 * Returns `{ ok: true, principal }` with `principal = { principalId, orgId, kind: "agent" }`,
 * or `{ ok: false, refusal }`, a RBAC_DENIED refusal naming the door; it never throws a
 * refusal (unlike `resolveAgentWriter`, which keeps its throwing contract). Reasons:
 *
 *   - "no-verified-subject"      no auth object, no identity, or an identity with no subject;
 *   - "credential-invalid"       `getUserIdentity()` threw (its text is never surfaced);
 *   - "standing-not-allowed"     no service account carries the subject (a member, a person),
 *     its organisation does not name it, or it is not the operator's (a client service account);
 *   - "principal-lookup-failed"  the subject lookup was not supplied, threw, or answered a non-list;
 *   - "org-mapping-lookup-failed" / "org-mapping-record-invalid"  the organisation lookup was not
 *     supplied, threw, or answered a malformed row or a row of another organisation;
 *   - "principal-inactive" / "no-verified-organisation" / "organisation-not-active"  the
 *     service-account row or its organisation does not hold;
 *   - then every refusal of `resolveAgentWriter` for the claim.
 *
 * @callerResolver — resolves a verified caller; consumers may derive their accepted sinks from this tag.
 */
export async function resolveAgentWriterFromIdentity(
  auth: TransportAuth | null | undefined,
  input: AgentWriterFromIdentityInput,
  deps: AgentWriterFromIdentityDeps,
  options?: AgentWriterOptions,
): Promise<AgentWriterFromIdentityResult> {
  const door = options?.door ?? "resolveAgentWriterFromIdentity";
  try {
    const subject = await subjectFromTransport(auth, door);
    await requireServiceAccountSubject(subject, deps, door);
    const principal = await resolveClaim(input?.verifiedActor, input?.targetOrgId, deps?.principalLookups, door);
    return { ok: true, principal };
  } catch (err) {
    // Every step refuses by an IdentityRefusalError built here; anything else is a
    // programming error and propagates unchanged.
    if (err instanceof IdentityRefusalError) return { ok: false, refusal: err.refusal };
    throw err;
  }
}
