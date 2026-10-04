/**
 * @vantageos/cloud-identity 0.9.0 — the person principal.
 *
 * A PERSON signed in through an OAuth connector (Claude, ChatGPT, any MCP
 * client) is not an agent. This module is the single, framework-agnostic
 * answer to four questions a consumer must not re-implement:
 *
 *   1. Who is the person, and in which organisation?
 *      `resolvePersonPrincipal` — from the record of an access token that the
 *      consumer already looked up by its digest. Never from an argument.
 *   2. Under what name does the person act?
 *      `resolvePersonActingName` / `checkPersonCallShape` — its OWN name,
 *      "user:<subject>", taken from the principal. An agent name needs that
 *      agent's own verified credential; another user's name is refused.
 *   3. Is a row in the person's organisation?
 *      `resolvePersonTenantAccess` — a strict equality on the organisation.
 *   4. May the person write?
 *      `resolveWriterRole` / `requireWriterRole` — the verified role must be on
 *      the writer allowlist the consumer holds as data. Fail closed.
 *
 * Pure functions over plain inputs: no Clerk SDK, no database, no network, no
 * master or bypass flag anywhere in the input. The consumer performs the
 * lookups (the token row, the organisation row, the writer list) and passes the
 * results in; this module only decides. Every refusal is a typed value carrying
 * its own code, reason and door, so a caller can branch on content, and an
 * absence (no organisation, no role, no list) is a refusal, never a default.
 *
 * @security This module verifies NOTHING about the credential itself. The
 * token record must come from a lookup of the bearer the person presented, made
 * by the consumer's trusted transport layer. Passing a client-supplied object
 * makes that object the source of subject, organisation and role.
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// Refusal vocabulary
// ---------------------------------------------------------------------------

export type PersonRefusalCode =
  | "RBAC_DENIED"
  | "PERSON_ACTS_AS_ITSELF"
  | "AGENT_CREDENTIAL_REQUIRED"
  | "AGENT_IDENTITY_MISMATCH";

export type PersonRefusalReason =
  | "person-token-not-live"
  | "not-a-person-token"
  | "person-token-no-org"
  | "org-not-active"
  | "person-acts-as-itself"
  | "agent-proof-on-person-path"
  | "agent-credential-required"
  | "agent-identity-mismatch"
  | "other-organisation"
  | "role-not-writer";

/** The typed refusal. A non-empty object carrying its own code and door. */
export type PersonRefusal = {
  code: PersonRefusalCode;
  reason: PersonRefusalReason;
  /** The consumer's own name for the entry point that refused. */
  door: string;
  /** One sentence, safe to show to the caller. Never a credential. */
  detail: string;
  /** The acting name the caller typed, when the refusal is about a name. */
  claimed?: string;
  /** The person's own actor name, when the refusal is about a name. */
  self?: string;
  /** The verified role, when the refusal is about a role (null: none). */
  role?: string | null;
  /** The organisation the decision was taken in, when it applies. */
  orgSlug?: string | null;
};

/** Thrown by the throwing forms. Carries the typed refusal untouched. */
export class PersonRefusalError extends Error {
  readonly refusal: PersonRefusal;
  constructor(refusal: PersonRefusal) {
    super(`${refusal.code}: ${refusal.detail} (${refusal.reason}, ${refusal.door})`);
    this.name = "PersonRefusalError";
    this.refusal = refusal;
  }
}

function refuse(
  code: PersonRefusalCode,
  reason: PersonRefusalReason,
  door: string,
  detail: string,
  extra: Partial<Pick<PersonRefusal, "claimed" | "self" | "role" | "orgSlug">> = {},
): PersonRefusal {
  return { code, reason, door, detail, ...extra };
}

// ---------------------------------------------------------------------------
// Actor name
// ---------------------------------------------------------------------------

/** How a person is recorded as "who did it": "user:<verified subject>". */
export const PERSON_ACTOR_PREFIX = "user:";

/** NFC, lowercase, trim: the comparison form of an acting name. */
function normalizeName(name: string): string {
  return name.normalize("NFC").toLowerCase().trim();
}

/** The actor name of a verified subject. */
export function personActorName(subject: string): string {
  return `${PERSON_ACTOR_PREFIX}${subject}`;
}

/**
 * True when `name` is spelled like a person's actor name. Such a name is
 * RESERVED: a consumer refuses it at agent registration, so a stored actor
 * "user:..." can only have been written from a verified subject.
 */
export function isPersonActorName(name: string): boolean {
  return normalizeName(name).startsWith(PERSON_ACTOR_PREFIX);
}

// ---------------------------------------------------------------------------
// 1. The principal
// ---------------------------------------------------------------------------

/**
 * The record of a presented access token, in the package's vocabulary. The
 * consumer maps its own row onto this shape (`subject` is the verified Clerk
 * user id, `orgSlug` the organisation the token is bound to).
 */
export const personTokenRecordSchema = z.object({
  principal: z.string().optional(),
  subject: z.string(),
  orgSlug: z.string().optional(),
  orgRole: z.string().optional(),
  revokedAt: z.number().optional(),
  expiresAt: z.number(),
});
export type PersonTokenRecord = z.input<typeof personTokenRecordSchema>;

/** A verified person: who, in which organisation, with which role. */
export type PersonPrincipal = {
  subject: string;
  orgSlug: string;
  /** Present only when the token carries a verified role. Never defaulted. */
  orgRole?: string;
  /** "user:<subject>" — the name this person acts under. */
  actor: string;
};

/** The state of an organisation as the consumer's own mapping holds it. */
export type OrganisationState = { isActive: boolean };

export type PersonPrincipalDeps<O extends OrganisationState> = {
  /** Epoch milliseconds, supplied by the caller so the decision is pure. */
  now: number;
  /** Resolves the organisation row for a slug; null when unmapped. */
  lookupOrganisation: (orgSlug: string) => Promise<O | null>;
};

export type PersonPrincipalResult<O extends OrganisationState> =
  | { ok: true; principal: PersonPrincipal; organisation: O }
  | { ok: false; refusal: PersonRefusal };

/**
 * Resolves the person behind a presented token, or refuses. Checks, in order:
 * the token is live (present, unrevoked, unexpired); it acts for a PERSON;
 * it is bound to an organisation; that organisation exists and is active.
 * The only organisation ever looked up is the token's own.
 */
export async function resolvePersonPrincipal<O extends OrganisationState>(
  token: PersonTokenRecord | null | undefined,
  deps: PersonPrincipalDeps<O>,
  door: string,
): Promise<PersonPrincipalResult<O>> {
  const deny = (
    reason: PersonRefusalReason,
    detail: string,
  ): { ok: false; refusal: PersonRefusal } => ({
    ok: false,
    refusal: refuse("RBAC_DENIED", reason, door, detail),
  });

  const parsed = personTokenRecordSchema.safeParse(token);
  if (
    !parsed.success ||
    parsed.data.revokedAt !== undefined ||
    parsed.data.expiresAt < deps.now
  ) {
    return deny("person-token-not-live", "verifiedPerson names no live access token");
  }
  const row = parsed.data;
  if (row.principal !== "person" || row.subject === "") {
    return deny(
      "not-a-person-token",
      "verifiedPerson names a token that does not act for a person",
    );
  }
  const orgSlug = row.orgSlug;
  if (orgSlug === undefined || orgSlug === "") {
    return deny("person-token-no-org", "the person's token is bound to no organisation");
  }
  const organisation = await deps.lookupOrganisation(orgSlug);
  if (organisation === null || !organisation.isActive) {
    return deny(
      "org-not-active",
      `Org "${orgSlug}" not in client_org_mapping or inactive`,
    );
  }
  return {
    ok: true,
    organisation,
    principal: {
      subject: row.subject,
      orgSlug,
      ...(row.orgRole !== undefined ? { orgRole: row.orgRole } : {}),
      actor: personActorName(row.subject),
    },
  };
}

// ---------------------------------------------------------------------------
// 2. The own-name actor rule
// ---------------------------------------------------------------------------

export type PersonActingNameResult =
  | { ok: true; actingAs: "person"; actor: string }
  | { ok: true; actingAs: "agent"; actor: string }
  | { ok: false; refusal: PersonRefusal };

/**
 * Decides under which name a person acts. The acting identity comes from the
 * principal, never from the typed name:
 *
 *   - no name, or the person's own name  -> acts as itself;
 *   - another user's name                -> PERSON_ACTS_AS_ITSELF;
 *   - an agent's name                    -> only with that agent's own verified
 *                                           credential (`agentCredential`,
 *                                           resolved by the consumer): none ->
 *                                           AGENT_CREDENTIAL_REQUIRED, a
 *                                           different agent -> AGENT_IDENTITY_MISMATCH.
 */
export function resolvePersonActingName(input: {
  /** Only the actor name is read: the rule needs no organisation. */
  principal: Pick<PersonPrincipal, "actor">;
  claimedName?: string | null;
  /** The agent the presented credential resolved to, when one was presented. */
  agentCredential?: { agentName: string } | null;
  door: string;
}): PersonActingNameResult {
  const { principal, door } = input;
  const claimed = input.claimedName;
  if (claimed === undefined || claimed === null) {
    return { ok: true, actingAs: "person", actor: principal.actor };
  }
  const name = normalizeName(claimed);
  if (name === normalizeName(principal.actor)) {
    return { ok: true, actingAs: "person", actor: principal.actor };
  }
  if (name.startsWith(PERSON_ACTOR_PREFIX)) {
    return {
      ok: false,
      refusal: refuse(
        "PERSON_ACTS_AS_ITSELF",
        "person-acts-as-itself",
        door,
        `a person acts only in its own name; this call names "${claimed}"`,
        { claimed, self: principal.actor },
      ),
    };
  }
  const credential = input.agentCredential;
  if (credential === undefined || credential === null) {
    return {
      ok: false,
      refusal: refuse(
        "AGENT_CREDENTIAL_REQUIRED",
        "agent-credential-required",
        door,
        `this call names "${claimed}" but carried no credential of that agent`,
        { claimed, self: principal.actor },
      ),
    };
  }
  if (normalizeName(credential.agentName) !== name) {
    return {
      ok: false,
      refusal: refuse(
        "AGENT_IDENTITY_MISMATCH",
        "agent-identity-mismatch",
        door,
        `this call names "${claimed}" but the presented credential belongs to another agent`,
        { claimed, self: principal.actor },
      ),
    };
  }
  return { ok: true, actingAs: "agent", actor: credential.agentName };
}

/**
 * The shape of a call that reaches a backend door ON a person's behalf: it
 * carries no acting name (the transport already stripped the person's own) and
 * no agent proof (a person that presented an agent credential acts as that
 * agent, on the agent path). Returns the refusal, or null when the shape is
 * right.
 */
export function checkPersonCallShape(input: {
  door: string;
  actingName?: string;
  agentProof?: boolean;
}): PersonRefusal | null {
  if (input.agentProof === true) {
    return refuse(
      "RBAC_DENIED",
      "agent-proof-on-person-path",
      input.door,
      "a person's call carries no agent credential and no verified actor",
    );
  }
  if (input.actingName !== undefined) {
    return refuse(
      "PERSON_ACTS_AS_ITSELF",
      "person-acts-as-itself",
      input.door,
      `a person acts only in its own name; this call also names "${input.actingName}"`,
      { claimed: input.actingName },
    );
  }
  return null;
}

// ---------------------------------------------------------------------------
// 3. Tenant compare
// ---------------------------------------------------------------------------

export type PersonAccessResult = { ok: true } | { ok: false; refusal: PersonRefusal };

/**
 * A row is reachable only when its organisation stamp EQUALS the person's
 * organisation. An absent or empty stamp never equals a resolved organisation,
 * so an unstamped row is refused.
 */
export function resolvePersonTenantAccess(input: {
  principal: PersonPrincipal;
  rowOrgId: string | null | undefined;
  door: string;
}): PersonAccessResult {
  const { principal, rowOrgId, door } = input;
  if (typeof rowOrgId === "string" && rowOrgId !== "" && rowOrgId === principal.orgSlug) {
    return { ok: true };
  }
  return {
    ok: false,
    refusal: refuse(
      "RBAC_DENIED",
      "other-organisation",
      door,
      "the row is outside the person's organisation (tenant boundary)",
      { orgSlug: principal.orgSlug },
    ),
  };
}

// ---------------------------------------------------------------------------
// 4. Writer role
// ---------------------------------------------------------------------------

type WriterRoleInput = {
  /** The VERIFIED role claim of the token. Absent or null is refused. */
  role: string | null | undefined;
  /** The writer allowlist the consumer holds as data. Empty refuses all. */
  writerRoles: readonly string[];
  door: string;
  orgSlug?: string | null;
};

/**
 * Non-throwing writer-role assertion. The role must appear EXACTLY in the
 * allowlist; no hierarchy, no inheritance. An absent role, an absent list and
 * an empty list all refuse: a missing list never means "all roles".
 */
export function resolveWriterRole(input: WriterRoleInput): PersonAccessResult {
  const role = input.role ?? null;
  if (role !== null && input.writerRoles.includes(role)) return { ok: true };
  return {
    ok: false,
    refusal: refuse(
      "RBAC_DENIED",
      "role-not-writer",
      input.door,
      "member role is not a writer role",
      { role, orgSlug: input.orgSlug ?? null },
    ),
  };
}

/** Throwing form of {@link resolveWriterRole}; throws `PersonRefusalError`. */
export function requireWriterRole(input: WriterRoleInput): void {
  const r = resolveWriterRole(input);
  if (!r.ok) throw new PersonRefusalError(r.refusal);
}
