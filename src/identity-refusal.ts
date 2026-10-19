/**
 * Typed refusal shared by the 0.10.0 primitives (role policy, membership,
 * org-admin proof, namespace write, secret comparison), the 0.11.0
 * principal-by-id resolver and target check, the 0.12.0 org-admin check, and the 0.13.0 list-membership check.
 *
 * A refusal is a value carrying its own code, reason and door, so a caller
 * branches on content rather than on the mere presence of an exception, and an
 * absence can never be mistaken for a refusal. It carries no credential.
 *
 * Mirrors the shape of `PersonRefusal` / `PersonRefusalError` on purpose: same
 * `code`/`reason`/`door`/`detail` fields, same `ERROR: detail (reason, door)`
 * message form. It is a separate type only because `PersonRefusalCode` is a
 * closed vocabulary for the person path.
 */

export type IdentityRefusalCode = "RBAC_DENIED" | "CREDENTIAL_REFUSED";

export type IdentityRefusalReason =
  // role policy
  | "unknown-role"
  | "unknown-minimum-role"
  | "invalid-role-order"
  | "role-below-minimum"
  | "role-claim-absent"
  | "role-claim-unmapped"
  | "invalid-role-mapping"
  // membership and tenant
  | "membership-invalid-input"
  | "membership-lookup-failed"
  | "membership-not-found"
  | "membership-record-invalid"
  | "membership-inactive"
  | "other-organisation"
  // org-admin proof
  | "no-verified-organisation"
  | "no-verified-subject"
  | "role-not-admin"
  // namespace write
  | "namespace-invalid"
  | "no-write-prefixes"
  | "namespace-write-denied"
  // synchronous secret comparison
  | "secret-not-configured"
  | "secret-mismatch"
  // principal by id (0.11.0)
  | "credential-invalid"
  | "principal-lookup-failed"
  | "principal-not-found"
  | "principal-record-invalid"
  | "principal-inactive"
  | "organisation-not-active"
  | "reserved-fleet-scope"
  | "acting-agent-other-organisation"
  | "target-unstamped"
  | "target-other-organisation"
  | "target-owner-mismatch"
  // org admin by id (0.12.0)
  | "principal-not-a-person"
  // list membership by agent ID (0.13.0)
  | "list-absent"
  | "list-empty"
  | "principal-not-an-agent"
  | "principal-not-listed"
  // standing of a resolved org scope (0.20.0)
  | "scope-not-resolved"
  | "standing-not-allowed"
  // person scope inside an organisation
  | "person-scope-absent"
  | "person-scope-empty"
  | "person-scope-grant-unreasoned"
  | "person-scope-malformed"
  | "person-scope-lookup-failed"
  // agent bound to its human owner
  | "agent-owner-mismatch"
  | "agent-owner-not-member"
  | "agent-not-owned"
  // resource server: MCP access token (0.15.0)
  | "bearer-missing"
  | "bearer-malformed"
  | "token-invalid"
  | "jwks-unavailable"
  // organisation by ID (0.16.0)
  | "org-mapping-lookup-failed"
  | "org-mapping-not-found"
  | "org-mapping-record-invalid"
  // support access grant (0.21.5)
  | "support-grant-absent"
  | "support-grant-expired"
  | "support-grant-revoked"
  | "support-grant-mismatch"
  | "support-grant-own-organisation"
  | "support-grant-not-a-person"
  | "support-grant-invalid"
  | "support-grant-lookup-failed"
  // Clerk membership webhook (0.21.6)
  | "webhook-secret-invalid"
  | "webhook-headers-missing"
  | "webhook-timestamp-out-of-window"
  | "webhook-signature-mismatch"
  | "membership-event-invalid";

export type IdentityRefusal = {
  code: IdentityRefusalCode;
  reason: IdentityRefusalReason;
  /** The consumer's own name for the entry point that refused. */
  door: string;
  /** One sentence, safe to show to the caller. Never a credential. */
  detail: string;
};

/** Thrown by the asserting forms. Carries the typed refusal untouched. */
export class IdentityRefusalError extends Error {
  readonly refusal: IdentityRefusal;
  constructor(refusal: IdentityRefusal) {
    super(`${refusal.code}: ${refusal.detail} (${refusal.reason}, ${refusal.door})`);
    this.name = "IdentityRefusalError";
    this.refusal = refusal;
  }
}

/** @internal Build a refusal. Not exported from the package. */
export function refusal(
  code: IdentityRefusalCode,
  reason: IdentityRefusalReason,
  door: string,
  detail: string,
): IdentityRefusal {
  return { code, reason, door, detail };
}
