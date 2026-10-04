/**
 * Typed refusal shared by the 0.10.0 primitives (role policy, membership,
 * org-admin proof, namespace write, secret comparison).
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
  | "role-not-admin"
  // namespace write
  | "namespace-invalid"
  | "no-write-prefixes"
  | "namespace-write-denied"
  // synchronous secret comparison
  | "secret-not-configured"
  | "secret-mismatch";

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
