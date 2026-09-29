/**
 * @vantageos/cloud-identity — Organization-membership guard.
 * (See package.json "version" for the release this shipped in.)
 *
 * Closes the second measured 0.2.0 defect: the published package exposed no
 * "must belong to an organization" gate anywhere (`grep -rlE
 * "requireOrg|orgRequired|orgId" package/dist/*.js` returned no matches on
 * the 0.2.0 tarball). Absence of an organization must REFUSE, never fall
 * through to full access — the same defect class as the scope-filter fix in
 * `./scope-filter.ts`.
 *
 * The semantics are reused verbatim from a Convex implementation of the same
 * guard rather than reinvented — a second implementation of one authorization
 * check is a second chance to get it wrong. That original:
 *
 *   - takes a Convex `QueryCtx | MutationCtx | ActionCtx`
 *   - derives identity via `ctx.auth.getUserIdentity()`
 *   - throws when there is no session
 *   - throws when `identity.org_id` is not a non-empty string
 *   - returns the org id
 *
 * ADAPTATION (named per the brief's requirement to flag any semantic
 * deviation): this package is framework-agnostic and has no `ctx.auth`. The
 * caller pre-resolves whichever identity/bearer object it already has
 * (Clerk session identity for the human path, or the package's own
 * `TenantContext` — see `./tenancy-domain.ts` — for the machine/bearer path)
 * and passes it in as a `TenantSource`. The refuse-on-absence /
 * refuse-on-empty semantics are otherwise identical to the source function;
 * no other behavioural change was made.
 *
 * This is the membership half of the package's contract; tenant resolution,
 * row filtering and identifier validation are covered by
 * `getEffectiveTenantId`, `passesScopeFilter`/`scopeFilterList` and
 * `validateMasterBearer` respectively. Framework adapters wrap
 * `requireTenantId`; they must never reimplement its checks.
 */

import type { TenantContext } from "./tenancy-domain.js";

/**
 * Minimal shape of a resolved human-path session identity. Intentionally
 * framework-agnostic: the caller derives this from Clerk (or any other
 * session provider) before calling `requireTenantId` — this package never
 * imports a session SDK.
 */
export type SessionIdentity = {
  orgId?: string | null;
};

/**
 * Named deployment mode — 0.4.0. `cloud` requires an organization/workspace
 * on every request (the existing, unchanged `session`/`bearer` behaviour
 * below). `self-host` is single-tenant: the tenant id is DECLARED via
 * explicit configuration, never inferred from the absence of an
 * organization. See the `self-host` branch of `TenantSource` and
 * `requireTenantId` for the refuse-on-missing-config semantics.
 */
export type DeploymentMode = "cloud" | "self-host";

/**
 * Discriminated union covering both VantagePeers Cloud entry paths behind
 * one contract:
 *   - `session`: human path, via a connection/login provider (Clerk, etc.).
 *   - `bearer`: machine path, via a resolved, ALREADY-VERIFIED token
 *     (`TenantContext` — see `decodeUnverifiedBearer` / the planned signed-JWT
 *     verifier for how a `TenantContext` gets produced).
 *   - `self-host`: single-tenant path (0.4.0, additive). The tenant id is
 *     presented explicitly by configuration, not inferred: `requireTenantId`
 *     returns `tenantId` only when it is a non-empty string, and throws
 *     otherwise — a right is never granted by absence, here either.
 */
export type TenantSource =
  | { kind: "session"; identity: SessionIdentity | null | undefined }
  | { kind: "bearer"; context: TenantContext }
  | { kind: "self-host"; tenantId: string | null | undefined };

/**
 * Resolve the caller's tenant id, refusing when no organization/workspace is
 * attached — for EITHER entry path, behind one contract.
 *
 *   - `kind: "session"` and `identity` is null/undefined → throws
 *     ("Unauthenticated: no session.")
 *   - `kind: "session"` and `identity.orgId` is missing or empty → throws
 *     ("No active organization on this session...")
 *   - `kind: "bearer"` and `context.workspaceId` is missing or empty → throws
 *     ("No workspace on this bearer-resolved tenant context...")
 *   - otherwise → returns the tenant id (orgId, or workspaceId)
 *
 * A right is never granted by absence: every branch above refuses by
 * throwing, there is no fallback branch that returns a value when
 * organization/workspace information is missing.
 */
export function requireTenantId(source: TenantSource): string {
  if (source.kind === "session") {
    if (!source.identity) {
      throw new Error("Unauthenticated: no session.");
    }
    const orgId = source.identity.orgId;
    if (typeof orgId !== "string" || orgId.length === 0) {
      throw new Error(
        "No active organization on this session: select an organization before accessing agents.",
      );
    }
    return orgId;
  }

  if (source.kind === "self-host") {
    const tenantId = source.tenantId;
    if (typeof tenantId !== "string" || tenantId.length === 0) {
      throw new Error(
        "No tenant id configured for self-host mode: declare a tenantId explicitly — it is never inferred from absence.",
      );
    }
    return tenantId;
  }

  const workspaceId = source.context?.workspaceId;
  if (typeof workspaceId !== "string" || workspaceId.length === 0) {
    throw new Error(
      "No workspace on this bearer-resolved tenant context: the bearer must resolve to a non-empty workspaceId.",
    );
  }
  return workspaceId;
}

// ---------------------------------------------------------------------------
// 0.6.0 — the non-throwing sibling, for a public READ
// ---------------------------------------------------------------------------

/**
 * Why a caller resolved to no tenant. A closed set, so a consumer can branch
 * on content.
 */
export type TenantAbsenceReason =
  | "no-session"
  | "no-organization"
  | "no-workspace"
  | "no-tenant-configured";

/**
 * The typed absence. It is a NON-empty object carrying its own code: it can
 * never be mistaken for `[]`, `{}`, `null`, `0` or a zeroed aggregate, all of
 * which are what "an organization with nothing in it" looks like.
 */
export type TenantAbsence = {
  code: "TENANT_ABSENT";
  reason: TenantAbsenceReason;
};

/**
 * Result of `resolveTenantIdOrAbsent`. Branch on `present`; the two arms
 * share no field, so a consumer that forgets to branch gets a type error
 * rather than a silently-empty read.
 */
export type TenantResolution =
  | { present: true; tenantId: string }
  | { present: false; absence: TenantAbsence };

/**
 * The tenant id is OPAQUE. It is returned byte-for-byte as presented
 * (`orgId`, `workspaceId` or the self-host `tenantId`), never trimmed,
 * lower-cased or otherwise interpreted. This package never receives or
 * derives a slug or any human-facing name; each product maps its own notion
 * (an organization id, a workspace id) onto that string.
 *
 * NON-THROWING sibling of `requireTenantId`, for a public READ.
 *
 * `requireTenantId` throws on every branch, which is right for a WRITE
 * boundary and wrong for a subscribed read: a throw at a caller with no
 * organization crashes a mounted render, while a bare empty value is
 * byte-identical to "there is nothing". This function does neither: it
 * returns the tenant, or a typed absence that cannot be confused with an
 * empty result.
 *
 * Same `TenantSource` union, same refusal conditions as `requireTenantId` —
 * every input that makes it throw makes this return `{ present: false }`,
 * and every input it serves is served identically. Grants nothing that
 * `requireTenantId` refuses.
 */
export function resolveTenantIdOrAbsent(source: TenantSource): TenantResolution {
  const absent = (reason: TenantAbsenceReason): TenantResolution => ({
    present: false,
    absence: { code: "TENANT_ABSENT", reason },
  });

  if (source.kind === "session") {
    if (!source.identity) return absent("no-session");
    const orgId = source.identity.orgId;
    if (typeof orgId !== "string" || orgId.length === 0) {
      return absent("no-organization");
    }
    return { present: true, tenantId: orgId };
  }

  if (source.kind === "self-host") {
    const tenantId = source.tenantId;
    if (typeof tenantId !== "string" || tenantId.length === 0) {
      return absent("no-tenant-configured");
    }
    return { present: true, tenantId };
  }

  const workspaceId = source.context?.workspaceId;
  if (typeof workspaceId !== "string" || workspaceId.length === 0) {
    return absent("no-workspace");
  }
  return { present: true, tenantId: workspaceId };
}
