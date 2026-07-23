/**
 * @vantageos/cloud-identity 0.3.0 — Organization-membership guard.
 *
 * Closes the second measured 0.2.0 defect: the published package exposed no
 * "must belong to an organization" gate anywhere (`grep -rlE
 * "requireOrg|orgRequired|orgId" package/dist/*.js` returned no matches on
 * the 0.2.0 tarball). Absence of an organization must REFUSE, never fall
 * through to full access — the same defect class as the scope-filter fix in
 * `./scope-filter.ts`.
 *
 * Hoisted (reused, not reimplemented) from evevantage's
 * `convex/lib/auth.ts::requireOrgId`
 * (commit 1c102132ac5832573e58145de43b7338ba5d0b00). The source function:
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
 * This is one of the two membership/tenant-facing surfaces the 2026-07-23
 * scope avenant asks for behind a single contract (the other three — tenant
 * resolution + row filtering + identifier validation — are already covered
 * by `getEffectiveTenantId`, `passesScopeFilter`/`scopeFilterList`, and
 * `validateMasterBearer` respectively). Framework adapters (Convex, Hono,
 * etc.) wrap `requireTenantId`; they must never reimplement its checks.
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
 * Discriminated union covering both VantagePeers Cloud entry paths behind
 * one contract:
 *   - `session`: human path, via a connection/login provider (Clerk, etc.).
 *   - `bearer`: machine path, via a resolved, ALREADY-VERIFIED token
 *     (`TenantContext` — see `decodeUnverifiedBearer` / the planned signed-JWT
 *     verifier for how a `TenantContext` gets produced).
 */
export type TenantSource =
  | { kind: "session"; identity: SessionIdentity | null | undefined }
  | { kind: "bearer"; context: TenantContext };

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

  const workspaceId = source.context?.workspaceId;
  if (typeof workspaceId !== "string" || workspaceId.length === 0) {
    throw new Error(
      "No workspace on this bearer-resolved tenant context: the bearer must resolve to a non-empty workspaceId.",
    );
  }
  return workspaceId;
}
