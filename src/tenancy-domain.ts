/**
 * @vantageos/cloud-identity 0.2.0 — Domain-tenancy layer.
 *
 * Additive-only: does not modify any 0.1.0 exports.
 *
 * Provides:
 *   - WorkspaceRole literal union + Zod schema
 *   - Workspace type + Zod schema
 *   - WorkspaceMember type + Zod schema
 *   - TenantContext type + Zod schema
 *   - ScopeViolationError class (code: "SCOPE_VIOLATION")
 *   - getEffectiveTenantId(ctx, args) — multi-tenant isolation guard
 *   - resolveBearer(token) — parse a bearer token into { userId, workspaceId, roles[] }
 *
 * Task: k177hejb4tc5em5p70m9hxwn3x88kyp4
 * Mission: k57b4t2q VR Cloud MVP Day 100
 * Orchestrator: Sigma — VantagePeers | 2026-06-13
 */

import { z } from "zod";

// ---------------------------------------------------------------------------
// WorkspaceRole
// ---------------------------------------------------------------------------

export const workspaceRoleSchema = z.enum(["Admin", "Editor", "Viewer"]);
export type WorkspaceRole = z.infer<typeof workspaceRoleSchema>;

// ---------------------------------------------------------------------------
// Workspace
// ---------------------------------------------------------------------------

export const workspaceSchema = z.object({
  id: z.string().min(1),
  name: z.string().min(1),
  createdAt: z.number(),
  metadata: z.record(z.string(), z.unknown()).optional(),
});
export type Workspace = z.infer<typeof workspaceSchema>;

// ---------------------------------------------------------------------------
// WorkspaceMember
// ---------------------------------------------------------------------------

export const workspaceMemberSchema = z.object({
  userId: z.string().min(1),
  workspaceId: z.string().min(1),
  role: workspaceRoleSchema,
  joinedAt: z.number(),
});
export type WorkspaceMember = z.infer<typeof workspaceMemberSchema>;

// ---------------------------------------------------------------------------
// TenantContext
// ---------------------------------------------------------------------------

export const tenantContextSchema = z.object({
  workspaceId: z.string().min(1),
  userId: z.string().min(1),
  roles: z.array(workspaceRoleSchema),
});
export type TenantContext = z.infer<typeof tenantContextSchema>;

// ---------------------------------------------------------------------------
// ScopeViolationError
// ---------------------------------------------------------------------------

export interface ScopeViolationPayload {
  requestedTenantId: string;
  contextTenantId: string;
  reason: string;
}

/**
 * Thrown by `getEffectiveTenantId` when `args.workspaceId` does not match the
 * workspaceId encoded in the bearer-resolved `TenantContext`. This error is the
 * canonical cross-tenant isolation signal across the VantagePeers Cloud fleet.
 *
 * Callers MUST translate this to a 403 or MCP permission-denied — never 404.
 */
export class ScopeViolationError extends Error {
  readonly code = "SCOPE_VIOLATION" as const;
  readonly payload: ScopeViolationPayload;

  constructor(payload: ScopeViolationPayload) {
    super(
      `SCOPE_VIOLATION: requested tenant "${payload.requestedTenantId}" does not match context tenant "${payload.contextTenantId}" — ${payload.reason}`,
    );
    this.name = "ScopeViolationError";
    this.payload = payload;
    // Restore prototype chain (required for instanceof checks in transpiled targets).
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

// ---------------------------------------------------------------------------
// getEffectiveTenantId
// ---------------------------------------------------------------------------

/**
 * Resolve the effective tenant workspace ID from a `TenantContext` + request args.
 *
 * If `args.workspaceId` differs from the context's `workspaceId` (derived from
 * the bearer token), a `ScopeViolationError` is thrown immediately.
 *
 * This is the primary multi-tenant isolation gate — call it at the top of every
 * MCP tool handler that accepts a `workspaceId` argument.
 *
 * @example
 * ```ts
 * const tenantId = getEffectiveTenantId(ctx, args);
 * // safe to use tenantId for DB queries — caller's scope is verified
 * ```
 */
export function getEffectiveTenantId(
  ctx: TenantContext,
  args: { workspaceId: string },
): string {
  if (args.workspaceId !== ctx.workspaceId) {
    throw new ScopeViolationError({
      requestedTenantId: args.workspaceId,
      contextTenantId: ctx.workspaceId,
      reason: "args.workspaceId does not match bearer-resolved context workspaceId",
    });
  }
  return ctx.workspaceId;
}

// ---------------------------------------------------------------------------
// resolveBearer
// ---------------------------------------------------------------------------

/**
 * Decode and validate a bearer token into `{ userId, workspaceId, roles[] }`.
 *
 * Token format: `base64(JSON({ userId, workspaceId, roles: WorkspaceRole[] }))`.
 *
 * This is intentionally a lightweight, framework-agnostic implementation —
 * production callers will substitute a signed JWT or opaque-token lookup
 * against a Convex tenancy table. The contract (shape + Zod validation) is
 * stable; the decode mechanism can be swapped without touching the API.
 *
 * Consistent with `validateMasterBearer` in that it treats ANY decode/shape
 * failure as a hard throw (not a soft `ok: false`) because the caller has
 * committed to multi-tenant isolation and should not silently degrade.
 */

const bearerPayloadSchema = z.object({
  userId: z.string().min(1),
  workspaceId: z.string().min(1),
  roles: z.array(workspaceRoleSchema),
});

export type BearerPayload = z.infer<typeof bearerPayloadSchema>;

export async function resolveBearer(token: string): Promise<BearerPayload> {
  let raw: string;
  try {
    raw = Buffer.from(token, "base64").toString("utf-8");
  } catch {
    throw new Error(`resolveBearer: failed to base64-decode token`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(`resolveBearer: token payload is not valid JSON`);
  }

  // Zod parse — throws ZodError on schema violations (missing fields, bad roles).
  return bearerPayloadSchema.parse(parsed);
}
