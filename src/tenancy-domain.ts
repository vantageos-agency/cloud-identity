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
 *   - decodeUnverifiedBearer(token) — DECODE-ONLY helper, NOT authentication.
 *     The decoded payload is attacker-controlled. Production code MUST use a
 *     signed JWT or opaque-token lookup (planned: 0.3.0) before treating the
 *     payload as a trust boundary.
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
// decodeUnverifiedBearer
// ---------------------------------------------------------------------------

/**
 * @security ⚠️ DECODE-ONLY. NOT AUTHENTICATION. NOT A TRUST BOUNDARY.
 *
 * Decodes a `base64(JSON({ userId, workspaceId, roles[] }))` payload and
 * validates its SHAPE with Zod. It performs NO signature verification, NO
 * issuer check, NO expiry check, NO replay-attack protection. The decoded
 * payload is attacker-controlled and MUST NOT be used as the source of
 * truth for multi-tenant isolation.
 *
 * Forgery example: any attacker producing
 *   base64(JSON({ userId:"x", workspaceId:"victim-org", roles:["Admin"] }))
 * passes this function. Treating the returned `workspaceId` as authoritative
 * — for example feeding it into `getEffectiveTenantId` as the trusted
 * `ctx.workspaceId` — silently grants cross-tenant access.
 *
 * Use only as:
 *   - test fixture / harness helper
 *   - decoder for a bearer that was ALREADY verified by an upstream signed-JWT
 *     middleware (the production trust boundary)
 *
 * For the production trust boundary, callers MUST substitute a signed JWT
 * (planned export in 0.3.0) or an opaque-token lookup against a Convex
 * tenancy table.
 *
 * Renamed from `resolveBearer` (0.2.0 pre-release) to make the lack of
 * verification impossible to miss at the call-site.
 */

const bearerPayloadSchema = z.object({
  userId: z.string().min(1),
  workspaceId: z.string().min(1),
  roles: z.array(workspaceRoleSchema),
});

export type BearerPayload = z.infer<typeof bearerPayloadSchema>;

export async function decodeUnverifiedBearer(
  token: string,
): Promise<BearerPayload> {
  let raw: string;
  try {
    raw = Buffer.from(token, "base64").toString("utf-8");
  } catch {
    throw new Error(`decodeUnverifiedBearer: failed to base64-decode token`);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new Error(
      `decodeUnverifiedBearer: token payload is not valid JSON`,
    );
  }

  // Zod parse — throws ZodError on schema violations (missing fields, bad roles).
  return bearerPayloadSchema.parse(parsed);
}
