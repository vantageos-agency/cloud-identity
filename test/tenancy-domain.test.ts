/**
 * @vantageos/cloud-identity 0.2.0 — Tenancy domain layer tests.
 *
 * TDD RED phase: these tests reference symbols that do not yet exist in src/.
 * All suites are expected to fail at module-resolution or type-import time.
 *
 * Task: k177hejb4tc5em5p70m9hxwn3x88kyp4
 * Mission: k57b4t2q VR Cloud MVP Day 100
 */

import { describe, it, expect } from "vitest";
import {
  workspaceSchema,
  workspaceMemberSchema,
  workspaceRoleSchema,
  tenantContextSchema,
  ScopeViolationError,
  getEffectiveTenantId,
  decodeUnverifiedBearer,
} from "../src/tenancy-domain.js";
import type {
  Workspace,
  WorkspaceMember,
  WorkspaceRole,
  TenantContext,
} from "../src/tenancy-domain.js";

// ---------------------------------------------------------------------------
// Zod schema tests — WorkspaceRole
// ---------------------------------------------------------------------------

describe("workspaceRoleSchema", () => {
  it("accepts Admin", () => {
    expect(workspaceRoleSchema.parse("Admin")).toBe("Admin");
  });
  it("accepts Editor", () => {
    expect(workspaceRoleSchema.parse("Editor")).toBe("Editor");
  });
  it("accepts Viewer", () => {
    expect(workspaceRoleSchema.parse("Viewer")).toBe("Viewer");
  });
  it("rejects unknown role", () => {
    expect(() => workspaceRoleSchema.parse("Owner")).toThrow();
  });
  it("rejects empty string", () => {
    expect(() => workspaceRoleSchema.parse("")).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Zod schema tests — Workspace
// ---------------------------------------------------------------------------

describe("workspaceSchema", () => {
  it("parses a valid workspace", () => {
    const ws: Workspace = workspaceSchema.parse({
      id: "ws_abc123",
      name: "ACME Corp",
      createdAt: 1718000000000,
    });
    expect(ws.id).toBe("ws_abc123");
    expect(ws.name).toBe("ACME Corp");
    expect(ws.createdAt).toBe(1718000000000);
  });

  it("rejects missing id", () => {
    expect(() =>
      workspaceSchema.parse({ name: "X", createdAt: 0 }),
    ).toThrow();
  });

  it("rejects missing name", () => {
    expect(() =>
      workspaceSchema.parse({ id: "ws_1", createdAt: 0 }),
    ).toThrow();
  });

  it("accepts optional metadata", () => {
    const ws: Workspace = workspaceSchema.parse({
      id: "ws_2",
      name: "Beta",
      createdAt: 1718000000000,
      metadata: { plan: "pro" },
    });
    expect(ws.metadata?.plan).toBe("pro");
  });
});

// ---------------------------------------------------------------------------
// Zod schema tests — WorkspaceMember
// ---------------------------------------------------------------------------

describe("workspaceMemberSchema", () => {
  it("parses a valid member", () => {
    const m: WorkspaceMember = workspaceMemberSchema.parse({
      userId: "user_alice",
      workspaceId: "ws_abc",
      role: "Admin",
      joinedAt: 1718000000000,
    });
    expect(m.userId).toBe("user_alice");
    expect(m.role).toBe("Admin");
  });

  it("rejects invalid role in member", () => {
    expect(() =>
      workspaceMemberSchema.parse({
        userId: "u",
        workspaceId: "ws",
        role: "SuperAdmin",
        joinedAt: 0,
      }),
    ).toThrow();
  });

  it("rejects missing workspaceId", () => {
    expect(() =>
      workspaceMemberSchema.parse({
        userId: "u",
        role: "Viewer",
        joinedAt: 0,
      }),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// Zod schema tests — TenantContext
// ---------------------------------------------------------------------------

describe("tenantContextSchema", () => {
  it("parses a full tenant context", () => {
    const ctx: TenantContext = tenantContextSchema.parse({
      workspaceId: "ws_xyz",
      userId: "user_bob",
      roles: ["Admin", "Viewer"],
    });
    expect(ctx.workspaceId).toBe("ws_xyz");
    expect(ctx.roles).toContain("Admin");
  });

  it("accepts empty roles array", () => {
    const ctx = tenantContextSchema.parse({
      workspaceId: "ws_1",
      userId: "u_1",
      roles: [],
    });
    expect(ctx.roles).toHaveLength(0);
  });

  it("rejects missing workspaceId", () => {
    expect(() =>
      tenantContextSchema.parse({ userId: "u", roles: ["Viewer"] }),
    ).toThrow();
  });

  it("rejects invalid role in roles array", () => {
    expect(() =>
      tenantContextSchema.parse({
        workspaceId: "ws",
        userId: "u",
        roles: ["Hacker"],
      }),
    ).toThrow();
  });
});

// ---------------------------------------------------------------------------
// ScopeViolationError
// ---------------------------------------------------------------------------

describe("ScopeViolationError", () => {
  it("is an Error subclass", () => {
    const err = new ScopeViolationError({
      requestedTenantId: "ws_a",
      contextTenantId: "ws_b",
      reason: "tenant mismatch",
    });
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(ScopeViolationError);
  });

  it("has code SCOPE_VIOLATION", () => {
    const err = new ScopeViolationError({
      requestedTenantId: "ws_a",
      contextTenantId: "ws_b",
      reason: "tenant mismatch",
    });
    expect(err.code).toBe("SCOPE_VIOLATION");
  });

  it("exposes the payload fields", () => {
    const err = new ScopeViolationError({
      requestedTenantId: "ws_a",
      contextTenantId: "ws_b",
      reason: "cross-tenant write rejected",
    });
    expect(err.payload.requestedTenantId).toBe("ws_a");
    expect(err.payload.contextTenantId).toBe("ws_b");
    expect(err.payload.reason).toBe("cross-tenant write rejected");
  });

  it("has a descriptive message", () => {
    const err = new ScopeViolationError({
      requestedTenantId: "ws_1",
      contextTenantId: "ws_2",
      reason: "mismatch",
    });
    expect(err.message).toContain("SCOPE_VIOLATION");
  });

  it("name is ScopeViolationError", () => {
    const err = new ScopeViolationError({
      requestedTenantId: "ws_x",
      contextTenantId: "ws_y",
      reason: "test",
    });
    expect(err.name).toBe("ScopeViolationError");
  });
});

// ---------------------------------------------------------------------------
// getEffectiveTenantId
// ---------------------------------------------------------------------------

const makeCtx = (workspaceId: string): TenantContext => ({
  workspaceId,
  userId: "user_test",
  roles: ["Viewer"],
});

describe("getEffectiveTenantId", () => {
  it("returns ctx.workspaceId when args.workspaceId matches ctx", () => {
    const result = getEffectiveTenantId(makeCtx("ws_alpha"), {
      workspaceId: "ws_alpha",
    });
    expect(result).toBe("ws_alpha");
  });

  it("throws ScopeViolationError when args.workspaceId differs from ctx (scenario 1 — A vs B)", () => {
    expect(() =>
      getEffectiveTenantId(makeCtx("ws_tenant_a"), { workspaceId: "ws_tenant_b" }),
    ).toThrow(ScopeViolationError);
  });

  it("throws ScopeViolationError — scenario 2: attacker requests another org's workspace", () => {
    expect(() =>
      getEffectiveTenantId(makeCtx("ws_legit"), { workspaceId: "ws_evil_corp" }),
    ).toThrow(ScopeViolationError);
  });

  it("throws ScopeViolationError — scenario 3: empty string mismatch is caught", () => {
    expect(() =>
      getEffectiveTenantId(makeCtx("ws_abc"), { workspaceId: "" }),
    ).toThrow(ScopeViolationError);
  });

  it("thrown ScopeViolationError carries correct contextTenantId + requestedTenantId", () => {
    let thrown: ScopeViolationError | undefined;
    try {
      getEffectiveTenantId(makeCtx("ws_real"), { workspaceId: "ws_fake" });
    } catch (e) {
      if (e instanceof ScopeViolationError) thrown = e;
    }
    expect(thrown).toBeDefined();
    expect(thrown!.payload.contextTenantId).toBe("ws_real");
    expect(thrown!.payload.requestedTenantId).toBe("ws_fake");
  });

  it("valid case — exact match resolves correctly", () => {
    const result = getEffectiveTenantId(
      { workspaceId: "ws_prod_42", userId: "u_1", roles: ["Admin"] },
      { workspaceId: "ws_prod_42" },
    );
    expect(result).toBe("ws_prod_42");
  });
});

// ---------------------------------------------------------------------------
// decodeUnverifiedBearer
// ---------------------------------------------------------------------------

describe("decodeUnverifiedBearer", () => {
  it("resolves a well-formed bearer token to userId + workspaceId + roles", async () => {
    // The token format for decodeUnverifiedBearer is: base64(JSON({userId, workspaceId, roles}))
    const payload = {
      userId: "user_charlie",
      workspaceId: "ws_delta",
      roles: ["Admin", "Editor"] as WorkspaceRole[],
    };
    const token = Buffer.from(JSON.stringify(payload)).toString("base64");
    const result = await decodeUnverifiedBearer(token);
    expect(result.userId).toBe("user_charlie");
    expect(result.workspaceId).toBe("ws_delta");
    expect(result.roles).toContain("Admin");
    expect(result.roles).toContain("Editor");
  });

  it("throws on malformed token (not valid base64 JSON)", async () => {
    await expect(decodeUnverifiedBearer("not-valid-base64!##")).rejects.toThrow();
  });

  it("throws when payload is missing required workspaceId", async () => {
    const payload = { userId: "u", roles: ["Viewer"] };
    const token = Buffer.from(JSON.stringify(payload)).toString("base64");
    await expect(decodeUnverifiedBearer(token)).rejects.toThrow();
  });

  it("throws when roles contain invalid value", async () => {
    const payload = { userId: "u", workspaceId: "ws_x", roles: ["God"] };
    const token = Buffer.from(JSON.stringify(payload)).toString("base64");
    await expect(decodeUnverifiedBearer(token)).rejects.toThrow();
  });

  it("resolves empty roles array", async () => {
    const payload = { userId: "u2", workspaceId: "ws_empty", roles: [] };
    const token = Buffer.from(JSON.stringify(payload)).toString("base64");
    const result = await decodeUnverifiedBearer(token);
    expect(result.roles).toHaveLength(0);
  });
});
