/**
 * @vantageos/cloud-identity 0.4.0 — RED-then-GREEN ledger for two additive
 * primitives:
 *
 *   1. Named deployment mode (`cloud` vs `self-host`) — `requireTenantId`
 *      gains a `{ kind: "self-host", tenantId }` branch that returns the
 *      DECLARED tenant id, and throws (never defaults) when it is missing.
 *      The existing `session`/`bearer` branches are untouched.
 *
 *   2. Human-path resolver — `resolveHumanIdentity` maps an already-resolved
 *      Clerk-shaped session to `{ tenant, subject, role }`, with `role` in
 *      the new `HumanAccountRole` union.
 *
 * Task: k17akq515
 * Mission: k17akq515
 * Orchestrator: Sigma — VantagePeers | 2026-08-13
 */

import { describe, it, expect } from "vitest";
import { requireTenantId } from "../src/org-guard.js";
import type { TenantSource, DeploymentMode } from "../src/org-guard.js";
import {
  resolveHumanIdentity,
  humanAccountRoleSchema,
} from "../src/human-path.js";

// ---------------------------------------------------------------------------
// (a) self-host mode: resolving the tenant returns the configured tenant id
// ---------------------------------------------------------------------------

describe("(a) self-host deployment mode", () => {
  it("requireTenantId returns the configured single tenant id", () => {
    const source: TenantSource = {
      kind: "self-host",
      tenantId: "the-one-tenant",
    };
    expect(requireTenantId(source)).toBe("the-one-tenant");
  });

  it("DeploymentMode names both modes explicitly", () => {
    const modes: DeploymentMode[] = ["cloud", "self-host"];
    expect(modes).toEqual(["cloud", "self-host"]);
  });
});

// ---------------------------------------------------------------------------
// (b) human path: resolved Clerk session -> { tenant, subject, role }
// ---------------------------------------------------------------------------

describe("(b) human path — resolveHumanIdentity", () => {
  it("maps a resolved Clerk session to { tenant, subject, role }", () => {
    const result = resolveHumanIdentity({
      orgId: "org_abc",
      userId: "user_123",
      orgRole: "org:admin",
    });
    expect(result).toEqual({
      tenant: "org_abc",
      subject: "user_123",
      role: "admin",
    });
    expect(humanAccountRoleSchema.parse(result.role)).toBe("admin");
  });

  it("maps every recognized Clerk org role", () => {
    expect(
      resolveHumanIdentity({
        orgId: "o",
        userId: "u",
        orgRole: "org:owner",
      }).role,
    ).toBe("owner");
    expect(
      resolveHumanIdentity({
        orgId: "o",
        userId: "u",
        orgRole: "org:member",
      }).role,
    ).toBe("member");
    expect(
      resolveHumanIdentity({
        orgId: "o",
        userId: "u",
        orgRole: "org:client",
      }).role,
    ).toBe("client");
  });

  it("throws on an unrecognized org role instead of defaulting", () => {
    expect(() =>
      resolveHumanIdentity({
        orgId: "org_abc",
        userId: "user_123",
        orgRole: "org:superuser",
      }),
    ).toThrow(/unrecognized organization role/i);
  });
});

// ---------------------------------------------------------------------------
// (c) BIPOLAR PROBE — cloud invariant #1123 still holds, AND self-host
//     never infers a tenant from absence.
// ---------------------------------------------------------------------------

describe("(c) BIPOLAR PROBE — 0.4.0 reopens nothing", () => {
  it("cloud mode: an org-less session identity is STILL REFUSED", () => {
    expect(() =>
      requireTenantId({ kind: "session", identity: { orgId: null } }),
    ).toThrow(/no active organization/i);
    expect(() =>
      requireTenantId({ kind: "session", identity: null }),
    ).toThrow(/no session/i);
  });

  it("cloud mode: an org-less human-path session is STILL REFUSED", () => {
    expect(() =>
      resolveHumanIdentity({ orgId: null, userId: "u", orgRole: "org:admin" }),
    ).toThrow(/no active organization/i);
  });

  it("self-host mode with NO configured tenant id THROWS — presented, never inferred", () => {
    expect(() =>
      requireTenantId({ kind: "self-host", tenantId: undefined }),
    ).toThrow(/no tenant id configured/i);
    expect(() =>
      requireTenantId({ kind: "self-host", tenantId: "" }),
    ).toThrow(/no tenant id configured/i);
  });
});
