/**
 * @vantageos/cloud-identity 0.3.0 — RED-then-GREEN ledger for two closed defects:
 *
 *   1. `passesScopeFilter` (and friends) granted wildcard access when the
 *      caller omitted `oauthCtx` entirely. A right must never be granted by
 *      absence. Omission now REFUSES at runtime (defense-in-depth) AND
 *      breaks at compile time (`oauthCtx: OAuthCtx`, no `| undefined`). The
 *      old wildcard behaviour is still reachable, but only by the caller
 *      explicitly importing and passing `LEGACY_WILDCARD_CTX`.
 *
 *   2. No organization-membership guard existed anywhere in the published
 *      package. `requireTenantId` closes it — hoisted (reused, not
 *      reimplemented) from evevantage's `convex/lib/auth.ts::requireOrgId`
 *      (commit 1c102132ac5832573e58145de43b7338ba5d0b00), adapted to be
 *      framework-agnostic (no `ctx.auth.getUserIdentity()` — the caller
 *      pre-resolves the identity/bearer and passes it as a `TenantSource`).
 *
 * Task: k1733eqbv7d80f0azqtsp00fvh8b3bkv
 * Mission: k57fhn28prpf167ne5x6p30hex8b2hcd
 * Orchestrator: Sigma — VantagePeers | 2026-07-23
 */

import { describe, it, expect } from "vitest";
import {
  passesScopeFilter,
  scopeFilterList,
  scopeFilterGet,
  isWildcardScope,
  LEGACY_WILDCARD_CTX,
} from "../src/scope-filter.js";
import { requireTenantId } from "../src/org-guard.js";
import type { OAuthCtx } from "../src/types.js";
import type { TenantContext } from "../src/tenancy-domain.js";

const scopedCtx: OAuthCtx = {
  scope: "tenant",
  fromAllowList: ["alice"],
  namespaceReadPrefixes: ["orchestrator/alpha"],
  namespaceWritePrefixes: [],
};

// ---------------------------------------------------------------------------
// MUST_BLOCK — context omitted entirely (the measured 0.2.0 defect)
// ---------------------------------------------------------------------------

describe("MUST_BLOCK — omitted oauthCtx no longer grants wildcard access", () => {
  it("passesScopeFilter(undefined, row) refuses instead of passing", () => {
    // `as any` bypasses the (now mandatory) TS signature to exercise the
    // runtime defense-in-depth guard directly — see item 7 of the PR
    // evidence for the compile-time break against a typed caller.
    expect(() =>
      passesScopeFilter(undefined as unknown as OAuthCtx, {
        createdBy: "stranger",
        namespace: "anywhere",
      }),
    ).toThrow(/oauthCtx is required/i);
  });

  it("scopeFilterList(undefined, rows) refuses instead of passing everything", () => {
    expect(() =>
      scopeFilterList(undefined as unknown as OAuthCtx, [
        { createdBy: "stranger", namespace: "anywhere" },
      ]),
    ).toThrow(/oauthCtx is required/i);
  });

  it("scopeFilterGet(undefined, row) refuses instead of passing", () => {
    expect(() =>
      scopeFilterGet(undefined as unknown as OAuthCtx, {
        createdBy: "stranger",
        namespace: "anywhere",
      }),
    ).toThrow(/oauthCtx is required/i);
  });

  it("isWildcardScope(undefined) refuses instead of reporting wildcard", () => {
    expect(() => isWildcardScope(undefined as unknown as OAuthCtx)).toThrow(
      /oauthCtx is required/i,
    );
  });
});

// ---------------------------------------------------------------------------
// MUST_BLOCK — identity without organization (requireTenantId)
// ---------------------------------------------------------------------------

describe("MUST_BLOCK — requireTenantId refuses identity without organization", () => {
  it("throws when session identity is null (no session)", () => {
    expect(() =>
      requireTenantId({ kind: "session", identity: null }),
    ).toThrow(/no session/i);
  });

  it("throws when session identity has no orgId", () => {
    expect(() =>
      requireTenantId({ kind: "session", identity: {} }),
    ).toThrow(/no active organization/i);
  });

  it("throws when session identity has an empty-string orgId", () => {
    expect(() =>
      requireTenantId({ kind: "session", identity: { orgId: "" } }),
    ).toThrow(/no active organization/i);
  });

  it("throws when bearer-resolved tenant context has an empty workspaceId", () => {
    const ctx = { workspaceId: "", userId: "u1", roles: [] } as TenantContext;
    expect(() => requireTenantId({ kind: "bearer", context: ctx })).toThrow(
      /no workspace/i,
    );
  });
});

// ---------------------------------------------------------------------------
// MUST_PASS — legitimate paths keep working
// ---------------------------------------------------------------------------

describe("MUST_PASS — legitimate callers keep passing", () => {
  it("LEGACY_WILDCARD_CTX, requested explicitly, still passes everything", () => {
    expect(
      passesScopeFilter(LEGACY_WILDCARD_CTX, {
        createdBy: "stranger",
        namespace: "anywhere",
      }),
    ).toBe(true);
    expect(isWildcardScope(LEGACY_WILDCARD_CTX)).toBe(true);
  });

  it("a fully-specified tenant context keeps normal allow/deny semantics", () => {
    expect(
      passesScopeFilter(scopedCtx, { createdBy: "alice", namespace: "x/y" }),
    ).toBe(true);
    expect(
      passesScopeFilter(scopedCtx, {
        createdBy: "bob",
        namespace: "orchestrator/beta",
      }),
    ).toBe(false);
  });

  it("requireTenantId returns orgId for a session with an active organization", () => {
    expect(
      requireTenantId({ kind: "session", identity: { orgId: "org_123" } }),
    ).toBe("org_123");
  });

  it("requireTenantId returns workspaceId for a bearer-resolved tenant context", () => {
    const ctx: TenantContext = {
      workspaceId: "ws_abc",
      userId: "u1",
      roles: ["Admin"],
    };
    expect(requireTenantId({ kind: "bearer", context: ctx })).toBe("ws_abc");
  });
});
