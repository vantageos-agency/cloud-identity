import { describe, expect, it } from "vitest";
import {
  checkWorkspaceMatchesToken,
  IdentityRefusalError,
  requireWorkspaceMatchesToken,
} from "../src/index.js";

/**
 * The token/args workspace cross-check (0.37.0). The named scoped identity is
 * a token bound to workspace `ws_a` (a "crm-reader" token): not a maintenance
 * token, not a workspace creator. The check owns the comparison through
 * `isRowInTenant`: strict equality of two opaque ids, an empty side is never a
 * match.
 */
const TOKEN_A = { workspaceId: "ws_a" };

function reasonOf(fn: () => unknown): string | undefined {
  try {
    fn();
  } catch (e) {
    if (e instanceof IdentityRefusalError) return e.refusal.reason;
    throw e;
  }
  return undefined;
}

describe("requireWorkspaceMatchesToken: both directions", () => {
  it("a token bound to ws_a is admitted to args naming ws_a, and returns ws_a", () => {
    expect(requireWorkspaceMatchesToken(TOKEN_A, { workspaceId: "ws_a" })).toBe("ws_a");
  });

  it("a token bound to ws_a is refused args naming ws_b", () => {
    expect(reasonOf(() => requireWorkspaceMatchesToken(TOKEN_A, { workspaceId: "ws_b" }))).toBe(
      "workspace-mismatch",
    );
  });

  it("the refusal carries its code and the consumer's door, never the ids", () => {
    const r = checkWorkspaceMatchesToken(TOKEN_A, { workspaceId: "ws_b" }, "crm.http");
    expect(r.ok).toBe(false);
    if (!r.ok) {
      expect(r.refusal).toMatchObject({ code: "RBAC_DENIED", reason: "workspace-mismatch", door: "crm.http" });
      expect(r.refusal.detail).not.toContain("ws_a");
      expect(r.refusal.detail).not.toContain("ws_b");
    }
  });
});

describe("requireWorkspaceMatchesToken: omission is never broader than presentation", () => {
  it("omitted args.workspaceId resolves to the token's own workspace, exactly as presenting it would", () => {
    expect(requireWorkspaceMatchesToken(TOKEN_A, {})).toBe("ws_a");
    expect(requireWorkspaceMatchesToken(TOKEN_A, { workspaceId: null })).toBe("ws_a");
    expect(requireWorkspaceMatchesToken(TOKEN_A, undefined)).toBe("ws_a");
  });

  it("a non-string or empty presented workspaceId is a mismatch, never a pass", () => {
    for (const workspaceId of [7, "", ["ws_a"], { toString: () => "ws_a" }, true]) {
      expect(reasonOf(() => requireWorkspaceMatchesToken(TOKEN_A, { workspaceId }))).toBe("workspace-mismatch");
    }
  });

  it("args that are not an object are a mismatch", () => {
    for (const args of ["ws_a", 7, ["ws_a"]]) {
      expect(reasonOf(() => requireWorkspaceMatchesToken(TOKEN_A, args))).toBe("workspace-mismatch");
    }
  });

  it("a token with no usable workspace binding matches nothing, not even an omitted workspace", () => {
    for (const token of [{ workspaceId: "" }, { workspaceId: 7 }, {}, null, undefined]) {
      expect(reasonOf(() => requireWorkspaceMatchesToken(token, { workspaceId: "ws_a" }))).toBe(
        "workspace-binding-missing",
      );
      expect(reasonOf(() => requireWorkspaceMatchesToken(token, {}))).toBe("workspace-binding-missing");
    }
  });

  it("matching is exact: case and whitespace differences are mismatches", () => {
    for (const workspaceId of ["WS_A", " ws_a", "ws_a "]) {
      expect(reasonOf(() => requireWorkspaceMatchesToken(TOKEN_A, { workspaceId }))).toBe("workspace-mismatch");
    }
  });
});
