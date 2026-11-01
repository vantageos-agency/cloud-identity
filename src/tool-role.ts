/**
 * Agent tool roles: the one pure decision every MCP server calls, for both
 * `tools/list` (filter) and `tools/call` (refuse).
 *
 * Spec: ElPi-Corp fab6c779, "Agent tool roles", rules 1, 2, 3, 5 and 6.
 *
 *   - A role is data owned by one organisation:
 *     `{ roleId, orgClerkId, domains: [{ domain, read, write }], add, remove }`.
 *   - A tool declares `{ toolId, domain, mode }` (toolId = the MCP tool name), `mode` exactly "read" or "write".
 *   - Grant order: the domain grant (`read` for a read tool, `write` for a write
 *     tool), then `add` grants single tools outside it, then `remove` withdraws
 *     single tools. Remove wins.
 *   - Deny by default. Every deny branch carries its own reason; a role-store
 *     read that failed is the distinct code `TOOL_ROLE_UNRESOLVED`, never a
 *     fall-through to "all tools".
 *
 * Pure: no storage, no I/O, no clock. The role is passed in ALREADY RESOLVED
 * (the consumer resolved it from the verified credential); the caller is the
 * package's resolved org scope, read through `scopeStanding`, so the
 * organisation compared is the caller's verified permanent ID (`orgClerkId`),
 * never a label and never a free argument.
 */

import { type StandingScope, scopeStanding } from "./scope-standing.js";

export type ToolRoleRefusalCode = "TOOL_ROLE_DENIED" | "TOOL_ROLE_UNRESOLVED";

export type ToolRoleRefusalReason =
  // the role-store read failed (TOOL_ROLE_UNRESOLVED)
  | "role-store-failed"
  // the agent has no role
  | "no-role"
  // the agent's role no longer exists
  | "role-not-found"
  // the resolved role (or the lookup) is not well formed
  | "role-invalid"
  // the caller is not an organisation member with a permanent ID
  | "caller-not-resolved"
  // the role belongs to another organisation (compared by clerkOrgId)
  | "other-organisation"
  // the tool has no declaration (no toolId or no domain)
  | "tool-undeclared"
  // the tool's mode is not exactly "read" or "write"
  | "tool-mode-invalid"
  // the tool is in the role's `remove` list
  | "tool-removed"
  // the tool's domain is not granted for the tool's mode
  | "domain-not-granted"
  // the domain is granted for read and the tool is a write tool
  | "write-on-read-grant";

/**
 * Same `code`/`reason`/`door`/`detail` fields as `IdentityRefusal`. A separate
 * type only because the tool-role codes are their own closed vocabulary.
 */
export type ToolRoleRefusal = {
  code: ToolRoleRefusalCode;
  reason: ToolRoleRefusalReason;
  /** The consumer's own name for the entry point that refused. */
  door: string;
  /** One sentence, safe to show to the caller. Never a credential. */
  detail: string;
};

export type ToolMode = "read" | "write";

/** A tool's own declaration (rule 2). */
export type ToolDeclaration = {
  /**
   * The tool's MCP name (the `name` of its tool definition). Spelled `toolId`
   * because no root export of this package takes a name-like field
   * (`test/principal-by-id-no-name-input.test.ts`).
   */
  toolId: string;
  domain: string;
  mode: ToolMode;
};

export type ToolRoleDomainGrant = {
  domain: string;
  read: boolean;
  write: boolean;
};

/** A role, as the role store holds it for one organisation (rule 1). */
export type ToolRole = {
  roleId: string;
  /** The permanent ID of the organisation that owns the role. */
  orgClerkId: string;
  domains: readonly ToolRoleDomainGrant[];
  add: readonly string[];
  remove: readonly string[];
};

/**
 * The outcome of the consumer's role-store read for the calling agent.
 *   - "resolved"   the agent's role;
 *   - "absent"     no role: `cause` "unassigned" (default) or "deleted" (the
 *                  agent points at a role that no longer exists);
 *   - "unresolved" the read failed.
 */
export type ToolRoleLookup =
  | { status: "resolved"; role: ToolRole }
  | { status: "absent"; cause?: "unassigned" | "deleted" }
  | { status: "unresolved" };

export type ToolRoleDecision =
  | { ok: true; tool: string; via: "domain" | "add" }
  | { ok: false; refusal: ToolRoleRefusal };

export type ToolRoleOptions = {
  /** The consumer's name for the door; carried on every refusal. */
  door?: string;
};

const DOOR = "decideToolRole";

function nonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.length > 0;
}

function nameList(value: unknown): value is readonly string[] {
  return Array.isArray(value) && value.every(nonEmpty);
}

function wellFormedRole(value: unknown): value is ToolRole {
  if (value === null || typeof value !== "object" || Array.isArray(value)) return false;
  const r = value as Record<string, unknown>;
  if (!nonEmpty(r.roleId) || !nonEmpty(r.orgClerkId)) return false;
  if (!nameList(r.add) || !nameList(r.remove)) return false;
  if (!Array.isArray(r.domains)) return false;
  const seen = new Set<string>();
  for (const g of r.domains as unknown[]) {
    if (g === null || typeof g !== "object" || Array.isArray(g)) return false;
    const grant = g as Record<string, unknown>;
    if (!nonEmpty(grant.domain) || typeof grant.read !== "boolean" || typeof grant.write !== "boolean") {
      return false;
    }
    // Two entries for one domain would leave the grant ambiguous: fail closed.
    if (seen.has(grant.domain)) return false;
    seen.add(grant.domain);
  }
  return true;
}

/**
 * Allow or deny one tool for the calling agent.
 *
 * Checks, in order (the first that applies decides):
 *   1. the lookup failed                          TOOL_ROLE_UNRESOLVED role-store-failed
 *   2. no role / role no longer exists            no-role / role-not-found
 *   3. the lookup or the role is malformed        role-invalid
 *   4. the caller is not a member with an org ID  caller-not-resolved
 *   5. role.orgClerkId !== caller.orgClerkId      other-organisation
 *   6. no toolId or no domain                     tool-undeclared
 *   7. mode not exactly "read" | "write"          tool-mode-invalid
 *   8. tool in `remove`                           tool-removed (remove wins)
 *   9. tool in `add`                              allow, via "add"
 *  10. domain granted for the tool's mode         allow, via "domain"
 *  11. write tool, domain granted read only       write-on-read-grant
 *  12. otherwise                                  domain-not-granted
 * Steps 2-8, 11 and 12 deny with TOOL_ROLE_DENIED.
 */
export function decideToolRole(
  lookup: ToolRoleLookup,
  tool: ToolDeclaration,
  caller: StandingScope,
  options?: ToolRoleOptions,
): ToolRoleDecision {
  const door = options?.door ?? DOOR;
  const deny = (
    reason: ToolRoleRefusalReason,
    detail: string,
    code: ToolRoleRefusalCode = "TOOL_ROLE_DENIED",
  ): ToolRoleDecision => ({
    ok: false,
    refusal: { code, reason, door, detail },
  });

  const l = lookup as Partial<Record<string, unknown>> | null | undefined;
  if (l === null || typeof l !== "object") {
    return deny("role-invalid", "The role lookup is not well formed.");
  }
  if (l.status === "unresolved") {
    return deny("role-store-failed", "The agent's role could not be read.", "TOOL_ROLE_UNRESOLVED");
  }
  if (l.status === "absent") {
    return l.cause === "deleted"
      ? deny("role-not-found", "The agent's role no longer exists.")
      : deny("no-role", "The agent has no role.");
  }
  if (l.status !== "resolved" || !wellFormedRole(l.role)) {
    return deny("role-invalid", "The agent's role is not well formed.");
  }
  const role = l.role;

  if (scopeStanding(caller) !== "member") {
    return deny("caller-not-resolved", "The caller is not resolved to an organisation member.");
  }
  // `scopeStanding` "member" guarantees a non-empty string `orgClerkId`.
  if (role.orgClerkId !== (caller as { orgClerkId: string }).orgClerkId) {
    return deny("other-organisation", "The agent's role belongs to another organisation.");
  }

  const t = tool as Partial<Record<string, unknown>> | null | undefined;
  if (t === null || typeof t !== "object" || !nonEmpty(t.toolId) || !nonEmpty(t.domain)) {
    return deny("tool-undeclared", "The tool has no declaration.");
  }
  const mode = t.mode;
  if (mode !== "read" && mode !== "write") {
    return deny("tool-mode-invalid", "The tool's mode is not read or write.");
  }
  const toolId = t.toolId;

  if (role.remove.includes(toolId)) {
    return deny("tool-removed", "The tool is removed from the agent's role.");
  }
  if (role.add.includes(toolId)) {
    return { ok: true, tool: toolId, via: "add" };
  }
  const grant = role.domains.find((g) => g.domain === t.domain);
  if (grant?.[mode] === true) {
    return { ok: true, tool: toolId, via: "domain" };
  }
  if (grant !== undefined && mode === "write" && grant.read) {
    return deny("write-on-read-grant", "The agent's role grants this domain for read only.");
  }
  return deny("domain-not-granted", "The agent's role does not grant this tool's domain.");
}

/**
 * The declared tools the calling agent may use: exactly those `decideToolRole`
 * allows, in input order. For `tools/list` and for the identity tool's
 * `grantedTools` (`.map((t) => t.toolId)`), so both equal the call-time decision.
 * A non-array list is an empty list.
 */
export function filterGrantedTools<T extends ToolDeclaration>(
  lookup: ToolRoleLookup,
  tools: readonly T[],
  caller: StandingScope,
): T[] {
  if (!Array.isArray(tools)) return [];
  return tools.filter((tool) => decideToolRole(lookup, tool, caller).ok);
}
