import { describe, expect, it } from "vitest";
import * as root from "../src/index.js";
import {
  decideToolRole,
  filterGrantedTools,
  type ToolDeclaration,
  type ToolRole,
  type ToolRoleDecision,
  type ToolRoleLookup,
} from "../src/tool-role.js";

/**
 * Agent tool roles, rules 1, 2, 3, 5 and 6 (ElPi-Corp fab6c779, tool-roles section).
 * Each rule-5 deny branch has a DENY pole and an ALLOW pole that differs from it
 * by the one input that branch reads.
 */

const ORG = "org_2aAAAAAAAAAAAAAAAAAAAAAAAAA";
const OTHER_ORG = "org_2bBBBBBBBBBBBBBBBBBBBBBBBBB";

const member = (orgClerkId: string, orgSlug = "acme") => ({
  userId: "user_1",
  orgSlug,
  orgClerkId,
  allowedAgentIds: [],
  scopes: [],
  fleetWide: false as const,
  isMaster: false as const,
});

const CALLER = member(ORG);

const listTasks: ToolDeclaration = {
  toolId: "list_tasks",
  domain: "tasks",
  mode: "read",
};
const createTask: ToolDeclaration = {
  toolId: "create_task",
  domain: "tasks",
  mode: "write",
};
const deleteTask: ToolDeclaration = {
  toolId: "delete_task",
  domain: "tasks",
  mode: "write",
};
const recall: ToolDeclaration = {
  toolId: "recall",
  domain: "memory",
  mode: "read",
};
const storeMemory: ToolDeclaration = {
  toolId: "store_memory",
  domain: "memory",
  mode: "write",
};
const sendMessage: ToolDeclaration = {
  toolId: "send_message",
  domain: "messages",
  mode: "write",
};

const ALL_TOOLS = [listTasks, createTask, deleteTask, recall, storeMemory, sendMessage];

const role = (overrides: Partial<ToolRole> = {}): ToolRole => ({
  roleId: "role_reader",
  orgClerkId: ORG,
  domains: [{ domain: "tasks", read: true, write: true }],
  add: [],
  remove: [],
  ...overrides,
});

const resolved = (r: ToolRole): ToolRoleLookup => ({
  status: "resolved",
  role: r,
});

function reasonOf(d: ToolRoleDecision): string | null {
  return d.ok ? null : d.refusal.reason;
}
function codeOf(d: ToolRoleDecision): string | null {
  return d.ok ? null : d.refusal.code;
}

describe("decideToolRole: domain grant (rule 1)", () => {
  it("ALLOW: a read tool on a domain granted for read", () => {
    const d = decideToolRole(resolved(role()), listTasks, CALLER);
    expect(d).toEqual({ ok: true, tool: "list_tasks", via: "domain" });
  });

  it("ALLOW: a write tool on a domain granted for write", () => {
    const d = decideToolRole(resolved(role()), createTask, CALLER);
    expect(d.ok).toBe(true);
  });

  it("DENY domain-not-granted: the tool's domain is absent from the role", () => {
    const d = decideToolRole(resolved(role()), recall, CALLER);
    expect(codeOf(d)).toBe("TOOL_ROLE_DENIED");
    expect(reasonOf(d)).toBe("domain-not-granted");
  });

  it("DENY domain-not-granted: the domain is listed with read and write both false", () => {
    const r = role({
      domains: [{ domain: "memory", read: false, write: false }],
    });
    expect(reasonOf(decideToolRole(resolved(r), recall, CALLER))).toBe("domain-not-granted");
  });

  it("DENY domain-not-granted: write-only grant does not grant a read tool (separate booleans)", () => {
    const r = role({
      domains: [{ domain: "tasks", read: false, write: true }],
    });
    expect(reasonOf(decideToolRole(resolved(r), listTasks, CALLER))).toBe("domain-not-granted");
    expect(decideToolRole(resolved(r), createTask, CALLER).ok).toBe(true);
  });
});

describe("decideToolRole: read grant on a write tool (rule 5)", () => {
  const readOnly = role({
    domains: [{ domain: "tasks", read: true, write: false }],
  });

  it("DENY write-on-read-grant: a write tool on a read-only grant", () => {
    const d = decideToolRole(resolved(readOnly), createTask, CALLER);
    expect(codeOf(d)).toBe("TOOL_ROLE_DENIED");
    expect(reasonOf(d)).toBe("write-on-read-grant");
  });

  it("ALLOW: the read tool of the same domain on the same grant", () => {
    expect(decideToolRole(resolved(readOnly), listTasks, CALLER).ok).toBe(true);
  });
});

describe("decideToolRole: remove wins (rule 1, rule 5)", () => {
  it("DENY tool-removed: a removed tool is denied although its domain grants it", () => {
    const r = role({ remove: ["delete_task"] });
    const d = decideToolRole(resolved(r), deleteTask, CALLER);
    expect(codeOf(d)).toBe("TOOL_ROLE_DENIED");
    expect(reasonOf(d)).toBe("tool-removed");
  });

  it("ALLOW: the sibling tool of the same domain, not removed", () => {
    const r = role({ remove: ["delete_task"] });
    expect(decideToolRole(resolved(r), createTask, CALLER).ok).toBe(true);
  });

  it("DENY tool-removed: remove wins over add for the same tool", () => {
    const r = role({ add: ["recall"], remove: ["recall"] });
    expect(reasonOf(decideToolRole(resolved(r), recall, CALLER))).toBe("tool-removed");
  });
});

describe("decideToolRole: add grants outside domains (rule 1)", () => {
  it("ALLOW via add: a tool whose domain is not granted", () => {
    const r = role({ add: ["recall"] });
    expect(decideToolRole(resolved(r), recall, CALLER)).toEqual({
      ok: true,
      tool: "recall",
      via: "add",
    });
  });

  it("ALLOW via add: a write tool whose domain is granted read-only", () => {
    const r = role({
      domains: [{ domain: "tasks", read: true, write: false }],
      add: ["create_task"],
    });
    expect(decideToolRole(resolved(r), createTask, CALLER)).toEqual({
      ok: true,
      tool: "create_task",
      via: "add",
    });
  });

  it("DENY: add names one tool, its domain siblings stay denied", () => {
    const r = role({ add: ["recall"] });
    expect(reasonOf(decideToolRole(resolved(r), storeMemory, CALLER))).toBe("domain-not-granted");
  });
});

describe("decideToolRole: no role (rule 5)", () => {
  it("DENY no-role: the agent has no role", () => {
    const d = decideToolRole({ status: "absent" }, listTasks, CALLER);
    expect(codeOf(d)).toBe("TOOL_ROLE_DENIED");
    expect(reasonOf(d)).toBe("no-role");
  });

  it("DENY no-role: the agent has no role (explicit cause)", () => {
    expect(reasonOf(decideToolRole({ status: "absent", cause: "unassigned" }, listTasks, CALLER))).toBe("no-role");
  });

  it("DENY role-not-found: the agent's role no longer exists", () => {
    const d = decideToolRole({ status: "absent", cause: "deleted" }, listTasks, CALLER);
    expect(codeOf(d)).toBe("TOOL_ROLE_DENIED");
    expect(reasonOf(d)).toBe("role-not-found");
  });

  it("DENY role-invalid: a malformed role is not a grant", () => {
    const bad = [
      { ...role(), roleId: "" },
      { ...role(), orgClerkId: "" },
      { ...role(), domains: "tasks" },
      { ...role(), domains: [{ domain: "tasks", read: "true", write: false }] },
      { ...role(), domains: [{ domain: "", read: true, write: true }] },
      {
        ...role(),
        domains: [
          { domain: "tasks", read: true, write: false },
          { domain: "tasks", read: true, write: true },
        ],
      },
      { ...role(), add: ["", "x"] },
      { ...role(), remove: "delete_task" },
      null,
    ];
    for (const r of bad) {
      const d = decideToolRole({ status: "resolved", role: r as unknown as ToolRole }, listTasks, CALLER);
      expect(reasonOf(d)).toBe("role-invalid");
    }
  });

  it("DENY role-invalid: a malformed lookup is never a grant", () => {
    for (const l of [null, undefined, {}, { status: "granted" }, "resolved"]) {
      const d = decideToolRole(l as unknown as ToolRoleLookup, listTasks, CALLER);
      expect(d.ok).toBe(false);
      expect(codeOf(d)).toBe("TOOL_ROLE_DENIED");
    }
  });
});

describe("decideToolRole: the role's organisation (rule 5, compared by clerkOrgId)", () => {
  it("DENY other-organisation: same label, different clerkOrgId", () => {
    const caller = member(OTHER_ORG, "acme");
    const d = decideToolRole(resolved(role()), listTasks, caller);
    expect(codeOf(d)).toBe("TOOL_ROLE_DENIED");
    expect(reasonOf(d)).toBe("other-organisation");
  });

  it("ALLOW: different label, same clerkOrgId (a label is not identity)", () => {
    const caller = member(ORG, "acme-renamed");
    expect(decideToolRole(resolved(role()), listTasks, caller).ok).toBe(true);
  });

  it("DENY caller-not-resolved: a caller scope that is not a member standing", () => {
    const callers = [
      null,
      undefined,
      {},
      { ...CALLER, refused: true },
      { ...CALLER, orgClerkId: "" },
      { isMaster: false, fleetWide: false, orgSlug: "acme" },
      {
        isMaster: true,
        fleetWide: true,
        masterSource: "service-account",
        orgClerkId: ORG,
      },
      {
        isMaster: true,
        fleetWide: true,
        masterSource: "operator-admin",
        orgClerkId: ORG,
      },
    ];
    for (const c of callers) {
      const d = decideToolRole(resolved(role()), listTasks, c as never);
      expect(codeOf(d)).toBe("TOOL_ROLE_DENIED");
      expect(reasonOf(d)).toBe("caller-not-resolved");
    }
  });
});

describe("decideToolRole: the tool's declaration (rules 2 and 5)", () => {
  it("DENY tool-undeclared: no declaration, no name, or no domain", () => {
    const bad = [
      null,
      undefined,
      {},
      { toolId: "list_tasks", mode: "read" },
      { toolId: "", domain: "tasks", mode: "read" },
      { toolId: "list_tasks", domain: "", mode: "read" },
      { domain: "tasks", mode: "read" },
    ];
    for (const t of bad) {
      const d = decideToolRole(resolved(role()), t as unknown as ToolDeclaration, CALLER);
      expect(codeOf(d)).toBe("TOOL_ROLE_DENIED");
      expect(reasonOf(d)).toBe("tool-undeclared");
    }
  });

  it("DENY tool-mode-invalid: a mode other than exactly read or write", () => {
    for (const mode of [undefined, "", "Read", "READ", "readwrite", "admin", true, 1]) {
      const t = {
        toolId: "list_tasks",
        domain: "tasks",
        mode,
      } as unknown as ToolDeclaration;
      const d = decideToolRole(resolved(role()), t, CALLER);
      expect(codeOf(d)).toBe("TOOL_ROLE_DENIED");
      expect(reasonOf(d)).toBe("tool-mode-invalid");
    }
  });

  it("DENY tool-mode-invalid: add does not rescue a tool with a bad mode", () => {
    const t = {
      toolId: "recall",
      domain: "memory",
      mode: "admin",
    } as unknown as ToolDeclaration;
    expect(reasonOf(decideToolRole(resolved(role({ add: ["recall"] })), t, CALLER))).toBe("tool-mode-invalid");
  });
});

describe("decideToolRole: role-store failure (rule 5)", () => {
  it("TOOL_ROLE_UNRESOLVED: a failed role-store read is a distinct deny", () => {
    const d = decideToolRole({ status: "unresolved" }, listTasks, CALLER);
    expect(d.ok).toBe(false);
    expect(codeOf(d)).toBe("TOOL_ROLE_UNRESOLVED");
    expect(reasonOf(d)).toBe("role-store-failed");
  });

  it("TOOL_ROLE_UNRESOLVED: never all tools", () => {
    expect(filterGrantedTools({ status: "unresolved" }, ALL_TOOLS, CALLER)).toEqual([]);
  });
});

describe("decideToolRole: refusal shape", () => {
  it("carries code, reason, door and detail; door defaults to the function name", () => {
    const d = decideToolRole({ status: "absent" }, listTasks, CALLER);
    expect(d.ok).toBe(false);
    if (d.ok) return;
    expect(Object.keys(d.refusal).sort()).toEqual(["code", "detail", "door", "reason"]);
    expect(d.refusal.door).toBe("decideToolRole");
    expect(typeof d.refusal.detail).toBe("string");
    expect(d.refusal.detail.length).toBeGreaterThan(0);
  });

  it("names the consumer's door when given", () => {
    const d = decideToolRole({ status: "absent" }, listTasks, CALLER, {
      door: "tools/call",
    });
    expect(d.ok ? null : d.refusal.door).toBe("tools/call");
  });

  it("a refusal never echoes the caller scope", () => {
    const d = decideToolRole(resolved(role()), listTasks, member(OTHER_ORG));
    expect(JSON.stringify(d)).not.toContain("user_1");
  });
});

describe("filterGrantedTools (rule 6: the list equals the per-tool decisions)", () => {
  const roles: ToolRoleLookup[] = [
    { status: "absent" },
    { status: "absent", cause: "deleted" },
    { status: "unresolved" },
    resolved(role()),
    resolved(role({ domains: [] })),
    resolved(role({ domains: [{ domain: "tasks", read: true, write: false }] })),
    resolved(role({ add: ["recall", "send_message"], remove: ["delete_task"] })),
    resolved(
      role({
        domains: [
          { domain: "tasks", read: true, write: true },
          { domain: "memory", read: true, write: true },
          { domain: "messages", read: true, write: true },
        ],
      }),
    ),
    resolved(role({ orgClerkId: OTHER_ORG })),
  ];
  const tools = [
    ...ALL_TOOLS,
    {
      toolId: "bad_mode",
      domain: "tasks",
      mode: "admin",
    } as unknown as ToolDeclaration,
    { toolId: "no_domain", mode: "read" } as unknown as ToolDeclaration,
  ];

  it("returns exactly the declarations decideToolRole allows, in input order", () => {
    for (const lookup of roles) {
      const expected = tools.filter((t) => decideToolRole(lookup, t, CALLER).ok);
      expect(filterGrantedTools(lookup, tools, CALLER)).toEqual(expected);
    }
  });

  it("a role that grants nothing lists nothing", () => {
    expect(filterGrantedTools(resolved(role({ domains: [] })), ALL_TOOLS, CALLER)).toEqual([]);
  });

  it("the full grant lists every declared tool and no undeclared one", () => {
    const full = roles[7] as ToolRoleLookup;
    expect(filterGrantedTools(full, tools, CALLER).map((t) => t.toolId)).toEqual(ALL_TOOLS.map((t) => t.toolId));
  });

  it("a read-only grant omits the write tools of that domain", () => {
    const names = filterGrantedTools(roles[5] as ToolRoleLookup, ALL_TOOLS, CALLER).map((t) => t.toolId);
    expect(names).toEqual(["list_tasks"]);
  });

  it("a non-array tool list is an empty list, never a throw", () => {
    expect(filterGrantedTools(resolved(role()), null as unknown as ToolDeclaration[], CALLER)).toEqual([]);
  });
});

describe("tool-role exports", () => {
  it("the root exports decideToolRole and filterGrantedTools", () => {
    expect(root.decideToolRole).toBe(decideToolRole);
    expect(root.filterGrantedTools).toBe(filterGrantedTools);
  });
});
