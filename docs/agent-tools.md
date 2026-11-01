# Agents: acting claims and tool roles

Part of the `@vantageos/cloud-identity` documentation. Start at the [README](../README.md).

## May a typed name act as the agent? (`/acting-claim`, 0.22.0)

A name a caller types into a call is a CLAIM. `decideActingClaim` decides, from
the caller you already resolved by ID, whether that claim may be treated as the
acting agent. It is pure: no lookup, no environment read. It compares the claim
only to the stored label of an agent proven by ID, never to find or prove one,
and a claim never overrides a resolved identity.

```ts
import { decideActingClaim } from "@vantageos/cloud-identity";

const r = decideActingClaim({
  claimed: typedName,
  caller: { kind: "agent-credential", agentId, agentLabel, orgSlug }, // or the kinds below
  mode: switchIsPermissive ? "permissive" : "strict",
  door: "send_message",
});
if (!r.ok) return deny(`${r.refusal.code}: ${r.refusal.detail}`);
// r.via === "permissive-unattributed": record the call as unattributed.
```

| `caller` | decision |
| --- | --- |
| `null` | refused `RBAC_DENIED` (`no-context`), in every mode |
| `{ kind: "agent-credential", agentId, agentLabel, orgSlug }` | the claim must equal `agentLabel`, else `AGENT_IDENTITY_MISMATCH`, in every mode |
| `{ kind: "seat", agentId, agentLabel, orgId }` | the same, for a seat token that resolved to an agent by ID in its own organisation |
| `{ kind: "master-bearer" }` | `AGENT_CREDENTIAL_REQUIRED`, in every mode |
| `{ kind: "master-scope" }` | passes (`via: "master-scope"`) |
| `{ kind: "seat-unresolved", allowlist }` | passes when `allowlist` is exactly one real label and the claim equals it (`via: "seat-own-label"`); otherwise as `org-member`. For a seat whose provider could not stamp an agent (transitional) |
| `{ kind: "org-member" }` | passes only in explicit `"permissive"` mode (`via: "permissive-unattributed"`), else `AGENT_CREDENTIAL_REQUIRED` |

- `mode` is an input: absent, or any value other than the exact string
  `"permissive"`, is strict. A right is presented, never inferred from an absence.
- The comparison is the package's own: NFC, lowercase, trim. Case and
  composition form fold, accents do not. You pass no normaliser.
- A resolved agent with an empty ID or label, an unknown caller kind and a claim
  that is not a string are refused (`caller-invalid`, `claim-invalid`); the
  function never throws on malformed input.
- Every refusal is an `ActingClaimRefusal` (`code`, `reason`, `door`, `detail`,
  and `claimed` / `resolved` where they apply); it carries no credential.
  Types: `ActingCaller`, `ActingClaimMode`, `ActingClaimInput`,
  `ActingClaimRefusalCode`, `ActingClaimRefusalReason`, `ActingClaimResult`,
  `ActingClaimVia`.

## Agent tool roles: which tools an agent may see and call (/tool-role, 0.33.0)

A server sold with an agent layer decides, per calling agent, which tools exist
for it. One pure function decides; `tools/list` filters with it and `tools/call`
refuses with it, so a hidden tool cannot be called by name.

```ts
import { decideToolRole, filterGrantedTools } from "@vantageos/cloud-identity";

// `lookup` is your role-store read for the calling agent, resolved from the
// verified credential; `scope` is the package's resolved org scope (e.g. memberScopeFrom).
const lookup = { status: "resolved", role }; // | { status: "absent", cause?: "unassigned" | "deleted" } | { status: "unresolved" }

// tools/list
const listed = filterGrantedTools(lookup, declaredTools, scope);
// identity tool (rule 6): grantedTools equals what tools/list serves
const grantedTools = listed.map((t) => t.toolId);

// tools/call
const d = decideToolRole(lookup, declaration, scope, { door: "tools/call" });
if (!d.ok) return { isError: true, structuredContent: { error: d.refusal } };
```

- A role is `{ roleId, orgClerkId, domains: [{ domain, read, write }], add, remove }`;
  a tool declares `{ toolId, domain, mode }` with `mode` exactly `"read"` or `"write"`;
  `toolId` is the MCP tool name (spelled so because no root export takes a
  name-like field).
- Grant order: the domain grant (`read` for a read tool, `write` for a write tool),
  then `add` grants single tools outside it, then `remove` withdraws (remove wins,
  over `add` too). `read` and `write` are separate: a write grant does not grant
  a read tool.
- `decideToolRole(lookup, tool, caller, { door? })` returns
  `{ ok: true, tool, via: "domain" | "add" }` or `{ ok: false, refusal }`, the
  refusal carrying `code`, `reason`, `door`, `detail` (the `IdentityRefusal` shape).
- `TOOL_ROLE_UNRESOLVED` `role-store-failed`: the role-store read failed. Never
  "all tools".
- `TOOL_ROLE_DENIED` reasons: `no-role`, `role-not-found` (the role no longer
  exists), `role-invalid` (malformed role or lookup, duplicated domain entry),
  `caller-not-resolved` (the caller is not a `"member"` standing with an
  `orgClerkId`), `other-organisation` (the role's `orgClerkId` is not the caller's,
  compared by permanent ID, never by label), `tool-undeclared`, `tool-mode-invalid`,
  `tool-removed`, `write-on-read-grant`, `domain-not-granted`.
- `filterGrantedTools(lookup, tools, caller)` returns exactly the declarations
  `decideToolRole` allows, in input order.
- Pure: no storage, no I/O, no clock. The package does not store roles.
- On the root and the `./tool-role` subpath.
- Types: `ToolRole`, `ToolRoleDomainGrant`, `ToolDeclaration`, `ToolMode`,
  `ToolRoleLookup`, `ToolRoleDecision`, `ToolRoleOptions`, `ToolRoleRefusal`,
  `ToolRoleRefusalCode`, `ToolRoleRefusalReason`.
