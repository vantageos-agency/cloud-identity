# @vantageos/cloud-identity

Framework-agnostic identity + scope-filter primitives for **VantagePeers Cloud** (multi-tenant MCP).

Consumed by `vantage-peers-mcp` and `@vantageos/vantage-crm-mcp` — provides the small, testable building blocks that gate cross-tenant data access in the MCP transport layer.

## Install

```bash
npm install @vantageos/cloud-identity
```

## Modules

| Module | Symbols | Purpose |
| --- | --- | --- |
| `@vantageos/cloud-identity/crypto` | `timingSafeEqual` | Constant-time byte comparison (no branch-timing leak). |
| `@vantageos/cloud-identity/scope-filter` | `passesScopeFilter`, `scopeFilterList`, `scopeFilterGet` | Row-level visibility filter on `(createdBy, namespace)` using the caller's OAuth scope. |
| `@vantageos/cloud-identity/bearer-validation` | `validateMasterBearer` | Bearer-token parsing + sha256 constant-time match against a configured master secret. |
| `@vantageos/cloud-identity/types` | `OAuthCtx`, `ScopeProfile`, `NamespacePrefix`, `FromAllowListEntry`, `ValidateMasterBearerResult` | Public type surface (0.1.0). |
| `@vantageos/cloud-identity/tenancy-domain` | `Workspace`, `WorkspaceMember`, `WorkspaceRole`, `TenantContext`, `workspaceSchema`, `workspaceMemberSchema`, `workspaceRoleSchema`, `tenantContextSchema`, `ScopeViolationError`, `getEffectiveTenantId`, `resolveBearer` | Domain-tenancy layer (0.2.0) — multi-tenant isolation guard + Zod schemas + bearer resolution. |

## 0.1.0 scope

This release ships the **transport-agnostic** core:

- `crypto.timingSafeEqual`
- `scope-filter.{passesScopeFilter, scopeFilterList, scopeFilterGet}`
- `bearer-validation.validateMasterBearer`
- types

## 0.2.0 domain-tenancy layer

Released 2026-06-13. Additive — no breaking changes.

New in 0.2.0:
- `WorkspaceRole` literal union + Zod schema
- `Workspace` + `WorkspaceMember` + `TenantContext` types + Zod schemas
- `ScopeViolationError` — canonical cross-tenant isolation error
- `getEffectiveTenantId(ctx, args)` — multi-tenant guard (call at the top of every tool handler)
- `resolveBearer(token)` — decode bearer token into `{ userId, workspaceId, roles[] }`

## 0.3.0 roadmap

- D1 ghost Clerk identity injection.
- Signed JWT support in `resolveBearer`.
- Co-designed in a Theta cycle.

## Usage examples

### Constant-time byte comparison

```ts
import { timingSafeEqual } from "@vantageos/cloud-identity/crypto";

const a = new TextEncoder().encode(presentedHash);
const b = new TextEncoder().encode(expectedHash);
if (!(await timingSafeEqual(a, b))) {
  return new Response("forbidden", { status: 403 });
}
```

### Scope-aware row filtering

```ts
import { scopeFilterList } from "@vantageos/cloud-identity/scope-filter";
import type { OAuthCtx } from "@vantageos/cloud-identity/types";

const ctx: OAuthCtx = {
  fromAllowList: ["alice"],
  namespaceReadPrefixes: ["orchestrator/alpha"],
  namespaceWritePrefixes: [],
};
const visible = scopeFilterList(ctx, rowsFromConvex);
```

### Master Bearer validation

```ts
import { validateMasterBearer } from "@vantageos/cloud-identity/bearer-validation";

const res = await validateMasterBearer(
  request.headers.get("authorization") ?? undefined,
  process.env.BEARER_SECRET_MASTER ?? "",
);
if (!res.ok) {
  return new Response(`unauthorized: ${res.error}`, { status: 401 });
}
```

### Domain-tenancy layer (0.2.0)

#### getEffectiveTenantId — multi-tenant isolation guard

```ts
import { getEffectiveTenantId, resolveBearer, ScopeViolationError } from "@vantageos/cloud-identity/tenancy-domain";
import type { TenantContext } from "@vantageos/cloud-identity/tenancy-domain";

// 1. Resolve the bearer token (called once per MCP request, e.g. in middleware)
const ctx: TenantContext = await resolveBearer(rawToken);

// 2. At the top of every tool handler that receives a workspaceId argument:
try {
  const tenantId = getEffectiveTenantId(ctx, args);
  // tenantId is safe — caller's bearer matches the requested workspace
  const rows = await db.list({ workspaceId: tenantId });
} catch (err) {
  if (err instanceof ScopeViolationError) {
    // Translate to 403 — do NOT expose details to caller
    return new Response("forbidden", { status: 403 });
  }
  throw err;
}
```

#### resolveBearer — decode a bearer token

```ts
import { resolveBearer } from "@vantageos/cloud-identity/tenancy-domain";

// Token format: base64(JSON({ userId, workspaceId, roles: WorkspaceRole[] }))
const token = Buffer.from(JSON.stringify({
  userId: "user_alice",
  workspaceId: "ws_prod",
  roles: ["Admin"],
})).toString("base64");

const { userId, workspaceId, roles } = await resolveBearer(token);
```

#### Zod schemas — validate workspace objects at boundaries

```ts
import { workspaceSchema, tenantContextSchema } from "@vantageos/cloud-identity/tenancy-domain";

// Validate at API boundary
const ws = workspaceSchema.parse(requestBody);

// Validate TenantContext from an external JWT payload
const ctx = tenantContextSchema.parse(jwtPayload);
```

## Security doctrine

Canonical reference: `docs/cloud/security-multi-tenant.md` in the `vantage-peers` repo.

## License

MIT — VantagePeers Cloud, 2026.
