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
| `@vantageos/cloud-identity/tenancy-domain` | `Workspace`, `WorkspaceMember`, `WorkspaceRole`, `TenantContext`, `workspaceSchema`, `workspaceMemberSchema`, `workspaceRoleSchema`, `tenantContextSchema`, `ScopeViolationError`, `getEffectiveTenantId`, `decodeUnverifiedBearer` | Domain-tenancy layer (0.2.0) — multi-tenant isolation guard + Zod schemas + bearer DECODER (not auth — see security note). |

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
- `decodeUnverifiedBearer(token)` — DECODE-ONLY helper. ⚠️ NOT authentication. NOT a trust boundary. See [Security: bearer decoding](#security-bearer-decoding) below.

## 0.3.0 roadmap

- D1 ghost Clerk identity injection.
- Signed-JWT bearer verification (replacing the decode-only helper as the production trust boundary).
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
import { getEffectiveTenantId, ScopeViolationError } from "@vantageos/cloud-identity/tenancy-domain";
import type { TenantContext } from "@vantageos/cloud-identity/tenancy-domain";

// 1. Obtain ctx from your VERIFIED auth middleware. Examples:
//    - Clerk session (clerkClient.verifyToken + claims → TenantContext)
//    - signed-JWT middleware (jose / jsonwebtoken with public key)
//    - Convex tenancy-table lookup against an opaque token
//    Whatever path: ctx.workspaceId MUST come from a SIGNATURE-VERIFIED source.
const ctx: TenantContext = await verifiedAuthMiddleware(request);

// 2. At the top of every tool handler that receives a workspaceId argument:
try {
  const tenantId = getEffectiveTenantId(ctx, args);
  // tenantId is safe — caller's verified ctx matches the requested workspace
  const rows = await db.list({ workspaceId: tenantId });
} catch (err) {
  if (err instanceof ScopeViolationError) {
    // Translate to 403 — do NOT expose details to caller
    return new Response("forbidden", { status: 403 });
  }
  throw err;
}
```

#### decodeUnverifiedBearer — DECODE-ONLY helper

> ⚠️ **NOT AUTHENTICATION. NOT A TRUST BOUNDARY.** See the [Security: bearer decoding](#security-bearer-decoding) section below.

```ts
import { decodeUnverifiedBearer } from "@vantageos/cloud-identity/tenancy-domain";

// Use cases:
//   (a) tests / fixtures
//   (b) shape-inspection of a payload that was ALREADY verified upstream
//
// Do NOT feed the returned `workspaceId` into getEffectiveTenantId as the
// trusted `ctx.workspaceId` — the payload is attacker-controlled.

const token = Buffer.from(JSON.stringify({
  userId: "user_alice",
  workspaceId: "ws_prod",
  roles: ["Admin"],
})).toString("base64");

const { userId, workspaceId, roles } = await decodeUnverifiedBearer(token);
```

#### Zod schemas — validate workspace objects at boundaries

```ts
import { workspaceSchema, tenantContextSchema } from "@vantageos/cloud-identity/tenancy-domain";

// Validate at API boundary
const ws = workspaceSchema.parse(requestBody);

// Validate TenantContext from an external JWT payload
const ctx = tenantContextSchema.parse(jwtPayload);
```

## Security: bearer decoding

`decodeUnverifiedBearer` performs **no signature verification, no issuer check, no expiry check, no replay-attack protection**. The decoded payload is **attacker-controlled**.

Forgery example:

```ts
// Any attacker can produce this token — no key, no signature required.
const forged = Buffer.from(JSON.stringify({
  userId: "x",
  workspaceId: "victim-org",     // crosses tenant boundary
  roles: ["Admin"],              // elevates privileges
})).toString("base64");

const payload = await decodeUnverifiedBearer(forged); // accepts it
```

Feeding the decoded `workspaceId` into `getEffectiveTenantId` as the trusted `ctx.workspaceId` silently grants cross-tenant access — the multi-tenant isolation guard collapses because both `ctx` and `args` are then attacker-controlled.

**Use only as**:
- a test fixture / harness helper, OR
- a decoder for a bearer that was ALREADY verified by an upstream signed-JWT or opaque-token middleware (the production trust boundary).

**Production trust boundary** is one of:
- Clerk session verification (planned 0.3.0 D1 ghost identity injection)
- signed JWT with rotating issuer key (planned 0.3.0)
- opaque-token lookup against a Convex tenancy table

Do **not** publish a service that treats `decodeUnverifiedBearer` as authentication.

## Security doctrine

Canonical reference: `docs/cloud/security-multi-tenant.md` in the `vantage-peers` repo.

## License

MIT — VantagePeers Cloud, 2026.
