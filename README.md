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
| `@vantageos/cloud-identity/types` | `OAuthCtx`, `ScopeProfile`, `NamespacePrefix`, `FromAllowListEntry`, `ValidateMasterBearerResult` | Public type surface. |

## 0.1.0 scope

This release ships the **transport-agnostic** core:

- `crypto.timingSafeEqual`
- `scope-filter.{passesScopeFilter, scopeFilterList, scopeFilterGet}`
- `bearer-validation.validateMasterBearer`
- types

## 0.2.0 roadmap

- `getEffectiveWorkspaceId` (workspace resolution helper, sourced from `vantageos-crm`).
- D1 ghost Clerk identity injection.
- Co-designed in a Theta cycle.

## Security doctrine

Canonical reference: `docs/cloud/security-multi-tenant.md` in the `vantage-peers` repo.

## License

MIT — VantagePeers Cloud, 2026.
