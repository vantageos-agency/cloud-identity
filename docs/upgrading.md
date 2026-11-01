# Upgrading

Part of the `@vantageos/cloud-identity` documentation. Start at the [README](../README.md).

## Upgrading to 0.4.0

**This release is purely additive — nothing you already call changes.** Every
0.3.0 export keeps its exact behaviour; 0.4.0 only adds two primitives, so an
upgrade from 0.3.0 compiles and runs unchanged until you choose to adopt them.

What is new:

- **A named deployment mode.** `requireTenantId` gains a `self-host` source
  alongside `session` and `bearer`. `cloud` is unchanged — an org-less
  identity is still refused. `self-host` is single-tenant and returns the
  tenant you **declare**; it throws when none is configured, never inferring
  one from absence.

  ```js
  import { requireTenantId } from "@vantageos/cloud-identity";

  // cloud (unchanged): refuses when the session has no org
  requireTenantId({ kind: "session", identity });
  // self-host: returns the DECLARED tenant, throws if it is empty
  requireTenantId({ kind: "self-host", tenantId: process.env.TENANT_ID });
  ```

- **A human-path normalizer.** `normalizeVerifiedHumanSession` maps an
  **already-verified** Clerk-shaped session into `{ tenant, subject, role }`
  (`role` ∈ `owner | admin | member | client`).

  ```js
  import { normalizeVerifiedHumanSession } from "@vantageos/cloud-identity";

  // session MUST already be verified upstream, e.g. Clerk auth() server-side:
  const { tenant, subject, role } = normalizeVerifiedHumanSession(session);
  ```

  ⚠️ It **normalizes, it does not authenticate.** Passing an unverified,
  client-controlled object (a `req.body`, a query payload) makes that object
  the trusted source of tenant, subject and role — a privilege escalation.
  Verify the session upstream first; only pass the object your provider
  already verified. (Same discipline as `decodeUnverifiedBearer`.)

Nothing to change on upgrade, nothing removed. Adopt the new primitives when
you need them.

## Upgrading to 0.3.0

**This release changes a default, and it breaks compilation on purpose.**

Before 0.3.0, calling a scope-filter function without an authorization context
returned `true` — no context meant full access. A caller who simply forgot to
pass the context received every row, and no warning. From 0.3.0 the context is
required: omitting it is a type error, and passing `null` or `undefined`
throws.

The breakage is deliberate, and it is the point. A caller that stops compiling
is a caller that has been told. A caller that still compiles and quietly
returns different rows is an incident nobody attributes to the upgrade.

What to do:

- If the call site has a real authorization context, pass it. This is almost
  always the right fix, and the context is usually already in scope.
- If the call site genuinely means "unrestricted", pass the exported constant
  `LEGACY_WILDCARD_CTX` by name. It reproduces the old behaviour exactly. It
  has to be written out, because an intentional bypass belongs in a code review
  and an accidental one should not be possible.

```js
import { scopeFilterList, LEGACY_WILDCARD_CTX } from "@vantageos/cloud-identity";

scopeFilterList(LEGACY_WILDCARD_CTX, rows); // explicit, unrestricted
```

`requireTenantId` is also new in 0.3.0. Nothing existing calls it, so it breaks
nothing.

Version history is in [CHANGELOG.md](../CHANGELOG.md).
