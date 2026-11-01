# Caller paths: a person, a service, a Convex consumer

Part of the `@vantageos/cloud-identity` documentation. Start at the [README](../README.md).

## A host-verified identity to its tenant

When the host has already verified the caller (a Convex function holds
`await ctx.auth.getUserIdentity()`), `requireTenantFromIdentity` returns the
tenant ID from the identity's organisation ID claim, read by the package's own
claim reader. It throws `IdentityRefusalError` (`RBAC_DENIED`,
`no-verified-organisation`) when there is no identity or no organisation ID;
there is no fallback to a slug or a default.

```ts
import { requireTenantFromIdentity } from "@vantageos/cloud-identity";

const tenantId = requireTenantFromIdentity(await ctx.auth.getUserIdentity(), {
  door: "engine:queue.enqueue",
});
```

For an audit stamp (`createdBy`), `requireSubjectFromIdentity(identity, { door })`
(0.21.3) returns the same verified identity's subject, and throws
`IdentityRefusalError` (`RBAC_DENIED`, `no-verified-subject`) when there is no
identity or the subject is not a non-empty string.

## A service calling Convex: the machine credential

A service with no human behind it (no Clerk session, so no
`ctx.auth.getUserIdentity()`) calls public Convex functions with a machine
credential (0.21.4). The package decides the identity; the consumer supplies
one indexed read.

**Mint.** `mintMachineCredential()` returns a `MintedMachineCredential`:
`credential` (`vpmc_` + 32 random bytes, base64url) and `secretHash` (its
SHA-256 hex digest). Store ONLY `secretHash`, with `tenantId`, optional
`agentId`, `revoked` and `expiresAt` (the `StoredBearerRow` shape). Hand
`credential` to the service once.

**Transport.** Convex functions do not receive request headers, so the
credential reaches the function as an ARGUMENT, next to the organisation the
service claims to act for. Since 0.25.0 that argument is the credential's
DIGEST, never the credential: see "Convex consumers: pass the digest, never
the token" below. Rotate by minting a new credential and revoking the old row.

**Resolve.** In a Convex function, `resolveConvexMachineCallerFromDigest({
credentialDigest, claimedOrgId }, deps)` (`ConvexMachineCallerDigestInput`).
For a caller that holds the raw credential in-process, outside any Convex
argument, `resolveConvexMachineCaller({ credential, claimedOrgId }, deps)`
(`ConvexMachineCallerInput`, `ConvexMachineCallerDeps` = `PresentedBearerDeps`
plus `door`) returns a `ConvexMachineCallerResult`: `{ ok: true, tenantId,
agent, scopes }` or `{ ok: false, refusal }`. It runs the same core as
`validatePresentedBearer` (digest lookup, constant-time re-compare, row shape,
revocation, expiry). Tagged `@callerResolver`.

| Outcome | Refusal |
|---|---|
| empty or non-string credential or claimed org (lookup not called) | `CREDENTIAL_REFUSED` `credential-invalid` |
| digest that is not 64 lowercase hex characters (lookup not called) | the same `CREDENTIAL_REFUSED` `credential-invalid` |
| unknown, revoked, expired, malformed row, stored-digest mismatch | the same `CREDENTIAL_REFUSED` `credential-invalid` |
| the lookup threw | `RBAC_DENIED` `principal-lookup-failed` (answer "unavailable") |
| valid credential, row tenant is not the claimed org | `RBAC_DENIED` `other-organisation` |

```ts
import { IdentityRefusalError } from "@vantageos/cloud-identity/identity-refusal";
import { resolveConvexMachineCallerFromDigest } from "@vantageos/cloud-identity/machine-caller";

const r = await resolveConvexMachineCallerFromDigest(
  { credentialDigest: args.credentialDigest, claimedOrgId: args.orgId },
  {
    door: "engine:world.step",
    lookupBySecretHash: (d) =>
      ctx.db
        .query("machine_credentials")
        .withIndex("by_secret_hash", (q) => q.eq("secretHash", d))
        .unique(),
  },
);
if (!r.ok) throw new IdentityRefusalError(r.refusal);
const tenantId = r.tenantId;
```

Rejected alternative: a custom JWT provider on Convex auth, because it needs
the consumer to run a token issuer.

## Convex consumers: pass the digest, never the token

A raw bearer passed as a Convex function argument leaks. Measured: when any
argument of a Convex call fails its validator, Convex echoes the WHOLE
argument object, valid fields included, into the caller's error, and that
error is persisted in the deployment log. One malformed call writes the token
to a log.

So hash at the HTTP boundary and send only the SHA-256 hex digest (0.25.0):

1. **HTTP boundary** (MCP server, route handler): `sha256Hex(token)` from
   `@vantageos/cloud-identity/crypto`. It is the same function that produces
   the stored `secretHash` (and `mintMachineCredential`'s), so the digests
   agree by construction. Forward the digest; drop the token.
2. **Convex function**: resolve the digest.
   - `resolveConvexMachineCallerFromDigest({ credentialDigest, claimedOrgId }, deps)`
     from `@vantageos/cloud-identity/machine-caller` for a machine caller.
   - `resolvePresentedDigest(digestHex, deps)` from
     `@vantageos/cloud-identity/presented-bearer` for a presented bearer; it
     returns the same `ValidatePresentedBearerResult` as
     `validatePresentedBearer`.

**A digest door is reachable only by the service identity.** The stored
`secretHash` IS the digest, so once a door accepts a digest, a stored digest is
a presentable credential: read access to the token table becomes equivalent to
holding every live token. Expose the Convex function that calls
`resolvePresentedDigest` / `resolveConvexMachineCallerFromDigest` to the
deployment's service identity only (an internal function, or a door that refuses
any other caller by name), never to a client, and treat the token table's read
access as security-critical.

Both run the one decision the raw-token functions run after hashing: lookup by
digest, constant-time re-compare of the stored digest, row shape, revocation,
expiry. The raw-token functions (`validatePresentedBearer`,
`resolveConvexMachineCaller`) are unchanged; they hash and call the same code,
and `test/presented-digest.test.ts` pins identical results for every outcome.

Only a 64-character lowercase hex digest is accepted. Anything else is refused
with the SAME refusal as a well-formed digest that matches no row (`mismatch`,
or `CREDENTIAL_REFUSED` `credential-invalid`), without a lookup, so the shape
of the input tells a prober nothing. The consumer's `onRefusal` sink still
receives the internal reason `malformed-digest`.

A digest is still the key of a live credential: whoever holds it can present
it to a digest door. Do not log it on purpose. What it does not do is reveal
the token.

Import from the narrow subpaths in a Convex bundle. The root index re-exports
the Clerk handshake: measured with esbuild, importing
`resolveConvexMachineCallerFromDigest` from the root bundles 33 `@clerk`
modules, from `./machine-caller` none (`test/machine-caller-subpath.test.ts`).

```ts
// HTTP boundary
import { sha256Hex } from "@vantageos/cloud-identity/crypto";
await convex.mutation(api.engine.step, {
  orgId,
  credentialDigest: await sha256Hex(credential),
});

// Convex function: args = { orgId: v.string(), credentialDigest: v.string() }
import { resolveConvexMachineCallerFromDigest } from "@vantageos/cloud-identity/machine-caller";
const r = await resolveConvexMachineCallerFromDigest(
  { credentialDigest: args.credentialDigest, claimedOrgId: args.orgId },
  { door: "engine:step", lookupBySecretHash: (d) => lookupRow(ctx, d) },
);
```

## Both caller paths, one contract

A right is never granted by an absent argument. `requireTenantId` refuses by
default — a missing session, a missing organization, or a missing
bearer-resolved workspace all throw; there is no branch that falls through to
"full access" when tenant information is absent. The same function resolves
both entry paths a VantagePeers Cloud request can arrive on:

```ts
import {
  requireTenantId,
  decodeUnverifiedBearer,
  type TenantSource,
} from "@vantageos/cloud-identity";

async function resolveTenant(req: {
  session?: { orgId?: string | null } | null;
  bearerToken?: string;
}): Promise<string> {
  const source: TenantSource = req.session
    ? { kind: "session", identity: req.session }
    : {
        // decodeUnverifiedBearer only decodes the shape — verify the token's
        // signature (or look it up against your own store) before trusting
        // any field on the payload. See "What this package does not do".
        kind: "bearer",
        context: await decodeUnverifiedBearer(req.bearerToken!),
      };

  // Throws for BOTH paths if no tenant is attached — never returns a
  // "default" tenant id when one is missing.
  return requireTenantId(source);
}

// Human path: a signed-in user with an active organization.
await resolveTenant({ session: { orgId: "org_abc" } }); // -> "org_abc"

// Machine path: a caller presenting an already-resolved bearer token.
await resolveTenant({ bearerToken: someBase64Token }); // -> the token's workspaceId

// Either path with nothing attached throws instead of granting access.
await resolveTenant({ session: null }); // throws Error("Unauthenticated: no session.")
```
