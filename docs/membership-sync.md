# Clerk membership sync

Part of the `@vantageos/cloud-identity` documentation. Start at the [README](../README.md).

## Clerk membership sync (0.21.6)

Who belongs to which organisation, kept live from Clerk's
`organizationMembership.*` webhooks. The package holds the verification, the
parsing and the ordering; the consumer keeps its HTTP route and its own table.
Nothing here reads or writes a store.

**`verifySvixWebhook({ id, timestamp, signature, rawBody }, { secret, now?, toleranceSeconds? })`**
checks a delivery with Web Crypto: HMAC-SHA256 over `${id}.${timestamp}.${rawBody}`,
keyed by the base64 part of `whsec_<base64>`. `id`, `timestamp` and `signature`
are the `svix-id`, `svix-timestamp` and `svix-signature` headers; `rawBody` is the
body text before any JSON parse; `now` is milliseconds. Every `v1,<base64>`
candidate is compared in constant time with no early exit. Returns `{ ok: true }`
or `{ ok: false, refusal }` (`CREDENTIAL_REFUSED`) with one of
`webhook-secret-invalid` (absent or not `whsec_<base64>`, a server
misconfiguration, so answer 500), `webhook-headers-missing`,
`webhook-timestamp-out-of-window` (both directions, default 300 seconds, a
non-numeric timestamp included) or `webhook-signature-mismatch`. No refusal
carries the secret, the signature or the body. Types `SvixDelivery`,
`VerifySvixWebhookOptions`, `VerifySvixWebhookResult`.

**`clerkMembershipEvent(payload, { svixTimestampSeconds })`** takes the parsed,
already verified JSON. `created` and `updated` give `kind: "upsert"`, `deleted`
gives `kind: "delete"`, with `orgId` (`data.organization.id`), `personId`
(`data.public_user_data.user_id`), `orgSlug` when present, `role` (`org:admin`
is `admin`, anything else `member`) and `eventAt` in milliseconds. An upsert is
timed `data.updated_at`, else the delivery time. A delete is timed
`max(data.updated_at, delivery time)`: Clerk leaves `updated_at` equal to
`created_at` on a removal, so a removal is never dated before the moment Clerk
sent it. Any other event type is `{ ok: true, kind: "ignore" }`; a missing
organisation or user ID refuses `RBAC_DENIED` / `membership-event-invalid`.
Types `MembershipEvent`, `ClerkMembershipEventResult`.

**`decideMembershipEvent(existing, event)`** answers `{ apply, revive }` from the
stored row's `lastEventAt` and `deletedAt` (or `null`). An upsert at or before
`lastEventAt` is stale; a delete is stale only when strictly older, so the
removal wins a tie; an upsert newer than a tombstone revives. A tombstone with
no `lastEventAt` is ordered by its `deletedAt`. Types `StoredMembershipState`,
`DecideMembershipEventResult`.

**`membershipPersonLookups(readMembership)`** returns, from ONE closure, the
lookups that read the consumer's stored membership: `{ personById, lookupMembership }`.
`readMembership(orgId, personId)` returns the stored row (`{ role?, deletedAt?, orgId? }`)
or `null`. `personById` is for `resolveActingPrincipal`: a live row answers
`{ id, orgId, active: true }`, an absent or tombstoned (`deletedAt` set) one
answers `null`. `lookupMembership(personId, orgId)` is for `buildAgentLink`,
`resolveAgentLink` and `resolveMembership`: a live row answers
`{ active: true, role, orgId? }` with the role exactly as stored (`null` when the row
has none), a tombstoned row `{ active: false, role: null }` (a removed member's
stale role is not surfaced), an absent one `null`. A throwing read propagates
from both, so a failure is never taken for an absence. Types
`StoredMembershipRead` (the row read) and `MembershipLookupResult` (what
`lookupMembership` answers).

```ts
// agent-link deps from the one package call: no membership read of your own
const deps = {
  lookupAgent: (agentId) => readAgent(agentId),
  ...membershipPersonLookups((orgId, personId) => readOrgMembershipRow(orgId, personId)),
  adminRoles: ["org:admin"], // matched EXACTLY against the stored role
};
await buildAgentLink(input, deps);
```

**`planMembershipReconcile(stored, fromClerk, { at, fullyReadOrgIds })`** plans a
backfill as data: `{ upserts, tombstones }`. Every member Clerk reports is
upserted (a tombstoned one is revived, `revive: true`); a stored member Clerk
does not report is tombstoned only in an organisation listed in
`fullyReadOrgIds`, so a partial read removes nobody. A row stamped after `at`
is never touched. Types `MembershipRow`, `ClerkMembershipRow`,
`PlanMembershipReconcileOptions`, `MembershipUpsert`, `MembershipTombstone`,
`MembershipReconcilePlan`.

```ts
const verdict = await verifySvixWebhook(
  {
    id: req.headers.get("svix-id"),
    timestamp: req.headers.get("svix-timestamp"),
    signature: req.headers.get("svix-signature"),
    rawBody,
  },
  { secret: process.env.CLERK_WEBHOOK_SECRET },
);
if (!verdict.ok) return respondRefused(verdict.refusal);

const parsed = clerkMembershipEvent(JSON.parse(rawBody), {
  svixTimestampSeconds: Number(req.headers.get("svix-timestamp")),
});
if (!parsed.ok || parsed.kind === "ignore") return respondOk();

const row = await readRow(parsed.orgId, parsed.personId);
const { apply, revive } = decideMembershipEvent(row, parsed);
if (apply) await writeRow(parsed, { revive });
```

### A signed body, verified in constant time (`/hmac-signature`, 0.28.0)

**`verifyHmacSha256Signature({ body, signature }, { secret, encoding? })`** checks a
provider that signs the raw request body with a shared secret (a Gumroad-style
`X-...-Signature` header) with Web Crypto: HMAC-SHA256 of `body`, keyed by the UTF-8
bytes of `secret`. `body` is the text (or bytes) before any parse; `signature` is the
header value, hex by default (either case) or base64 with `encoding: "base64"`, and
a leading `sha256=` is accepted in both. The presented digest is decoded to 32 bytes
and compared with `timingSafeEqualSync`, so the time taken does not say where it
differs. Returns `{ ok: true }` or `{ ok: false, refusal }` (`CREDENTIAL_REFUSED`) with
`webhook-secret-invalid` (absent or empty secret, a server misconfiguration),
`webhook-headers-missing` (absent or empty signature) or `webhook-signature-mismatch`
(a wrong or malformed digest alike). No refusal carries the secret, the signature or
the body. A narrow import from `@vantageos/cloud-identity/hmac-signature` bundles no
`@clerk` module. Types `HmacSignatureDelivery`, `HmacSignatureEncoding`,
`VerifyHmacSha256SignatureOptions`, `VerifyHmacSha256SignatureResult`.

```ts
import { verifyHmacSha256Signature } from "@vantageos/cloud-identity/hmac-signature";

const verdict = await verifyHmacSha256Signature(
  { body: rawBody, signature: req.headers.get("x-provider-signature") },
  { secret: process.env.PROVIDER_SECRET },
);
if (!verdict.ok) return new Response("unauthorized", { status: 401 });
```

Two refusal reasons joined the vocabulary in 0.28.0 for a consumer's own doors:
`assignee-not-an-agent-of-org` (the named assignee is not an agent of the
organisation; no function here returns it) and `no-organisation` (the caller has no
organisation; produced by `noOrganisationRefusal` since 0.32.0, below).

### A verified identity with no organisation (`/identity-refusal`, 0.32.0)

**`noOrganisationRefusal(from: IdentityRefusal): IdentityRefusal | null`** is the
producer of the `no-organisation` refusal. The package's resolvers refuse a verified
identity that has no organisation attached with their own reason,
`no-verified-organisation` (`resolveCallerFromClaims`, `resolveOrgFromClaim`, and the
others that read a verified organisation ID). A door that tells "signed in, no
organisation" apart from every other refusal forwards what this returns instead of
building that refusal itself: `{ code: "RBAC_DENIED", reason: "no-organisation",
door: from.door, detail: "The verified identity has no organisation attached." }`. Every
other refusal answers null: an anonymous caller is `credential-invalid`, and an
organisation that is claimed but unmapped or inactive keeps its own reason. A slug
claim alone is still no verified organisation (a label never selects one). The input
is not mutated. Exported from the root and from `@vantageos/cloud-identity/identity-refusal`.

```ts
import { noOrganisationRefusal, resolveCallerFromClaims } from "@vantageos/cloud-identity";

const caller = await resolveCallerFromClaims(identity, deps, { adminRoles, door });
if (!caller.ok) {
  const noOrg = noOrganisationRefusal(caller.refusal);
  if (noOrg) return { ok: false, reason: noOrg.reason, detail: noOrg.detail };
  // ... every other refusal
}
```
