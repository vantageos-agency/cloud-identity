# Verifying a private_key_jwt client assertion

Part of the `@vantageos/cloud-identity` documentation. Start at the [README](../README.md).

## A client that signs its token request (`/client-assertion`, 0.34.0)

Some MCP clients (ChatGPT among them) identify themselves with a Client ID
Metadata Document (CIMD): their `client_id` is an https URL whose JSON document
lists their redirect URIs and, for `private_key_jwt`, a `jwks_uri`. At `/token`
such a client may send `client_assertion_type` and `client_assertion`, a JWT it
signed (RFC 7523, OIDC Core section 9). An authorization server either verifies
that assertion or must not accept it; ignoring it is not an option.

**`createClientAssertionVerifier(options?)`** returns `{ verify(input) }`.
`verify({ assertionType, assertion, clientId?, audiences })` answers
`{ ok: true, clientId }` or `{ ok: false, reason }`:

- `assertionType` must be `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
  (`JWT_BEARER_ASSERTION_TYPE`).
- The UNVERIFIED `iss` only locates the key set. It must be URL-shaped (a DCR id
  has no document to hold keys), and a `clientId` you pass (the `client_id`
  request parameter, when the client sent one) must equal it. After the
  signature verifies, `iss` and `sub` must both equal that client id.
- The key set is read from the `jwks_uri` of the client's CIMD document. Both
  the document and the key set are fetched through the same SSRF guard: https
  only, every resolved address public, no redirects, no credentials or fragment
  in the URL, a time cap, and a 64 KiB size cap on the key set.
- The algorithm is pinned to RS256 (`ASSERTION_SIGNING_ALGS`). A document that
  declares another `token_endpoint_auth_signing_alg` is refused before its key
  set is fetched, and an `alg: none` or HMAC assertion cannot verify. An RSA key
  under 2048 bits does not verify; a `crit` header is refused.
- `aud` must name one of `audiences` (your token endpoint, your issuer). `exp`
  is required, with 30 seconds of clock tolerance, and may be at most
  `MAX_ASSERTION_LIFETIME_SECONDS` (300) plus those 30 seconds ahead of now: an
  assertion whose `exp` is further out is refused (`client assertion rejected`).
  `nbf` and `iat` must be numbers when present, and neither may be in the
  future past the 30 seconds of tolerance.
- `jti` is required and accepted ONCE. The default store (`createJtiStore(maxEntries = 10000)`)
  holds each jti until its `exp` plus 30 seconds. When it is full, a new jti is
  refused: a live jti is never evicted to make room, so a flood cannot reopen a
  replay window. Because `exp` is capped, every held jti expires within 360
  seconds of being accepted, so a flood of valid assertions can fill the store
  for at most that long after it stops; rate-limit `/token` per client and per
  address in front of the verifier. Pass `jtiStore` to share one store across instances (an object
  with `accept(clientId, jti, exp, nowSeconds): boolean`, type `JtiStore`).

Reasons (`AssertionRefusalReason`): `unsupported client assertion`,
`malformed client assertion`, `unknown client`,
`client_id does not match the assertion issuer`,
`client has no verifiable key set`, `unsupported signing algorithm`,
`invalid jwks_uri`, `key set unavailable`, `client assertion rejected`,
`client assertion replayed`. Answer every one of them with
`401 invalid_client`; the reason is for your logs.

Options (`AssertionVerifierOptions`): `now` (epoch milliseconds), `fetchImpl`,
`resolveHost` (host to addresses), `timeoutMs` (default 5000) and `jtiStore`,
each injectable for tests or for a hardened network.

```ts
import {
  createClientAssertionVerifier,
  JWT_BEARER_ASSERTION_TYPE,
} from "@vantageos/cloud-identity/client-assertion";

const assertions = createClientAssertionVerifier();

// in the /token handler, when the request carries a client assertion:
const verdict = await assertions.verify({
  assertionType: form.get("client_assertion_type") ?? undefined,
  assertion: form.get("client_assertion") ?? undefined,
  clientId: form.get("client_id") ?? undefined,
  audiences: [`${issuer}/token`, issuer],
});
if (!verdict.ok) return oauthError(401, "invalid_client");
// verdict.clientId is the authenticated client.
```

The same module exports the pieces the verifier is built from, for an
authorization server that resolves CIMD clients at `/authorize` too:
`resolveCimdDocument(clientId, options?)` (the validated document, with
`jwksUri` and `signingAlg` when declared, or null for ANY failure; types
`CimdDocument`, `CimdOptions`), `fetchGuardedJson(url, options?)`,
`isPublicAddress(ip)`, `isUrlShapedClientId(clientId)` and
`isAllowedRedirectUri(uri)`.

**Node only, subpath only.** The SSRF guard parses and matches addresses with
`node:net`'s `BlockList` and resolves hosts with `node:dns/promises`, so this
module is not re-exported from the package root (which stays bundleable on a
platform without Node built-ins). Import it from
`@vantageos/cloud-identity/client-assertion`.

**Limitation: DNS rebinding.** The guard resolves the host, checks every address,
then the fetch resolves it again, so a DNS-rebinding window exists between the
two. A deployment on a hostile network injects a `fetchImpl` that pins the
validated address (for example an undici dispatcher).
