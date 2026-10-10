import type { ClerkJwks } from "./clerk-session.js";
import { verifyClerkSessionToken } from "./clerk-session.js";
import type { VerifiedClerkSession } from "./clerk-session.js";
import { refusal, type IdentityRefusal } from "./identity-refusal.js";

/**
 * Resource-server primitives for an MCP server that is an OAuth 2.1 protected
 * resource: the discovery document (RFC 9728), the `401` challenge (RFC 6750,
 * RFC 9728 section 5.1), the issuer discovery URLs, and the verification of an
 * inbound access token bound to this resource (RFC 8707 audience, RFC 9207
 * issuer).
 *
 * Token verification is NOT a second verifier: it delegates signature, `iss`,
 * `aud`, `exp` and `nbf` to `verifyClerkSessionToken` (RS256 only) and adds the
 * `Authorization` header handling, the mandatory audience, and the HTTP
 * envelope. Nothing here fetches a key set or calls the network.
 */

const DEFAULT_DOOR = "mcp-resource-server";

function requireNonEmpty(fn: string, name: string, value: unknown): asserts value is string {
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`cloud-identity: ${fn} requires a non-empty ${name}`);
  }
}

function requireAbsoluteUrl(fn: string, name: string, value: unknown): URL {
  requireNonEmpty(fn, name, value);
  try {
    return new URL(value);
  } catch {
    throw new Error(`cloud-identity: ${fn}: ${name} must be an absolute URL`);
  }
}

// ---------------------------------------------------------------------------
// RFC 9728 Protected Resource Metadata
// ---------------------------------------------------------------------------

export interface ProtectedResourceMetadataConfig {
  /** Canonical identifier of this resource (the MCP server URL). Absolute URL, no fragment. */
  resource: string;
  /** Issuer URL(s) of the authorization server(s). At least one. */
  authorizationServers: readonly string[];
  /** Bearer transports accepted. Default `["header"]`. */
  bearerMethodsSupported?: readonly string[];
  /** Scopes this resource understands. */
  scopesSupported?: readonly string[];
  /** Human-readable name of the resource. */
  resourceName?: string;
  /** URL of developer documentation for the resource. */
  resourceDocumentation?: string;
}

export interface ProtectedResourceMetadata {
  resource: string;
  authorization_servers: string[];
  bearer_methods_supported: string[];
  scopes_supported?: string[];
  resource_name?: string;
  resource_documentation?: string;
}

/**
 * Builds the RFC 9728 document served at `/.well-known/oauth-protected-resource`.
 * A config that cannot produce a valid document throws: a document without a
 * resource or an authorization server leaves a client unable to discover where
 * to authenticate.
 */
export function buildProtectedResourceMetadata(
  config: ProtectedResourceMetadataConfig,
): ProtectedResourceMetadata {
  const fn = "buildProtectedResourceMetadata";
  const resource = requireAbsoluteUrl(fn, "resource", config.resource);
  if (resource.hash !== "" || config.resource.includes("#")) {
    throw new Error(`cloud-identity: ${fn}: resource must not carry a fragment`);
  }
  if (!Array.isArray(config.authorizationServers) || config.authorizationServers.length === 0) {
    throw new Error(`cloud-identity: ${fn} requires at least one authorizationServer`);
  }
  for (const as of config.authorizationServers) {
    requireAbsoluteUrl(fn, "authorizationServer", as);
  }
  const methods = config.bearerMethodsSupported ?? ["header"];
  if (methods.length === 0) {
    throw new Error(`cloud-identity: ${fn}: bearerMethodsSupported must not be empty`);
  }

  const doc: ProtectedResourceMetadata = {
    resource: config.resource,
    authorization_servers: [...config.authorizationServers],
    bearer_methods_supported: [...methods],
  };
  if (config.scopesSupported) doc.scopes_supported = [...config.scopesSupported];
  if (config.resourceName) doc.resource_name = config.resourceName;
  if (config.resourceDocumentation) doc.resource_documentation = config.resourceDocumentation;
  return doc;
}

// ---------------------------------------------------------------------------
// RFC 6750 / RFC 9728 challenge
// ---------------------------------------------------------------------------

export interface UnauthorizedChallengeConfig {
  /** Protection realm, for example `"mcp"`. */
  realm: string;
  /** Absolute URL of this resource's RFC 9728 metadata document. */
  resourceMetadataUrl: string;
  /** RFC 6750 `error`; omit when no token was presented. */
  error?: "invalid_request" | "invalid_token" | "insufficient_scope";
  /** RFC 6750 `error_description`. */
  errorDescription?: string;
  /** RFC 6750 `scope`: scopes needed, space separated. */
  scope?: string;
}

export interface UnauthorizedChallenge {
  status: 401;
  headers: { "WWW-Authenticate": string };
}

function quoted(fn: string, name: string, value: string): string {
  if (/[\r\n]/.test(value)) {
    throw new Error(`cloud-identity: ${fn}: ${name} must not contain a line break`);
  }
  return `"${value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`;
}

/**
 * Builds the `401` envelope: status and a `WWW-Authenticate: Bearer` value that
 * always carries `resource_metadata`, so a client can complete discovery. Every
 * value is quoted and escaped; a value cannot inject a parameter or a header.
 */
export function unauthorizedChallenge(config: UnauthorizedChallengeConfig): UnauthorizedChallenge {
  const fn = "unauthorizedChallenge";
  requireNonEmpty(fn, "realm", config.realm);
  requireAbsoluteUrl(fn, "resourceMetadataUrl", config.resourceMetadataUrl);
  const parts = [
    `Bearer realm=${quoted(fn, "realm", config.realm)}`,
    `resource_metadata=${quoted(fn, "resourceMetadataUrl", config.resourceMetadataUrl)}`,
  ];
  if (config.error) parts.push(`error=${quoted(fn, "error", config.error)}`);
  if (config.errorDescription) {
    parts.push(`error_description=${quoted(fn, "errorDescription", config.errorDescription)}`);
  }
  if (config.scope) parts.push(`scope=${quoted(fn, "scope", config.scope)}`);
  return { status: 401, headers: { "WWW-Authenticate": parts.join(", ") } };
}

// ---------------------------------------------------------------------------
// Issuer discovery URLs
// ---------------------------------------------------------------------------

export interface ClerkDiscoveryUrls {
  discoveryUrl: string;
  jwksUrl: string;
}

/**
 * Derives the OIDC discovery and JWKS URLs of a Clerk issuer. The issuer must
 * be an absolute `https` URL; anything else throws rather than producing a
 * URL the client fails against later.
 */
export function deriveClerkDiscoveryUrls(issuer: string): ClerkDiscoveryUrls {
  const fn = "deriveClerkDiscoveryUrls";
  const url = requireAbsoluteUrl(fn, "issuer", issuer);
  if (url.protocol !== "https:") {
    throw new Error(`cloud-identity: ${fn}: issuer must use https`);
  }
  const base = issuer.endsWith("/") ? issuer.slice(0, -1) : issuer;
  return {
    discoveryUrl: `${base}/.well-known/openid-configuration`,
    jwksUrl: `${base}/.well-known/jwks.json`,
  };
}

// ---------------------------------------------------------------------------
// Access-token verification
// ---------------------------------------------------------------------------

export interface McpResourceServerConfig {
  /** Realm of the challenge. */
  realm: string;
  /** Absolute URL of this resource's RFC 9728 metadata document. */
  resourceMetadataUrl: string;
  /** Exact `iss` the token must carry. */
  issuer: string;
  /** This resource's identifier: the token's `aud` must contain it. Required, never optional. */
  audience: string;
  /** The key set, or a function returning it (the consumer owns fetching and caching). */
  jwks: ClerkJwks | (() => Promise<ClerkJwks>);
  /** Clock tolerance in seconds for `exp` / `nbf`. Default 5. */
  clockToleranceSeconds?: number;
  /** The consumer's name for the entry point, carried in every refusal. */
  door?: string;
}

export type VerifyMcpAccessTokenResult =
  | { ok: true; session: VerifiedClerkSession }
  | ({ ok: false; refusal: IdentityRefusal } & UnauthorizedChallenge)
  | { ok: false; refusal: IdentityRefusal; status: 503 };

/**
 * Verifies the `Authorization` header of an MCP request against this resource.
 *
 * - no header: `401`, `invalid_request`, reason `bearer-missing`
 * - not a non-empty `Bearer` credential: `401`, `invalid_request`, `bearer-malformed`
 * - signature, issuer, audience, expiry or not-before wrong: `401`,
 *   `invalid_token`, `token-invalid` (one answer, so the cause is not an oracle)
 * - key set unreachable: `503`, no challenge, `jwks-unavailable` (an outage is
 *   never reported as a bad credential)
 *
 * A missing issuer or audience in the config throws: the check is never skipped.
 * `nowMs` is injectable for tests. The token never appears in a result.
 */
export async function verifyMcpAccessToken(
  authorization: string | undefined,
  config: McpResourceServerConfig,
  nowMs: number = Date.now(),
): Promise<VerifyMcpAccessTokenResult> {
  const fn = "verifyMcpAccessToken";
  requireNonEmpty(fn, "issuer", config.issuer);
  requireNonEmpty(fn, "audience", config.audience);
  requireNonEmpty(fn, "realm", config.realm);
  requireAbsoluteUrl(fn, "resourceMetadataUrl", config.resourceMetadataUrl);
  const door = config.door ?? DEFAULT_DOOR;

  const deny = (
    reason: "bearer-missing" | "bearer-malformed" | "token-invalid",
    error: "invalid_request" | "invalid_token",
    detail: string,
  ): VerifyMcpAccessTokenResult => ({
    ok: false,
    refusal: refusal("CREDENTIAL_REFUSED", reason, door, detail),
    ...unauthorizedChallenge({
      realm: config.realm,
      resourceMetadataUrl: config.resourceMetadataUrl,
      error,
    }),
  });

  if (authorization === undefined || authorization === null || authorization === "") {
    return deny("bearer-missing", "invalid_request", "No Authorization header was presented.");
  }
  const match = /^bearer[ \t]+(\S+)[ \t]*$/i.exec(authorization);
  if (!match || !match[1]) {
    return deny("bearer-malformed", "invalid_request", "The Authorization header is not a Bearer credential.");
  }

  const verified = await verifyClerkSessionToken(
    match[1],
    {
      issuer: config.issuer,
      jwks: config.jwks,
      audience: config.audience,
      clockToleranceSeconds: config.clockToleranceSeconds,
    },
    nowMs,
  );
  if (verified.ok) return { ok: true, session: verified.session };

  if (verified.refusal.reason === "jwks-unavailable") {
    return {
      ok: false,
      status: 503,
      refusal: refusal(
        "CREDENTIAL_REFUSED",
        "jwks-unavailable",
        door,
        "The signing keys could not be retrieved; retry later.",
      ),
    };
  }
  return deny("token-invalid", "invalid_token", "The access token was refused.");
}
