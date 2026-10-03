import {
  type AuthorizeRefusal,
  PKCE_METHOD,
  refusal,
} from "./authorize-shared.js";
import type { AuthorizedTokenClaims } from "./token-exchange.js";

/** Inputs of the discovery document. Every endpoint is an absolute URL. */
export interface DiscoveryConfig {
  issuer: string;
  authorizationEndpoint: string;
  tokenEndpoint: string;
  jwksUri: string;
  userinfoEndpoint: string;
  registrationEndpoint?: string;
  scopesSupported?: readonly string[];
}

export interface DiscoveryDocument {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  jwks_uri: string;
  userinfo_endpoint: string;
  registration_endpoint?: string;
  response_types_supported: string[];
  response_modes_supported: string[];
  grant_types_supported: string[];
  subject_types_supported: string[];
  scopes_supported: string[];
  code_challenge_methods_supported: string[];
  claims_supported: string[];
}

export type DiscoveryResult =
  | { ok: true; document: DiscoveryDocument }
  | { ok: false; refusal: AuthorizeRefusal };

function isAbsoluteUrl(value: string, requireHttps: boolean): boolean {
  try {
    const u = new URL(value);
    if (u.protocol === "https:") return true;
    return (
      !requireHttps &&
      u.protocol === "http:" &&
      (u.hostname === "localhost" || u.hostname === "127.0.0.1")
    );
  } catch {
    return false;
  }
}

/**
 * Builds the discovery document (OAuth authorization-server metadata with the
 * OIDC fields this package honours). It advertises only what is implemented:
 * the code flow, PKCE, the `authorization_code` grant, UserInfo. It does NOT
 * advertise id_tokens, refresh tokens or client-authentication methods; the
 * consumer may add those keys to the returned object if it implements them. The issuer must be an https URL with no query or fragment (plain
 * http only for loopback); every endpoint must be an absolute URL.
 */
export function buildDiscoveryDocument(config: DiscoveryConfig): DiscoveryResult {
  const bad: DiscoveryResult = { ok: false, refusal: refusal("issuer-invalid") };
  if (!isAbsoluteUrl(config.issuer, true)) return bad;
  const issuer = new URL(config.issuer);
  if (issuer.search !== "" || issuer.hash !== "") return bad;
  const endpoints = [
    config.authorizationEndpoint,
    config.tokenEndpoint,
    config.jwksUri,
    config.userinfoEndpoint,
    ...(config.registrationEndpoint ? [config.registrationEndpoint] : []),
  ];
  if (!endpoints.every((e) => isAbsoluteUrl(e, true))) return bad;

  const document: DiscoveryDocument = {
    issuer: config.issuer,
    authorization_endpoint: config.authorizationEndpoint,
    token_endpoint: config.tokenEndpoint,
    jwks_uri: config.jwksUri,
    userinfo_endpoint: config.userinfoEndpoint,
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: ["authorization_code"],
    subject_types_supported: ["public"],
    scopes_supported: [...(config.scopesSupported ?? ["openid", "email"])],
    code_challenge_methods_supported: [PKCE_METHOD],
    claims_supported: ["sub", "email", "email_verified"],
  };
  if (config.registrationEndpoint) {
    document.registration_endpoint = config.registrationEndpoint;
  }
  return { ok: true, document };
}

/** The subset of a Clerk user the UserInfo helper reads. */
export interface ClerkUserLike {
  id: string;
  primaryEmailAddressId?: string | null;
  emailAddresses: readonly {
    id: string;
    emailAddress: string;
    verification?: { status?: string | null } | null;
  }[];
}

export interface UserInfo {
  sub: string;
  email?: string;
  email_verified?: boolean;
}

export type UserInfoResult =
  | { ok: true; userinfo: UserInfo }
  | { ok: false; refusal: AuthorizeRefusal };

/**
 * Builds the UserInfo response from the Clerk user and the claims of the
 * presented token. The token must carry `openid`; the user must be the token's
 * subject; `email` and `email_verified` appear only when the token also
 * carries `email` AND the user has a primary address. `email_verified` is true
 * only for a Clerk verification status of exactly `verified`.
 */
export function buildUserInfo(
  claims: Pick<AuthorizedTokenClaims, "sub" | "scope">,
  user: ClerkUserLike,
): UserInfoResult {
  const scopes = claims.scope.split(/\s+/);
  if (!scopes.includes("openid")) {
    return { ok: false, refusal: refusal("openid-scope-required") };
  }
  if (user.id !== claims.sub) {
    return { ok: false, refusal: refusal("subject-mismatch") };
  }
  const userinfo: UserInfo = { sub: user.id };
  if (scopes.includes("email")) {
    const primary = user.emailAddresses.find(
      (a) => a.id === user.primaryEmailAddressId,
    );
    if (primary) {
      userinfo.email = primary.emailAddress;
      userinfo.email_verified = primary.verification?.status === "verified";
    }
  }
  return { ok: true, userinfo };
}
