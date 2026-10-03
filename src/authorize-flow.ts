import {
  type AuthorizeRefusal,
  MIN_SECRET_LENGTH,
  PKCE_METHOD,
  isWellFormedChallenge,
  refusal,
  signBlob,
  signMac,
  utf8,
  toBase64Url,
  verifyBlob,
} from "./authorize-shared.js";
import { sha256Hex, timingSafeEqual } from "./crypto.js";
import {
  type ClerkSessionVerifierConfig,
  type VerifiedClerkSession,
  verifyClerkSessionToken,
} from "./clerk-session.js";

/**
 * The authorize flow for a PERSON: a Clerk session, a verified organisation
 * membership, and an authorization code bound to both. Framework-agnostic:
 * every function takes plain values and returns a plain outcome; the consumer
 * owns HTTP, rendering and storage.
 *
 * The code is bound to `{ clerkUserId, orgId, orgSlug, orgRole, clientId,
 * redirectUri, codeChallenge, resource }`. Nothing is read from a
 * client-registration profile: a client's own fields only decide whether the
 * request is acceptable, never what the person may reach.
 */

// ---------------------------------------------------------------------------
// Collaborator shapes (supplied by the consumer)
// ---------------------------------------------------------------------------

/** A registered OAuth client, as the consumer's own registry knows it. */
export interface AuthorizeClient {
  clientId: string;
  /** Exact-match list; no prefix, wildcard or partial match is ever applied. */
  redirectUris: readonly string[];
  clientName?: string;
  revoked?: boolean;
}

/** One organisation membership, in the shape Clerk's Backend API returns. */
export interface ClerkOrgMembership {
  role: string;
  organization: { id: string; slug: string | null; name: string };
}

/** A stored authorization code. Only the digest of the code is stored. */
export interface AuthorizationCodeRecord {
  codeHash: string;
  clerkUserId: string;
  orgId: string;
  orgSlug: string | null;
  orgRole: string;
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  resource: string;
  scope: string;
  /** Epoch milliseconds. */
  expiresAt: number;
}

export type ConsumeCodeResult =
  | { status: "ok"; record: AuthorizationCodeRecord }
  | { status: "unknown" }
  | { status: "already-used" };

/**
 * Where codes live. `consume` MUST be atomic: of two concurrent calls for the
 * same digest exactly one gets `ok`. A read-then-write is not an
 * implementation of this interface.
 */
export interface AuthorizationCodeStore {
  put(record: AuthorizationCodeRecord): Promise<void>;
  consume(codeHash: string): Promise<ConsumeCodeResult>;
}

export interface AuthorizeConfig {
  /** HMAC secret for the state blob; at least 32 characters. Never sent to a client. */
  stateSecret: string;
  /** Clerk sign-in page. The return URL travels in `redirect_url`. */
  signInUrl: string;
  /** The consumer's endpoint that calls `resumeAuthorize`. */
  callbackUrl: string;
  /** Resource identifiers (RFC 8707) this server issues codes for. Exact match. */
  allowedResources: readonly string[];
  /** When set, every requested scope must be listed. */
  supportedScopes?: readonly string[];
  /** Scope granted when the request names none. Default `"openid"`. */
  defaultScope?: string;
  /** Verification of the Clerk session token. */
  session: ClerkSessionVerifierConfig;
  /** Seconds the signed state stays valid. Default 600. */
  stateTtlSeconds?: number;
  /** Seconds an authorization code stays valid. Default 60. */
  codeTtlSeconds?: number;
  /**
   * The person must explicitly approve (the outcome is a consent model, not a
   * code, until `approved: true` is posted back). DEFAULT TRUE: without it, any
   * dynamically registered client could obtain a code for a signed-in victim
   * who merely follows a link. Set `false` explicitly only for first-party
   * clients whose redirect URIs you control; a single organisation is then
   * auto-picked.
   */
  requireConsent?: boolean;
}

export interface AuthorizeDeps {
  lookupClient(clientId: string): Promise<AuthorizeClient | null>;
  /** Clerk Backend API: the user's organisation memberships. */
  listMemberships(clerkUserId: string): Promise<readonly ClerkOrgMembership[]>;
  codeStore: AuthorizationCodeStore;
  /** Epoch milliseconds. */
  now?: () => number;
  /** Opaque code generator; default 32 random bytes, base64url. */
  generateCode?: () => string;
}

// ---------------------------------------------------------------------------
// Outcomes
// ---------------------------------------------------------------------------

export interface OrgPickerModel {
  /** Signed state; post it back, untouched, to `resumeAuthorize`. */
  state: string;
  client: { clientId: string; clientName: string | null };
  resource: string;
  scope: string;
  /** Only organisations the verified user is a member of. */
  organizations: readonly {
    id: string;
    slug: string | null;
    name: string;
    role: string;
  }[];
  /** True when the person must tick approval even with one organisation. */
  consentRequired: boolean;
  /**
   * Proof that THIS picker was shown to THIS verified user for THIS state.
   * Render it as a hidden field and post it back as `consentToken`. Absent
   * when consent is not required.
   */
  consentToken: string | null;
}

export type AuthorizeOutcome =
  | { kind: "redirect-to-sign-in"; url: string }
  | { kind: "org-picker"; model: OrgPickerModel }
  | { kind: "redirect-to-client"; url: string }
  | { kind: "refused"; refusal: AuthorizeRefusal };

export interface ResumeInput {
  /** The `authorize_state` query parameter on the return URL (or the picker's posted state). */
  state: string;
  /** The Clerk session token presented on return. */
  sessionToken: string | undefined;
  /** The organisation the person chose in the picker. */
  orgId?: string;
  /** The person's explicit approval, when `requireConsent` is on. */
  approved?: boolean;
  /** The `consentToken` of the picker the person was shown. Required with `approved: true` when consent is on. */
  consentToken?: string;
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

interface ValidatedRequest {
  clientId: string;
  redirectUri: string;
  state: string | null;
  codeChallenge: string;
  resource: string;
  scope: string;
}

interface StatePayload {
  v: 1;
  cid: string;
  ru: string;
  st: string | null;
  cc: string;
  rs: string;
  sc: string;
  exp: number;
}

const STATE_PARAM = "authorize_state";

const refused = (reason: Parameters<typeof refusal>[0]): AuthorizeOutcome => ({
  kind: "refused",
  refusal: refusal(reason),
});

function nowOf(deps: AuthorizeDeps): number {
  return (deps.now ?? Date.now)();
}

function configOk(cfg: AuthorizeConfig): boolean {
  return (
    typeof cfg.stateSecret === "string" &&
    cfg.stateSecret.length >= MIN_SECRET_LENGTH &&
    cfg.allowedResources.length > 0
  );
}

function validateRequest(
  params: Readonly<Record<string, string | undefined>>,
  client: AuthorizeClient,
  cfg: AuthorizeConfig,
): { ok: true; req: ValidatedRequest } | { ok: false; reason: Parameters<typeof refusal>[0] } {
  if (client.revoked === true) return { ok: false, reason: "unknown-client" };
  const redirectUri = params.redirect_uri;
  if (!redirectUri || !client.redirectUris.includes(redirectUri)) {
    return { ok: false, reason: "redirect-uri-mismatch" };
  }
  if (params.response_type !== undefined && params.response_type !== "code") {
    return { ok: false, reason: "unsupported-response-type" };
  }
  const challenge = params.code_challenge;
  const method = params.code_challenge_method ?? PKCE_METHOD;
  if (!challenge || method !== PKCE_METHOD || !isWellFormedChallenge(challenge)) {
    return { ok: false, reason: "pkce-required" };
  }
  const resource = params.resource;
  if (!resource || !cfg.allowedResources.includes(resource)) {
    return { ok: false, reason: "resource-not-allowed" };
  }
  const scope = (params.scope ?? "").trim() || (cfg.defaultScope ?? "openid");
  if (cfg.supportedScopes) {
    const supported = cfg.supportedScopes;
    if (!scope.split(/\s+/).every((s) => supported.includes(s))) {
      return { ok: false, reason: "scope-not-supported" };
    }
  }
  return {
    ok: true,
    req: {
      clientId: client.clientId,
      redirectUri,
      state: params.state ?? null,
      codeChallenge: challenge,
      resource,
      scope,
    },
  };
}

async function signState(
  req: ValidatedRequest,
  cfg: AuthorizeConfig,
  deps: AuthorizeDeps,
): Promise<string> {
  const payload: StatePayload = {
    v: 1,
    cid: req.clientId,
    ru: req.redirectUri,
    st: req.state,
    cc: req.codeChallenge,
    rs: req.resource,
    sc: req.scope,
    exp: nowOf(deps) + (cfg.stateTtlSeconds ?? 600) * 1000,
  };
  return signBlob(payload, cfg.stateSecret);
}

function signInRedirect(cfg: AuthorizeConfig, stateBlob: string): AuthorizeOutcome {
  const back = new URL(cfg.callbackUrl);
  back.searchParams.set(STATE_PARAM, stateBlob);
  const url = new URL(cfg.signInUrl);
  url.searchParams.set("redirect_url", back.toString());
  return { kind: "redirect-to-sign-in", url: url.toString() };
}

async function lookupClientSafe(
  deps: AuthorizeDeps,
  clientId: string,
): Promise<{ ok: true; client: AuthorizeClient | null } | { ok: false }> {
  try {
    return { ok: true, client: await deps.lookupClient(clientId) };
  } catch {
    return { ok: false };
  }
}

async function bindAndIssue(
  req: ValidatedRequest,
  stateBlob: string,
  session: VerifiedClerkSession,
  clientName: string | null,
  choice: { orgId?: string; approved?: boolean; consentToken?: string },
  cfg: AuthorizeConfig,
  deps: AuthorizeDeps,
): Promise<AuthorizeOutcome> {
  let memberships: readonly ClerkOrgMembership[];
  try {
    memberships = await deps.listMemberships(session.userId);
  } catch {
    return refused("membership-lookup-unavailable");
  }
  if (memberships.length === 0) return refused("no-organization");

  let picked: ClerkOrgMembership | undefined;
  if (choice.orgId !== undefined) {
    // The chosen id is a CLAIM from the browser: it is honoured only if the
    // verified user's own membership list contains it.
    picked = memberships.find((m) => m.organization.id === choice.orgId);
    if (!picked) return refused("org-not-a-member");
  } else if (memberships.length === 1) {
    picked = memberships[0];
  }

  const consentRequired = cfg.requireConsent !== false;
  // The token binds the picker to the verified user, the signed state and the
  // set of organisations that user belongs to (the set is what was shown).
  const expectedToken = consentRequired
    ? await consentTokenFor(
        cfg.stateSecret,
        stateBlob,
        session.userId,
        memberships.map((m) => m.organization.id),
      )
    : null;
  if (consentRequired && picked && choice.approved === true) {
    // `approved: true` is a CLAIM in a POST body. An attacker client can mint
    // its own state and replay it with a victim's session; only a token the
    // server issued to this user for this state proves the picker was shown.
    const presented = choice.consentToken;
    const ok =
      typeof presented === "string" &&
      expectedToken !== null &&
      (await timingSafeEqual(utf8(presented), utf8(expectedToken)));
    if (!ok) return refused("consent-required");
  }
  if (!picked || (consentRequired && choice.approved !== true)) {
    return {
      kind: "org-picker",
      model: {
        state: stateBlob,
        client: { clientId: req.clientId, clientName },
        resource: req.resource,
        scope: req.scope,
        organizations: memberships.map((m) => ({
          id: m.organization.id,
          slug: m.organization.slug,
          name: m.organization.name,
          role: m.role,
        })),
        consentRequired,
        consentToken: expectedToken,
      },
    };
  }

  const code = (deps.generateCode ?? randomCode)();
  const record: AuthorizationCodeRecord = {
    codeHash: await sha256Hex(code),
    clerkUserId: session.userId,
    orgId: picked.organization.id,
    orgSlug: picked.organization.slug,
    orgRole: picked.role,
    clientId: req.clientId,
    redirectUri: req.redirectUri,
    codeChallenge: req.codeChallenge,
    resource: req.resource,
    scope: req.scope,
    expiresAt: nowOf(deps) + (cfg.codeTtlSeconds ?? 60) * 1000,
  };
  try {
    await deps.codeStore.put(record);
  } catch {
    return refused("code-store-unavailable");
  }
  const back = new URL(req.redirectUri);
  back.searchParams.set("code", code);
  if (req.state !== null) back.searchParams.set("state", req.state);
  return { kind: "redirect-to-client", url: back.toString() };
}

/**
 * `HMAC(stateSecret, "consent-v1\0" + state + "\0" + clerkUserId + "\0" +
 * sorted organisation ids joined by ",")`. Bound to the exact state blob (so a
 * token for one request is useless for another), to the verified user (so it
 * cannot be replayed under another session) and to the organisation set shown
 * (the chosen org is separately required to be in the live membership list).
 */
async function consentTokenFor(
  secret: string,
  state: string,
  userId: string,
  orgIds: readonly string[],
): Promise<string> {
  const set = [...orgIds].sort().join(",");
  return signMac(`consent-v1\0${state}\0${userId}\0${set}`, secret);
}

function randomCode(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

// ---------------------------------------------------------------------------
// Public functions
// ---------------------------------------------------------------------------

/**
 * Handles `GET /authorize`. Validates the request against the registered
 * client, then:
 *   - no Clerk session (absent, expired or forged) -> `redirect-to-sign-in`,
 *     carrying a signed, short-lived state blob and issuing NO code;
 *   - a verified session -> continues exactly as `resumeAuthorize` does.
 * A Clerk key set that cannot be reached is a refusal (`jwks-unavailable`),
 * never a redirect and never a grant.
 */
export async function startAuthorize(
  params: Readonly<Record<string, string | undefined>>,
  sessionToken: string | undefined,
  cfg: AuthorizeConfig,
  deps: AuthorizeDeps,
): Promise<AuthorizeOutcome> {
  if (!configOk(cfg)) return refused("server-misconfigured");
  const clientId = params.client_id;
  if (!clientId) return refused("invalid-request");
  const found = await lookupClientSafe(deps, clientId);
  if (!found.ok) return refused("client-lookup-unavailable");
  if (!found.client) return refused("unknown-client");
  const v = validateRequest(params, found.client, cfg);
  if (!v.ok) return refused(v.reason);

  const stateBlob = await signState(v.req, cfg, deps);
  if (!sessionToken) return signInRedirect(cfg, stateBlob);
  const verified = await verifyClerkSessionToken(
    sessionToken,
    cfg.session,
    nowOf(deps),
  );
  if (!verified.ok) {
    return verified.refusal.reason === "jwks-unavailable"
      ? { kind: "refused", refusal: verified.refusal }
      : signInRedirect(cfg, stateBlob);
  }
  return bindAndIssue(v.req, stateBlob, verified.session, found.client.clientName ?? null, {}, cfg, deps);
}

/**
 * Handles the return from Clerk (and the picker's form post). The request is
 * rebuilt ONLY from the signed state: no query parameter other than the blob
 * itself is read. A tampered or expired blob is refused; the client is looked
 * up again so a client revoked mid-flow gets no code.
 */
export async function resumeAuthorize(
  input: ResumeInput,
  cfg: AuthorizeConfig,
  deps: AuthorizeDeps,
): Promise<AuthorizeOutcome> {
  if (!configOk(cfg)) return refused("server-misconfigured");
  const raw =
    typeof input.state === "string" ? await verifyBlob(input.state, cfg.stateSecret) : null;
  const p = raw as Partial<StatePayload> | null;
  if (
    !p ||
    p.v !== 1 ||
    typeof p.cid !== "string" ||
    typeof p.ru !== "string" ||
    typeof p.cc !== "string" ||
    typeof p.rs !== "string" ||
    typeof p.sc !== "string" ||
    typeof p.exp !== "number" ||
    (p.st !== null && typeof p.st !== "string")
  ) {
    return refused("state-invalid");
  }
  if (p.exp <= nowOf(deps)) return refused("state-expired");

  const found = await lookupClientSafe(deps, p.cid);
  if (!found.ok) return refused("client-lookup-unavailable");
  if (!found.client) return refused("unknown-client");
  const v = validateRequest(
    {
      redirect_uri: p.ru,
      code_challenge: p.cc,
      resource: p.rs,
      scope: p.sc,
      ...(p.st !== null && p.st !== undefined ? { state: p.st } : {}),
    },
    found.client,
    cfg,
  );
  if (!v.ok) return refused(v.reason);

  if (!input.sessionToken) return refused("session-required");
  const verified = await verifyClerkSessionToken(
    input.sessionToken,
    cfg.session,
    nowOf(deps),
  );
  if (!verified.ok) return { kind: "refused", refusal: verified.refusal };

  return bindAndIssue(
    v.req,
    input.state,
    verified.session,
    found.client.clientName ?? null,
    { orgId: input.orgId, approved: input.approved, consentToken: input.consentToken },
    cfg,
    deps,
  );
}
