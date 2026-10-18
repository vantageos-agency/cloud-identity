import { createClerkClient } from "@clerk/backend";
import {
  type AuthorizeConfig,
  type AuthorizeDeps,
  type AuthorizeOutcome,
  type ResumeInput,
  resumeAuthorize,
} from "./authorize-flow.js";

/**
 * Resolves the person's Clerk session from the RAW request with Clerk's own
 * handshake, `@clerk/backend` `authenticateRequest()`. No handshake is written
 * here: on a development instance the session cookie lives on the hosted
 * sign-in domain, and only the SDK knows how to bring it to the app host
 * (redirect to the Frontend API handshake endpoint carrying the dev-browser
 * JWT, come back with `__clerk_handshake`, set `__session`).
 *
 * Behind a proxy, give the SDK the public origin through `x-forwarded-host` /
 * `x-forwarded-proto` on the request: the handshake `redirect_url` is derived
 * from them.
 */

export interface ClerkSessionFromRequestOptions {
  secretKey: string;
  publishableKey: string;
  /** Allowed `azp` values of the session token. */
  authorizedParties?: readonly string[];
  /** PEM public key: verifies the token without a call to Clerk's JWKS endpoint. */
  jwtKey?: string;
}

export type ClerkSessionFromRequest =
  | {
      kind: "signed-in";
      /** The verified session JWT, in the shape `ResumeInput.sessionToken` takes. */
      sessionToken: string;
      userId: string;
      sessionId: string | null;
      /** Headers the SDK wants on the response (may be empty). */
      headers: Headers;
    }
  | {
      kind: "handshake";
      /** HTTP status to answer with (a redirect). */
      status: number;
      /** `Location` + `Set-Cookie`: return them as they are. */
      headers: Headers;
    }
  | { kind: "signed-out"; reason: string; headers: Headers };

export async function resolveClerkSessionFromRequest(
  request: Request,
  options: ClerkSessionFromRequestOptions,
): Promise<ClerkSessionFromRequest> {
  const client = createClerkClient({
    secretKey: options.secretKey,
    publishableKey: options.publishableKey,
  });
  // A `__clerk_handshake` that does not verify (not a JWT, signed by another key) is no session.
  // The SDK throws on some of these forms and answers signed-out on others; both become one
  // outcome, and no header of the SDK's is kept: the cookies would come from an untrusted payload.
  const carriesHandshake = new URL(request.url).searchParams.has("__clerk_handshake");
  const invalidHandshake = (): ClerkSessionFromRequest => ({
    kind: "signed-out",
    reason: "handshake-invalid",
    headers: new Headers(),
  });
  let state: Awaited<ReturnType<typeof client.authenticateRequest>>;
  try {
    state = await client.authenticateRequest(request, {
      publishableKey: options.publishableKey,
      secretKey: options.secretKey,
      ...(options.authorizedParties ? { authorizedParties: [...options.authorizedParties] } : {}),
      ...(options.jwtKey ? { jwtKey: options.jwtKey } : {}),
      acceptsToken: "session_token",
    });
  } catch (error) {
    if (carriesHandshake) return invalidHandshake();
    throw error;
  }
  if (carriesHandshake && state.status === "signed-out") return invalidHandshake();
  if (state.status === "handshake") {
    return { kind: "handshake", status: 307, headers: state.headers };
  }
  if (state.status === "signed-in") {
    // The return from the handshake (`__clerk_handshake`) is signed-in AND carries the cookies to
    // set plus a `Location` that strips the handshake parameters. The SDK's contract is to answer
    // that redirect with those headers, as they are: the browser then holds `__session` on this
    // host and the next request is plain signed-in.
    if (state.headers.get("location")) {
      return { kind: "handshake", status: 307, headers: state.headers };
    }
    const auth = state.toAuth();
    return {
      kind: "signed-in",
      sessionToken: state.token,
      userId: auth.userId,
      sessionId: auth.sessionId ?? null,
      headers: state.headers,
    };
  }
  return { kind: "signed-out", reason: String(state.reason ?? "unknown"), headers: state.headers };
}

export interface ClerkSessionForFormPostOptions extends ClerkSessionFromRequestOptions {
  /** The origin the form was served from (scheme + host): the only `Origin` accepted. */
  expectedOrigin: string;
}

/**
 * The session of the person posting a same-origin form (the org picker's
 * Approve / Deny), resolved by the SDK exactly as on the GET that rendered
 * the form.
 *
 * Two facts make reading `__session` by hand wrong here, both measured on a
 * production instance: the cookie is named `__session_<suffix>` (never bare
 * `__session`), and the session JWT is short-lived, so it has often expired
 * by the time the person clicks. `authenticateRequest` reads the suffixed
 * cookie, and refreshes an expired token from `__refresh_<suffix>` — but only
 * for a GET. So the post is checked first (method POST, `Origin` equal to
 * `expectedOrigin`), then the session is resolved from the same URL and
 * cookies as a GET. A redirect (handshake) cannot answer a form post: it is
 * reported as signed-out, and the person starts the authorization again.
 *
 * The consumer must still verify the form's own anti-forgery proof (the
 * consent token): the Origin check bounds where the post may come from, it
 * does not prove what the person saw.
 */
export async function resolveClerkSessionForFormPost(
  request: Request,
  options: ClerkSessionForFormPostOptions,
): Promise<ClerkSessionFromRequest> {
  if (request.method !== "POST") {
    return { kind: "signed-out", reason: "not-a-form-post", headers: new Headers() };
  }
  if (request.headers.get("origin") !== new URL(options.expectedOrigin).origin) {
    return { kind: "signed-out", reason: "cross-origin-post", headers: new Headers() };
  }
  const headers = new Headers(request.headers);
  headers.delete("content-type");
  headers.delete("content-length");
  const asNavigation = new Request(request.url, { method: "GET", headers });
  const { expectedOrigin: _origin, ...clerk } = options;
  const session = await resolveClerkSessionFromRequest(asNavigation, clerk);
  if (session.kind === "handshake") {
    return { kind: "signed-out", reason: "session-needs-handshake", headers: new Headers() };
  }
  return session;
}

export type ResumeFromRequestOutcome =
  | AuthorizeOutcome
  | { kind: "handshake"; status: number; headers: Headers };

/**
 * `resumeAuthorize` fed from the raw request: the session is resolved by the
 * SDK first. `handshake` is returned untouched for the consumer to answer;
 * `signed-out` continues as an absent session (`session-required`).
 */
export async function resumeAuthorizeFromRequest(
  request: Request,
  input: Omit<ResumeInput, "sessionToken">,
  clerk: ClerkSessionFromRequestOptions,
  cfg: AuthorizeConfig,
  deps: AuthorizeDeps,
): Promise<ResumeFromRequestOutcome> {
  const session = await resolveClerkSessionFromRequest(request, clerk);
  if (session.kind === "handshake") return session;
  return resumeAuthorize(
    { ...input, sessionToken: session.kind === "signed-in" ? session.sessionToken : undefined },
    cfg,
    deps,
  );
}
