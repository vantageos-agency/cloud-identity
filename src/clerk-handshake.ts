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
  const state = await client.authenticateRequest(request, {
    publishableKey: options.publishableKey,
    secretKey: options.secretKey,
    ...(options.authorizedParties ? { authorizedParties: [...options.authorizedParties] } : {}),
    ...(options.jwtKey ? { jwtKey: options.jwtKey } : {}),
    acceptsToken: "session_token",
  });
  if (state.status === "handshake") {
    return { kind: "handshake", status: 307, headers: state.headers };
  }
  if (state.status === "signed-in") {
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
