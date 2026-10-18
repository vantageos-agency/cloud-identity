/**
 * A machine credential a Convex function can validate.
 *
 * A Convex query or mutation never sees a request header, so a service with
 * no human behind it (no Clerk session, no `ctx.auth` identity) cannot present
 * an `Authorization: Bearer` header to it. The credential therefore travels as
 * a function ARGUMENT, and this module resolves it by the same core as
 * `validatePresentedBearer`: digest, indexed lookup, constant-time re-compare,
 * row shape, revocation, expiry. The consumer supplies the lookup and nothing
 * else; the decision is made here.
 *
 * @security The credential, its digest and the claimed organisation never
 * appear in a returned refusal. The consumer stores only the digest.
 */

import { sha256Hex } from "./crypto.js";
import { type IdentityRefusal, refusal } from "./identity-refusal.js";
import { type AgentPresence, type PresentedBearerDeps, resolvePresentedToken } from "./presented-bearer.js";

const MACHINE_CREDENTIAL_PREFIX = "vpmc_";
const MACHINE_CREDENTIAL_BYTES = 32;

/** What a Convex function receives from the calling service. */
export type ConvexMachineCallerInput = {
  /** The machine credential, as minted by `mintMachineCredential`. Never logged. */
  credential: string;
  /** The organisation the caller claims to act for; must equal the stored row's tenant. */
  claimedOrgId: string;
};

export type ConvexMachineCallerDeps = PresentedBearerDeps & {
  /** The consumer's name for the entry point; carried on every refusal. */
  door: string;
};

export type ConvexMachineCallerResult =
  | { ok: true; tenantId: string; agent: AgentPresence; scopes: readonly string[] }
  | { ok: false; refusal: IdentityRefusal };

export type MintedMachineCredential = {
  /** Handed to the service once. Never stored by the consumer. */
  credential: string;
  /** SHA-256 hex digest of `credential`; the only value the consumer stores. */
  secretHash: string;
};

const INVALID_DETAIL = "The machine credential is not valid.";

/**
 * Resolves a machine credential presented as a Convex function argument into
 * its tenant, agent and scopes, or a typed refusal.
 *
 *   - empty or non-string `credential` / `claimedOrgId`: `CREDENTIAL_REFUSED`
 *     `credential-invalid`, without calling the lookup.
 *   - unknown, revoked, expired, malformed row, stored-digest mismatch: the
 *     SAME `CREDENTIAL_REFUSED` `credential-invalid` refusal, so a prober
 *     cannot tell the cases apart. The internal reason still reaches
 *     `deps.onRefusal`.
 *   - the lookup threw: `RBAC_DENIED` `principal-lookup-failed`, so the
 *     consumer can answer "unavailable". Never a grant.
 *   - valid credential, row tenant differs from `claimedOrgId`: `RBAC_DENIED`
 *     `other-organisation`.
 *
 * @callerResolver — resolves a verified caller; consumers may derive their accepted sinks from this tag.
 */
export async function resolveConvexMachineCaller(
  input: ConvexMachineCallerInput,
  deps: ConvexMachineCallerDeps,
): Promise<ConvexMachineCallerResult> {
  if (typeof deps?.lookupBySecretHash !== "function") {
    // A programming error in the consumer, not a claim about any caller.
    throw new TypeError("resolveConvexMachineCaller: deps.lookupBySecretHash must be a function.");
  }
  const door = typeof deps.door === "string" && deps.door !== "" ? deps.door : "resolveConvexMachineCaller";
  const invalid: ConvexMachineCallerResult = {
    ok: false,
    refusal: refusal("CREDENTIAL_REFUSED", "credential-invalid", door, INVALID_DETAIL),
  };

  const credential: unknown = input?.credential;
  const claimedOrgId: unknown = input?.claimedOrgId;
  if (typeof credential !== "string" || credential === "") return invalid;
  if (typeof claimedOrgId !== "string" || claimedOrgId === "") return invalid;

  const result = await resolvePresentedToken(credential, deps);
  if (!result.ok) {
    if (result.error === "unavailable") {
      return {
        ok: false,
        refusal: refusal(
          "RBAC_DENIED",
          "principal-lookup-failed",
          door,
          "The machine credential could not be checked, so no caller is resolved.",
        ),
      };
    }
    return invalid;
  }

  const { identity } = result;
  if (identity.tenantId !== claimedOrgId) {
    return {
      ok: false,
      refusal: refusal(
        "RBAC_DENIED",
        "other-organisation",
        door,
        "The machine credential does not belong to the claimed organisation.",
      ),
    };
  }
  return { ok: true, tenantId: identity.tenantId, agent: identity.agent, scopes: identity.scopes };
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Mints a machine credential: 32 bytes from `crypto.getRandomValues`,
 * base64url, prefixed `vpmc_`, and its SHA-256 hex digest. Store ONLY
 * `secretHash` (with `tenantId`, optional `agentId`, `revoked`, `expiresAt`);
 * hand `credential` to the service once.
 */
export async function mintMachineCredential(): Promise<MintedMachineCredential> {
  const bytes = new Uint8Array(MACHINE_CREDENTIAL_BYTES);
  globalThis.crypto.getRandomValues(bytes);
  const credential = `${MACHINE_CREDENTIAL_PREFIX}${base64Url(bytes)}`;
  return { credential, secretHash: await sha256Hex(credential) };
}
