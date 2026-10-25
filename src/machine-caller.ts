/**
 * A machine credential a Convex function can validate.
 *
 * A Convex query or mutation never sees a request header, so a service with
 * no human behind it (no Clerk session, no `ctx.auth` identity) cannot present
 * an `Authorization: Bearer` header to it. The credential therefore reaches
 * the function as an ARGUMENT, and this module resolves it by the same core as
 * `validatePresentedBearer`: digest, indexed lookup, constant-time re-compare,
 * row shape, revocation, expiry. The consumer supplies the lookup and nothing
 * else; the decision is made here.
 *
 * @security Pass the DIGEST, never the raw credential. Measured: when any
 * argument of a Convex call fails its validator, Convex echoes the whole
 * argument object, valid fields included, into the caller's error, and that
 * error is persisted in the deployment log. A raw credential in an argument is
 * one malformed call away from a log. Hash at the HTTP boundary with
 * `sha256Hex` and call `resolveConvexMachineCallerFromDigest` in the Convex
 * function. `resolveConvexMachineCaller` (raw credential) stays for callers
 * that already hold the credential in-process; it hashes and runs the same
 * decision.
 *
 * Import from `@vantageos/cloud-identity/machine-caller` in a Convex bundle:
 * the root index re-exports the Clerk handshake and pulls `@clerk/backend` in.
 *
 * @security The credential, its digest and the claimed organisation never
 * appear in a returned refusal. The consumer stores only the digest.
 */

import { sha256Hex } from "./crypto.js";
import { type IdentityRefusal, refusal } from "./identity-refusal.js";
import { type AgentPresence, type PresentedBearerDeps, resolvePresentedDigest } from "./presented-bearer.js";

const MACHINE_CREDENTIAL_PREFIX = "vpmc_";
const MACHINE_CREDENTIAL_BYTES = 32;

/**
 * A raw machine credential and the claimed organisation.
 *
 * @security Not for a Convex function argument: a validation failure on any
 * argument echoes the whole object, credential included, into the error and
 * the deployment log. Use `ConvexMachineCallerDigestInput` there.
 */
export type ConvexMachineCallerInput = {
  /** The machine credential, as minted by `mintMachineCredential`. Never logged. */
  credential: string;
  /** The organisation the caller claims to act for; must equal the stored row's tenant. */
  claimedOrgId: string;
};

/** What a Convex function receives from the calling service: the digest, never the credential. */
export type ConvexMachineCallerDigestInput = {
  /** `sha256Hex(credential)`, computed at the HTTP boundary: 64 lowercase hex characters. */
  credentialDigest: string;
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
 * Resolves a RAW machine credential into its tenant, agent and scopes, or a
 * typed refusal. Hashes the credential with `sha256Hex` and runs exactly the
 * decision of `resolveConvexMachineCallerFromDigest`.
 *
 * @security Do not receive the raw credential as a Convex function argument
 * (see the module note): use `resolveConvexMachineCallerFromDigest`.
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
  const door = doorOf(deps, "resolveConvexMachineCaller");

  const credential: unknown = input?.credential;
  const claimedOrgId: unknown = input?.claimedOrgId;
  if (typeof credential !== "string" || credential === "") return invalidFor(door);
  if (typeof claimedOrgId !== "string" || claimedOrgId === "") return invalidFor(door);

  return decideForOrg(await sha256Hex(credential), claimedOrgId, door, deps);
}

/**
 * Resolves the SHA-256 hex DIGEST of a machine credential, received as a
 * Convex function argument, into its tenant, agent and scopes, or a typed
 * refusal. The entry point a Convex function uses: the calling service hashes
 * the credential with `sha256Hex` at its HTTP boundary and sends only the
 * digest, so a Convex argument-validation error can never echo a usable
 * credential into an error or a log.
 *
 * Same outcomes as `resolveConvexMachineCaller`, through the same code. A
 * `credentialDigest` that is not 64 lowercase hex characters is refused with
 * the SAME `CREDENTIAL_REFUSED` `credential-invalid` as a digest that matches
 * no row, without calling the lookup, so its shape tells a prober nothing.
 *
 * @callerResolver — resolves a verified caller; consumers may derive their accepted sinks from this tag.
 */
export async function resolveConvexMachineCallerFromDigest(
  input: ConvexMachineCallerDigestInput,
  deps: ConvexMachineCallerDeps,
): Promise<ConvexMachineCallerResult> {
  if (typeof deps?.lookupBySecretHash !== "function") {
    // A programming error in the consumer, not a claim about any caller.
    throw new TypeError("resolveConvexMachineCallerFromDigest: deps.lookupBySecretHash must be a function.");
  }
  const door = doorOf(deps, "resolveConvexMachineCallerFromDigest");

  const credentialDigest: unknown = input?.credentialDigest;
  const claimedOrgId: unknown = input?.claimedOrgId;
  // A non-string digest is refused here; a string of the wrong shape is
  // refused inside the shared decision. Both are the same `credential-invalid`
  // a wrong digest gets, so the digest's shape tells a prober nothing.
  if (typeof credentialDigest !== "string") return invalidFor(door);
  if (typeof claimedOrgId !== "string" || claimedOrgId === "") return invalidFor(door);

  return decideForOrg(credentialDigest, claimedOrgId, door, deps);
}

function doorOf(deps: ConvexMachineCallerDeps, fallback: string): string {
  return typeof deps.door === "string" && deps.door !== "" ? deps.door : fallback;
}

function invalidFor(door: string): ConvexMachineCallerResult {
  return {
    ok: false,
    refusal: refusal("CREDENTIAL_REFUSED", "credential-invalid", door, INVALID_DETAIL),
  };
}

/** The ONE machine-caller decision, shared by the raw and the digest entry points. */
async function decideForOrg(
  credentialDigest: string,
  claimedOrgId: string,
  door: string,
  deps: ConvexMachineCallerDeps,
): Promise<ConvexMachineCallerResult> {
  const result = await resolvePresentedDigest(credentialDigest, deps);
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
    return invalidFor(door);
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
