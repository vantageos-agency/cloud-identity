/**
 * May a name a caller TYPED into a call be treated as the acting agent?
 *
 * A typed name is a CLAIM, never an authority. The decision is taken on the
 * caller the consumer already resolved BY ID (an agent credential, a seat
 * stamped with its agent, a master context); the typed name is only compared to
 * that resolved agent's own stored label, and it can never override it. This is
 * the one name comparison the decision needs: claimed against the label of an
 * identity that was proven by ID, never a name selecting or proving an identity.
 *
 * Pure: no lookup, no clock, no environment read, no Convex, no Clerk. The
 * consumer classifies its resolved caller into one {@link ActingCaller} kind and
 * passes the mode explicitly.
 *
 * Rows (rows 6 and 7 are read in the order 7, 6: both admit, so the outcome is the
 * same, and `via` then says a seat naming itself is not an unattributed call):
 *
 *   1. no caller (or a malformed one)       refused (RBAC_DENIED)
 *   2. `agent-credential`                   claim equals the agent's label, else
 *                                           AGENT_IDENTITY_MISMATCH, in EVERY mode
 *   3. `seat`                               the same equality, in EVERY mode
 *   4. `master-bearer`                      AGENT_CREDENTIAL_REQUIRED, in EVERY mode
 *   5. `master-scope`                       passes (it is not an agent and already
 *                                           reaches every row; a name widens nothing)
 *   6. mode `"permissive"` (explicit)       passes, marked unattributed
 *   7. `seat-unresolved`, one own label     passes when the claim equals the single
 *                                           allowlisted label
 *   8. anything else                        AGENT_CREDENTIAL_REQUIRED
 *
 * Row 7 belongs to its own caller kind, not to `org-member`: the local rule it
 * replaces is a TRANSITIONAL exemption for a seat whose provider could not stamp
 * the agent (the stamp is ABSENT, not null). A seat stamped with an agent is row
 * 3; an organisation-level seat (stamped null), a person token and a session
 * are `org-member`, which has no exemption at all. Whether a token qualifies as
 * `seat-unresolved` (an opaque-token context with no principal, not a master) is
 * the consumer's classification; this function only checks the allowlist is
 * exactly one real label and the claim equals it.
 *
 * Mode: an EXPLICIT input. Its absence, and any value other than the exact
 * string `"permissive"`, is strict. A right is presented, never inferred from an
 * absence, so a consumer that forgets to read its switch is strict.
 */

import { normalizeLabel } from "./label-normal.js";

/** The caller, as the consumer already resolved it BY ID. */
export type ActingCaller =
  | {
      kind: "agent-credential";
      /** The agent's permanent ID, from the verified credential. */
      agentId: string;
      /** The agent's own stored label. Compared to the claim, never used to find the agent. */
      agentLabel: string;
      /** The organisation the credential resolved in, for the refusal. */
      orgSlug: string;
    }
  | {
      kind: "seat";
      /** The agent the seat token resolved to by ID, in the token's own organisation. */
      agentId: string;
      /** That agent's own stored label. */
      agentLabel: string;
      orgId: string;
    }
  | {
      kind: "seat-unresolved";
      /** The token's own allowlist; exempt only when exactly one real (non-wildcard) label. */
      allowlist: readonly string[];
    }
  | { kind: "master-bearer" }
  | { kind: "master-scope" }
  | { kind: "org-member" };

export type ActingClaimMode = "strict" | "permissive";

export type ActingClaimInput = {
  /** What the caller typed into the call. */
  claimed: string;
  /** The resolved caller; `null` when the request carried no context at all. */
  caller: ActingCaller | null;
  /** Absent means strict. Only the exact string "permissive" admits a typed name. */
  mode?: ActingClaimMode;
  /** The consumer's own name for the door; carried on every refusal. */
  door?: string;
};

export type ActingClaimRefusalCode =
  | "RBAC_DENIED"
  | "AGENT_IDENTITY_MISMATCH"
  | "AGENT_CREDENTIAL_REQUIRED";

export type ActingClaimRefusalReason =
  | "no-context"
  | "caller-invalid"
  | "claim-invalid"
  | "agent-identity-mismatch"
  | "agent-credential-required";

export type ActingClaimRefusal = {
  code: ActingClaimRefusalCode;
  reason: ActingClaimRefusalReason;
  door: string;
  /** One sentence, safe to show to the caller. Never a credential. */
  detail: string;
  /** The typed claim, when it is a string. */
  claimed?: string;
  /** The agent the caller resolved to, on an identity mismatch. */
  resolved?: { agentId: string; agentLabel: string; org: string };
};

/**
 * How an accepted claim was admitted:
 *   resolved-agent         the claim equals the ID-resolved agent's label
 *   master-scope           a trusted all-authority context; no agent
 *   seat-own-label         a seat naming its own single allowlisted label
 *   permissive-unattributed  admitted only because the mode is explicitly
 *                          permissive: the consumer records the call UNATTRIBUTED
 */
export type ActingClaimVia =
  | "resolved-agent"
  | "master-scope"
  | "seat-own-label"
  | "permissive-unattributed";

export type ActingClaimResult =
  | { ok: true; via: ActingClaimVia }
  | { ok: false; refusal: ActingClaimRefusal };

const DEFAULT_DOOR = "decideActingClaim";

function isNonEmpty(value: unknown): value is string {
  return typeof value === "string" && value.trim() !== "";
}

/**
 * Decides whether the typed claim may be treated as the acting agent, or
 * refuses with a typed, code-carrying value. Never throws on malformed input.
 */
export function decideActingClaim(input: ActingClaimInput): ActingClaimResult {
  const door = typeof input?.door === "string" && input.door !== "" ? input.door : DEFAULT_DOOR;
  const claimed: unknown = input?.claimed;
  const caller: unknown = input?.caller;

  const deny = (
    code: ActingClaimRefusalCode,
    reason: ActingClaimRefusalReason,
    detail: string,
    extra: Pick<ActingClaimRefusal, "resolved"> = {},
  ): ActingClaimResult => ({
    ok: false,
    refusal: {
      code,
      reason,
      door,
      detail,
      ...(typeof claimed === "string" ? { claimed } : {}),
      ...extra,
    },
  });

  // Row 1: absence is never authority.
  if (caller === null || caller === undefined) {
    return deny("RBAC_DENIED", "no-context", "no authorization context on this request: a scope decision was reached without an identity");
  }
  if (typeof claimed !== "string") {
    return deny("RBAC_DENIED", "claim-invalid", "the acting claim is not a string");
  }
  const who = caller as ActingCaller;
  const required = () =>
    deny(
      "AGENT_CREDENTIAL_REQUIRED",
      "agent-credential-required",
      `this call names "${claimed}" but the request carried no per-agent credential: an organisation-level credential authenticates the organisation, not an agent, so a typed name is not accepted as an identity`,
    );

  switch (who.kind) {
    // Rows 2 and 3: an identity resolved BY ID is authoritative in every mode.
    case "agent-credential":
    case "seat": {
      if (!isNonEmpty(who.agentId) || !isNonEmpty(who.agentLabel)) {
        return deny("RBAC_DENIED", "caller-invalid", "the resolved agent carries no ID or no label");
      }
      if (normalizeLabel(claimed) === normalizeLabel(who.agentLabel)) {
        return { ok: true, via: "resolved-agent" };
      }
      const org = who.kind === "agent-credential" ? who.orgSlug : who.orgId;
      return deny(
        "AGENT_IDENTITY_MISMATCH",
        "agent-identity-mismatch",
        `this call names "${claimed}" but the caller resolves to agent "${who.agentLabel}" (${who.agentId}, org "${String(org)}"): a caller may only act under its own resolved identity; omit the name to act as the resolved agent`,
        { resolved: { agentId: who.agentId, agentLabel: who.agentLabel, org: String(org) } },
      );
    }
    // Row 4: a fleet credential is strict regardless of the mode.
    case "master-bearer":
      return required();
    // Row 5: the trusted local context is not an agent; a name widens nothing.
    case "master-scope":
      return { ok: true, via: "master-scope" };
    case "seat-unresolved":
    case "org-member": {
      // Row 7, read first so a seat naming itself is never marked unattributed
      // (the outcome is the same as row 6; only `via` differs).
      if (who.kind === "seat-unresolved" && Array.isArray(who.allowlist) && who.allowlist.length === 1) {
        const only = typeof who.allowlist[0] === "string" ? normalizeLabel(who.allowlist[0]) : "";
        if (only !== "" && only !== "*" && normalizeLabel(claimed) === only) {
          return { ok: true, via: "seat-own-label" };
        }
      }
      // Row 6: permissive is reached only by the exact string, never by absence.
      if (input.mode === "permissive") {
        return { ok: true, via: "permissive-unattributed" };
      }
      // Row 8.
      return required();
    }
    default:
      return deny("RBAC_DENIED", "caller-invalid", "the caller is of a kind this decision does not know");
  }
}
