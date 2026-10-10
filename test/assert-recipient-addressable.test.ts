import { describe, expect, it } from "vitest";
import {
  type ActingPrincipal,
  assertRecipientAddressable,
  type OrgKind,
} from "../src/index.js";

/**
 * May a sender address a recipient, across organisations, by AGENT ID only.
 * Same org; client -> operator when the recipient is on the sender org's
 * roster; operator -> client when the sender is on the recipient org's roster.
 * Everything else refuses, and a name never decides.
 */

const FLEET = "org_fleet";
const KINDS: Record<string, OrgKind> = { org_fleet: "operator", org_a: "client", org_b: "client" };
const ROSTERS: Record<string, { orgId: string; principalIds: string[] }> = {
  org_a: { orgId: "org_a", principalIds: ["fleet_coord"] },
  org_b: { orgId: "org_b", principalIds: ["fleet_other"] },
};

const lookups = {
  orgKindOf: (orgId: string) => KINDS[orgId],
  rosterOf: (orgId: string) => ROSTERS[orgId],
};

const CLIENT_AGENT: ActingPrincipal = { principalId: "a_1", orgId: "org_a", kind: "agent" };
const FLEET_AGENT: ActingPrincipal = { principalId: "fleet_coord", orgId: FLEET, kind: "agent" };

type Result = Awaited<ReturnType<typeof assertRecipientAddressable>>;
function refusedWith(result: Result) {
  expect(result.ok).toBe(false);
  if (result.ok) throw new Error("expected a refusal");
  return result.refusal;
}

describe("assertRecipientAddressable", () => {
  it("same org: admitted", async () => {
    const r = await assertRecipientAddressable(CLIENT_AGENT, { agentId: "a_2", orgId: "org_a" }, lookups);
    expect(r).toEqual({ ok: true });
  });

  it("client -> fleet: a listed recipient ID is admitted", async () => {
    const r = await assertRecipientAddressable(CLIENT_AGENT, { agentId: "fleet_coord", orgId: FLEET }, lookups);
    expect(r).toEqual({ ok: true });
  });

  it("client -> fleet: an unlisted recipient ID is refused", async () => {
    const r = refusedWith(
      await assertRecipientAddressable(CLIENT_AGENT, { agentId: "fleet_x", orgId: FLEET }, lookups, {
        door: "send_message",
      }),
    );
    expect(r.code).toBe("RBAC_DENIED");
    expect(r.reason).toBe("principal-not-listed");
    expect(r.door).toBe("send_message");
  });

  it("fleet -> client: admitted when the sender is on the recipient org roster", async () => {
    const r = await assertRecipientAddressable(FLEET_AGENT, { agentId: "a_1", orgId: "org_a" }, lookups);
    expect(r).toEqual({ ok: true });
  });

  it("fleet -> client: refused when the sender is not rostered", async () => {
    const r = refusedWith(
      await assertRecipientAddressable(FLEET_AGENT, { agentId: "b_1", orgId: "org_b" }, lookups),
    );
    expect(r.reason).toBe("principal-not-listed");
    expect(r.door).toBe("assertRecipientAddressable");
  });

  it("client A -> client B: refused", async () => {
    const r = refusedWith(
      await assertRecipientAddressable(CLIENT_AGENT, { agentId: "b_1", orgId: "org_b" }, lookups),
    );
    expect(r.reason).toBe("target-other-organisation");
  });

  it("a same NAME in another org never matches; only the ID does", async () => {
    const sameName = { agentId: "eta", orgId: FLEET };
    const r = refusedWith(await assertRecipientAddressable(CLIENT_AGENT, sameName, lookups));
    expect(r.reason).toBe("principal-not-listed");
    const namedRoster = {
      ...lookups,
      rosterOf: () => ({ orgId: "org_a", principalIds: ["eta"] }),
    };
    // the roster lists the ID "eta"; an agent whose ID is "eta" matches, nothing else does
    expect(await assertRecipientAddressable(CLIENT_AGENT, sameName, namedRoster)).toEqual({ ok: true });
    const other = await assertRecipientAddressable(
      CLIENT_AGENT,
      { agentId: "Eta", orgId: FLEET },
      namedRoster,
    );
    expect(refusedWith(other).reason).toBe("principal-not-listed");
  });

  it("a recipient or sender carrying only a name is refused", async () => {
    const nameOnly = { name: "fleet_coord", orgId: FLEET } as unknown as { agentId: string; orgId: string };
    expect(refusedWith(await assertRecipientAddressable(CLIENT_AGENT, nameOnly, lookups)).reason).toBe(
      "target-unstamped",
    );
    const senderName = { name: "a_1", orgId: "org_a", kind: "agent" } as unknown as ActingPrincipal;
    expect(
      refusedWith(await assertRecipientAddressable(senderName, { agentId: "a_2", orgId: "org_a" }, lookups))
        .reason,
    ).toBe("credential-invalid");
  });

  it("a missing or unresolvable roster is refused", async () => {
    const to = { agentId: "fleet_coord", orgId: FLEET };
    expect(
      refusedWith(await assertRecipientAddressable(CLIENT_AGENT, to, { ...lookups, rosterOf: () => null }))
        .reason,
    ).toBe("list-absent");
    expect(
      refusedWith(
        await assertRecipientAddressable(CLIENT_AGENT, to, {
          ...lookups,
          rosterOf: () => {
            throw new Error("boom");
          },
        }),
      ).reason,
    ).toBe("principal-lookup-failed");
    const { rosterOf: _omit, ...noRoster } = lookups;
    expect(
      refusedWith(await assertRecipientAddressable(CLIENT_AGENT, to, noRoster as typeof lookups)).reason,
    ).toBe("principal-lookup-failed");
    expect(
      refusedWith(
        await assertRecipientAddressable(CLIENT_AGENT, to, {
          ...lookups,
          rosterOf: () => ({ orgId: "org_b", principalIds: ["fleet_coord"] }),
        }),
      ).reason,
    ).toBe("target-other-organisation");
  });

  it("a missing sender or recipient is refused", async () => {
    const to = { agentId: "a_2", orgId: "org_a" };
    expect(refusedWith(await assertRecipientAddressable(null, to, lookups)).reason).toBe("credential-invalid");
    expect(refusedWith(await assertRecipientAddressable(undefined, to, lookups)).reason).toBe(
      "credential-invalid",
    );
    expect(refusedWith(await assertRecipientAddressable(CLIENT_AGENT, null, lookups)).reason).toBe(
      "target-unstamped",
    );
    expect(refusedWith(await assertRecipientAddressable(CLIENT_AGENT, undefined, lookups)).reason).toBe(
      "target-unstamped",
    );
    expect(
      refusedWith(await assertRecipientAddressable(CLIENT_AGENT, { agentId: "", orgId: "org_a" }, lookups))
        .reason,
    ).toBe("target-unstamped");
  });

  it("a sender that is not an agent is refused, even in its own org", async () => {
    for (const kind of ["person", "service", "fleet"] as const) {
      const r = await assertRecipientAddressable(
        { ...CLIENT_AGENT, kind },
        { agentId: "a_2", orgId: "org_a" },
        lookups,
      );
      expect(refusedWith(r).reason).toBe("principal-not-an-agent");
    }
  });

  it("an unknown or unreadable org kind is refused", async () => {
    const to = { agentId: "x", orgId: "org_zzz" };
    expect(
      refusedWith(await assertRecipientAddressable(CLIENT_AGENT, to, lookups)).reason,
    ).toBe("target-other-organisation");
    expect(
      refusedWith(
        await assertRecipientAddressable(CLIENT_AGENT, to, {
          ...lookups,
          orgKindOf: () => {
            throw new Error("boom");
          },
        }),
      ).reason,
    ).toBe("principal-lookup-failed");
  });
  it("an operator agent acting through a service account is matched on its own ID, never the carrier's", async () => {
    const viaSa: ActingPrincipal = {
      principalId: "agent-x",
      orgId: FLEET,
      kind: "agent",
      viaServiceAccountId: "sa-1",
    };
    const saRoster = {
      ...lookups,
      rosterOf: () => ({ orgId: "org_a", principalIds: ["sa-1"] }),
    };
    const r = refusedWith(await assertRecipientAddressable(viaSa, { agentId: "a_1", orgId: "org_a" }, saRoster));
    expect(r.reason).toBe("principal-not-listed");
  });

  it("the same-org shortcut is byte-equal: org_a and ORG_A are not the same organisation", async () => {
    const r = refusedWith(
      await assertRecipientAddressable(CLIENT_AGENT, { agentId: "a_2", orgId: "ORG_A" }, lookups),
    );
    expect(r.reason).toBe("target-other-organisation");
  });
});
