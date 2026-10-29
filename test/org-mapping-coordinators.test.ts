/**
 * 0.29.0 — `orgMappingRowSchema.addressableFleetCoordinatorIds`: the roster of
 * operator-organisation agent IDs a client organisation stores as reachable.
 * Exposed on `ResolvedOrg` exactly like `allowedAgentIds`; every existing
 * reader ignores it. The package has no roster builder: a consumer's
 * `RecipientLookups.rosterOf` reads the field.
 */

import { describe, it, expect } from "vitest";
import {
  assertRecipientAddressable,
  orgMappingRowSchema,
  resolveOrgFromClaim,
  findOperatorOrg,
} from "../src/index.js";

const row = (over: Record<string, unknown> = {}) => ({
  id: "org_a",
  label: "org-a",
  active: true,
  scopes: ["tasks"],
  orgKind: "client",
  ...over,
});
const byId = (r: unknown) => ({ orgById: async () => r as never });

describe("addressableFleetCoordinatorIds (0.29.0)", () => {
  it("present: exposed on the resolved org", async () => {
    const r = await resolveOrgFromClaim(
      { org_id: "org_a" },
      byId(row({ addressableFleetCoordinatorIds: ["agent_c1", "agent_c2"] })),
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.org.addressableFleetCoordinatorIds).toEqual(["agent_c1", "agent_c2"]);
  });

  it("empty: stays empty", async () => {
    const r = await resolveOrgFromClaim(
      { org_id: "org_a" },
      byId(row({ addressableFleetCoordinatorIds: [] })),
    );
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.org.addressableFleetCoordinatorIds).toEqual([]);
  });

  it("absent: stays absent (no key)", async () => {
    const r = await resolveOrgFromClaim({ org_id: "org_a" }, byId(row()));
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect("addressableFleetCoordinatorIds" in r.org).toBe(false);
  });

  it.each([
    ["not an array", "agent_c1"],
    ["an empty ID", [""]],
    ["a non-string ID", [7]],
    ["null", null],
  ])("malformed (%s) refuses the row", async (_n, bad) => {
    const r = await resolveOrgFromClaim(
      { org_id: "org_a" },
      byId(row({ addressableFleetCoordinatorIds: bad })),
    );
    expect(r.ok).toBe(false);
    if (r.ok) return;
    expect(r.refusal.reason).toBe("org-mapping-record-invalid");
  });

  it("the schema accepts the field and other readers are unaffected by it", async () => {
    expect(orgMappingRowSchema.safeParse(row({ addressableFleetCoordinatorIds: ["x"] })).success).toBe(true);
    const found = await findOperatorOrg({
      activeOrganisations: () => [
        row({ orgKind: "operator", addressableFleetCoordinatorIds: ["x"] }),
      ],
    });
    expect(found.kind).toBe("one");
  });

  it("feeds RecipientLookups.rosterOf: a roster built from the resolved org admits a listed coordinator", async () => {
    const r = await resolveOrgFromClaim(
      { org_id: "org_a" },
      byId(row({ addressableFleetCoordinatorIds: ["agent_c1"] })),
    );
    if (!r.ok) throw new Error("expected ok");
    const lookups = {
      orgKindOf: async (id: string) => (id === "org_a" ? "client" : "operator"),
      rosterOf: async (orgId: string) =>
        r.org.addressableFleetCoordinatorIds === undefined
          ? null
          : { orgId, principalIds: r.org.addressableFleetCoordinatorIds },
    };
    const sender = { principalId: "agent_s", orgId: "org_a", kind: "agent" as const };
    const ok = await assertRecipientAddressable(sender, { agentId: "agent_c1", orgId: "org_op" }, lookups as never);
    expect(ok.ok).toBe(true);
    const no = await assertRecipientAddressable(sender, { agentId: "agent_other", orgId: "org_op" }, lookups as never);
    expect(no.ok).toBe(false);
  });
});
