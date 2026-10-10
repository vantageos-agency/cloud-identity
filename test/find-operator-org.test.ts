import { describe, expect, it } from "vitest";
import { findOperatorOrg } from "../src/index.js";

/**
 * Find the operator organisation from stored mapping rows. Exactly one active
 * row of kind "operator" is the operator; none, several, an over-cap read, an
 * unreadable store and a malformed row are each a typed non-answer, and none of
 * them is ever decided from.
 */

const row = (over: Record<string, unknown> = {}) => ({
  id: "org_op",
  label: "operator",
  active: true,
  allowedOrchestrators: ["*"],
  scopes: ["read"],
  orgKind: "operator",
  ...over,
});
const lookups = (rows: unknown[]) => ({ activeOrganisations: () => rows });

describe("findOperatorOrg", () => {
  it("returns the single active operator with its ID and label", async () => {
    const r = await findOperatorOrg(lookups([row(), row({ id: "org_c", label: "c", orgKind: "client" })]));
    expect(r).toEqual({ kind: "one", org: { id: "org_op", label: "operator" } });
  });

  it("returns the operator without an ID while its mapping has none yet", async () => {
    const r = await findOperatorOrg(lookups([row({ id: undefined })]));
    expect(r).toEqual({ kind: "one", org: { id: undefined, label: "operator" } });
  });

  it("returns none when no active operator exists", async () => {
    expect(await findOperatorOrg(lookups([row({ orgKind: "client" })]))).toEqual({ kind: "none" });
    expect(await findOperatorOrg(lookups([]))).toEqual({ kind: "none" });
    expect(await findOperatorOrg(lookups([row({ active: false })]))).toEqual({ kind: "none" });
  });

  it("returns many, with the count, when two operators are active", async () => {
    const r = await findOperatorOrg(lookups([row(), row({ id: "org_op2", label: "op2" })]));
    expect(r).toEqual({ kind: "many", count: 2 });
  });

  it("reads one row past the cap and answers overCap when it is filled", async () => {
    const seen: number[] = [];
    const r = await findOperatorOrg(
      {
        activeOrganisations: (limit: number) => {
          seen.push(limit);
          return Array.from({ length: limit }, (_, i) =>
            row({ id: `org_${i}`, label: `l${i}`, orgKind: "client" }),
          );
        },
      },
      { cap: 3 },
    );
    expect(seen).toEqual([4]);
    expect(r).toEqual({ kind: "overCap" });
  });

  it("defaults the cap to 1000", async () => {
    const seen: number[] = [];
    await findOperatorOrg({
      activeOrganisations: (limit: number) => {
        seen.push(limit);
        return [];
      },
    });
    expect(seen).toEqual([1001]);
  });

  it("answers unreadable when the adapter is missing, throws, or returns a non-list", async () => {
    expect(await findOperatorOrg({})).toEqual({ kind: "unreadable" });
    expect(await findOperatorOrg(null)).toEqual({ kind: "unreadable" });
    expect(
      await findOperatorOrg({
        activeOrganisations: () => {
          throw new Error("db down");
        },
      }),
    ).toEqual({ kind: "unreadable" });
    expect(await findOperatorOrg({ activeOrganisations: () => null })).toEqual({ kind: "unreadable" });
  });

  it("answers unreadable when any row is malformed, never skipping it", async () => {
    expect(await findOperatorOrg(lookups([row(), { id: "org_x" }]))).toEqual({ kind: "unreadable" });
    expect(await findOperatorOrg(lookups([row({ id: "" })]))).toEqual({ kind: "unreadable" });
  });

  it("does not take any other kind value for the operator", async () => {
    expect(await findOperatorOrg(lookups([row({ orgKind: "Operator" })]))).toEqual({ kind: "none" });
    expect(await findOperatorOrg(lookups([row({ orgKind: undefined })]))).toEqual({ kind: "none" });
  });
});
