import { describe, expect, it } from "vitest";
import { isFleetStamp } from "../src/index.js";

/**
 * Is a tenant stamp the fleet's: unstamped, or the operator organisation's?
 * The operator is supplied by the caller (read from stored data); when there is
 * not exactly one it is `undefined` and only an unstamped row is the fleet's.
 */

const OPERATOR = { id: "org_op", label: "operator" } as const;
describe("isFleetStamp", () => {
  it("treats an unstamped row as the fleet's, with or without an operator", () => {
    expect(isFleetStamp({}, OPERATOR)).toBe(true);
    expect(isFleetStamp({}, undefined)).toBe(true);
    expect(isFleetStamp(null, undefined)).toBe(true);
    expect(isFleetStamp(undefined, OPERATOR)).toBe(true);
    expect(isFleetStamp({ id: null, label: null }, OPERATOR)).toBe(true);
  });

  it("treats a row stamped with the operator's ID as the fleet's", () => {
    expect(isFleetStamp({ id: "org_op" }, OPERATOR)).toBe(true);
    expect(isFleetStamp({ id: "org_op", label: "renamed" }, OPERATOR)).toBe(true);
  });

  it("refuses a stamped row when there is no single operator", () => {
    expect(isFleetStamp({ id: "org_op" }, undefined)).toBe(false);
    expect(isFleetStamp({ label: "operator" }, undefined)).toBe(false);
  });

  it("refuses another organisation's ID, even under the operator's label", () => {
    expect(isFleetStamp({ id: "org_x" }, OPERATOR)).toBe(false);
    expect(isFleetStamp({ id: "org_x", label: "operator" }, OPERATOR)).toBe(false);
  });

  it("never matches a label-only stamp, even under the operator's label", () => {
    expect(isFleetStamp({ label: "operator" }, OPERATOR)).toBe(false);
    expect(isFleetStamp({ label: "client" }, OPERATOR)).toBe(false);
  });

  it("does not take an empty-string stamp for an unstamped one", () => {
    expect(isFleetStamp({ id: "" }, OPERATOR)).toBe(false);
    expect(isFleetStamp({ label: "" }, OPERATOR)).toBe(false);
  });
});
