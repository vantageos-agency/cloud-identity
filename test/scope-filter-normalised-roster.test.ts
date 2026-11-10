import { describe, expect, it } from "vitest";
import {
  isMasterScope,
  passesScopeFilter,
  scopeFilterGet,
  scopeFilterList,
} from "../src/scope-filter.js";
import type { OAuthCtx } from "../src/types.js";

// Task k1726h1v7hqdbk818bn8s1rgdx8hy0ts. Stored actor labels are normalised
// (NFC, lowercase, trim) while the roster holds the agent's exact stored name.
// The scope filters compare both sides in the normalised form.

const adaCtx: OAuthCtx = {
  scope: "tenant",
  fromAllowList: ["Ada"],
  namespaceReadPrefixes: [],
  namespaceWritePrefixes: [],
};

describe("scope filters: roster names compared in normalised form", () => {
  it("roster ['Ada'] admits a row whose createdBy is 'ada'", () => {
    expect(passesScopeFilter(adaCtx, { createdBy: "ada" })).toBe(true);
  });

  it("roster ['Ada'] still admits a row whose createdBy is 'Ada'", () => {
    expect(passesScopeFilter(adaCtx, { createdBy: "Ada" })).toBe(true);
  });

  it("roster ['Ada'] admits 'ADA' and ' ada ' (both sides normalised)", () => {
    expect(passesScopeFilter(adaCtx, { createdBy: "ADA" })).toBe(true);
    expect(passesScopeFilter(adaCtx, { createdBy: " ada " })).toBe(true);
  });

  it("NFD and NFC spellings of the same name match", () => {
    const ctx: OAuthCtx = { ...adaCtx, fromAllowList: ["Élan"] };
    expect(passesScopeFilter(ctx, { createdBy: "élan" })).toBe(true);
  });

  it("roster ['Ada'] still refuses 'bram'", () => {
    expect(passesScopeFilter(adaCtx, { createdBy: "bram" })).toBe(false);
    expect(passesScopeFilter(adaCtx, { createdBy: "Bram" })).toBe(false);
  });

  it("accents do not fold: roster ['Elan'] refuses 'élan'", () => {
    const ctx: OAuthCtx = { ...adaCtx, fromAllowList: ["Elan"] };
    expect(passesScopeFilter(ctx, { createdBy: "élan" })).toBe(false);
  });

  it("a whitespace-only label never matches a whitespace-only roster entry", () => {
    const ctx: OAuthCtx = { ...adaCtx, fromAllowList: ["  "] };
    expect(passesScopeFilter(ctx, { createdBy: " " })).toBe(false);
    expect(passesScopeFilter(ctx, { pilot: "\t" } as never, ["pilot"])).toBe(false);
  });

  it("grant fields: string and array values compare normalised", () => {
    expect(passesScopeFilter(adaCtx, { pilot: "ada" } as never, ["pilot"])).toBe(true);
    expect(
      passesScopeFilter(adaCtx, { agents: ["bram", "ada"] } as never, ["agents"]),
    ).toBe(true);
    expect(
      passesScopeFilter(adaCtx, { agents: ["bram", "cleo"] } as never, ["agents"]),
    ).toBe(false);
  });

  it("scopeFilterGet returns the 'ada' row and nulls the 'bram' row", () => {
    const own = { createdBy: "ada" };
    expect(scopeFilterGet(adaCtx, own)).toBe(own);
    expect(scopeFilterGet(adaCtx, { createdBy: "bram" })).toBeNull();
  });

  it("scopeFilterList keeps 'ada' and 'Ada', drops 'bram'", () => {
    const rows = [{ createdBy: "ada" }, { createdBy: "Ada" }, { createdBy: "bram" }];
    expect(scopeFilterList(adaCtx, rows)).toEqual([rows[0], rows[1]]);
  });

  it("wildcard unchanged: '*' in the roster is master, a non-wildcard roster is not", () => {
    const star: OAuthCtx = { ...adaCtx, fromAllowList: ["*"] };
    expect(isMasterScope(star)).toBe(true);
    expect(passesScopeFilter(star, { createdBy: "bram" })).toBe(true);
    expect(isMasterScope(adaCtx)).toBe(false);
    expect(passesScopeFilter(adaCtx, { createdBy: "*" })).toBe(false);
  });

  it("the caller's roster is not mutated", () => {
    const list = ["Ada"];
    const ctx: OAuthCtx = { ...adaCtx, fromAllowList: list };
    passesScopeFilter(ctx, { createdBy: "ada" });
    expect(list).toEqual(["Ada"]);
  });
});
