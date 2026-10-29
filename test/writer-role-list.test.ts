/**
 * 0.30.0 — the writer-role list per organisation with a fleet default.
 *
 * Selection (the data is passed in; the package never reads a store):
 *   1. a list for the caller's org (present, even empty) -> that list;
 *   2. else the fleet default list;
 *   3. else NO list -> refusal. A missing or empty list never means "all roles".
 * `resolveWriterRole` (unchanged) takes ONE list; it cannot tell "this org has
 * no row" from "this org has an empty row", so selection is new.
 */

import { describe, it, expect } from "vitest";
import { selectWriterRoles, resolveWriterRoleForOrg } from "../src/person-principal.js";

describe("selectWriterRoles — org list, else fleet default, else none", () => {
  it("an org list wins over the fleet default", () => {
    expect(selectWriterRoles(["org:admin"], ["org:admin", "org:editor"])).toEqual({
      source: "org",
      roles: ["org:admin"],
    });
  });

  it("an EMPTY org list is the org's answer: nobody writes, no fallback to the default", () => {
    expect(selectWriterRoles([], ["org:admin"])).toEqual({ source: "org", roles: [] });
  });

  it("an absent (undefined or null) org list falls back to the fleet default", () => {
    expect(selectWriterRoles(undefined, ["org:admin"])).toEqual({ source: "fleet-default", roles: ["org:admin"] });
    expect(selectWriterRoles(null, ["org:admin"])).toEqual({ source: "fleet-default", roles: ["org:admin"] });
  });

  it("an empty fleet default is still the default's answer", () => {
    expect(selectWriterRoles(undefined, [])).toEqual({ source: "fleet-default", roles: [] });
  });

  it("no org list and no default is NONE, with no roles", () => {
    expect(selectWriterRoles(undefined, undefined)).toEqual({ source: "none", roles: [] });
    expect(selectWriterRoles(null, null)).toEqual({ source: "none", roles: [] });
  });

  it("a malformed org list is the org's (empty) answer: it never falls through to the default", () => {
    for (const bad of ["org:admin", 7, {}, ["org:admin", 3], [""]] as unknown[]) {
      expect(selectWriterRoles(bad as string[], ["org:admin"])).toEqual({ source: "org", roles: [] });
    }
  });

  it("a malformed fleet default selects nothing", () => {
    for (const bad of ["org:admin", 7, {}, ["x", null], [""]] as unknown[]) {
      expect(selectWriterRoles(undefined, bad as string[])).toEqual({ source: "fleet-default", roles: [] });
    }
  });

  it("returns a copy: mutating the result leaves the input intact", () => {
    const orgList = ["org:admin"];
    const sel = selectWriterRoles(orgList, undefined);
    (sel.roles as string[]).push("org:intruder");
    expect(orgList).toEqual(["org:admin"]);
  });
});

describe("resolveWriterRoleForOrg — the decision over the selected list", () => {
  const base = { door: "tasks:start", orgSlug: "acme-hr" };

  it("allows a role on the org's own list", () => {
    expect(resolveWriterRoleForOrg({ ...base, role: "org:editor", orgRoles: ["org:editor"], fleetDefaultRoles: ["org:admin"] })).toEqual({ ok: true });
  });

  it("refuses a role that is on the fleet default but not on the org's own list", () => {
    const r = resolveWriterRoleForOrg({ ...base, role: "org:admin", orgRoles: ["org:editor"], fleetDefaultRoles: ["org:admin"] });
    expect(r).toMatchObject({ ok: false, refusal: { code: "RBAC_DENIED", reason: "role-not-writer", door: "tasks:start", role: "org:admin", orgSlug: "acme-hr" } });
  });

  it("with no org row, the fleet default decides", () => {
    expect(resolveWriterRoleForOrg({ ...base, role: "org:admin", orgRoles: undefined, fleetDefaultRoles: ["org:admin"] })).toEqual({ ok: true });
    expect(resolveWriterRoleForOrg({ ...base, role: "org:viewer", orgRoles: null, fleetDefaultRoles: ["org:admin"] })).toMatchObject({ ok: false });
  });

  it("with no list anywhere, everyone is refused (never 'all roles')", () => {
    for (const role of ["org:admin", "org:member", "", null, undefined]) {
      expect(resolveWriterRoleForOrg({ ...base, role, orgRoles: undefined, fleetDefaultRoles: undefined })).toMatchObject({ ok: false, refusal: { reason: "role-not-writer" } });
    }
  });

  it("an empty org list refuses even a role the default would admit", () => {
    expect(resolveWriterRoleForOrg({ ...base, role: "org:admin", orgRoles: [], fleetDefaultRoles: ["org:admin"] })).toMatchObject({ ok: false });
  });

  it("an absent role is refused whatever the lists", () => {
    expect(resolveWriterRoleForOrg({ ...base, role: undefined, orgRoles: ["org:admin"], fleetDefaultRoles: ["org:admin"] })).toMatchObject({ ok: false });
  });

  it("the role must match exactly: no hierarchy, no inheritance", () => {
    expect(resolveWriterRoleForOrg({ ...base, role: "org:admin ", orgRoles: ["org:admin"], fleetDefaultRoles: undefined })).toMatchObject({ ok: false });
  });
});
