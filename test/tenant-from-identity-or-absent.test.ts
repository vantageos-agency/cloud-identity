import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { build } from "esbuild";
import { beforeAll, describe, expect, it } from "vitest";
import { requireTenantFromIdentity, tenantFromIdentityOrAbsent } from "../src/index.js";
import { resolveOrgFromClaim } from "../src/org-by-id.js";

/**
 * `tenantFromIdentityOrAbsent(identity)`: the NON-throwing sibling of
 * `requireTenantFromIdentity`, for a Convex READ path. It reads the
 * organisation ID claim of an identity the host has already verified and
 * returns `{ present: true, tenantId }` or a typed absence; it never throws.
 *
 * Its claim order is the one a Clerk Convex JWT consumer already reads
 * (`identity.org_id ?? identity.orgId ?? identity.o?.id`): the FIRST claim
 * name that is present (not null/undefined) decides, and an invalid value
 * there is an absence, never a fall-through to the next name. It does not
 * read `organizationId`.
 */

const REPO_ROOT = resolve(__dirname, "..");
const PKG = JSON.parse(readFileSync(resolve(REPO_ROOT, "package.json"), "utf-8"));

type Row = [label: string, identity: Record<string, unknown> | null | undefined, expected: string | null];

// Every row of the measured probe table, pinned as the expected answer.
const PROBE_TABLE: Row[] = [
  ["empty org_id", { org_id: "" }, null],
  ["non-string org_id", { org_id: 5 }, null],
  ["no claim at all", {}, null],
  ["non-string nested o.id", { o: { id: 7 } }, null],
  ["org_id", { org_id: "org_a1" }, "org_a1"],
  ["orgId", { orgId: "org_a1" }, "org_a1"],
  ["rule (a): empty org_id does not fall through to orgId", { org_id: "", orgId: "org_a1" }, null],
  ["rule (a): non-string org_id does not fall through to orgId", { org_id: 5, orgId: "org_a1" }, null],
  ["rule (b): organizationId is not read", { organizationId: "org_a1" }, null],
  ["rule (c): nested o.id is read", { o: { id: "org_a1" } }, "org_a1"],
  // RULING (d), Pi 2026-11-25: the Clerk `org_` shape check applies to this
  // reader too (one shape rule for every door; no live CRM org id lacks
  // `org_`, measured by theta). A non-`org_` value is an absence (REFUSE case).
  // The rule is ONE constant, `IDENTITY_READER_REQUIRES_ORG_SHAPE` in
  // src/claimed-org-id.ts.
  ["ruling (d): a non-org_ value is refused", { org_id: "acme" }, null],
];

describe("tenantFromIdentityOrAbsent: the probe table", () => {
  for (const [label, identity, expected] of PROBE_TABLE) {
    it(`${label}: ${JSON.stringify(identity)} -> ${expected ?? "absent"}`, () => {
      const result = tenantFromIdentityOrAbsent(identity);
      if (expected === null) {
        expect(result.present).toBe(false);
      } else {
        expect(result).toEqual({ present: true, tenantId: expected });
      }
    });
  }
});

describe("tenantFromIdentityOrAbsent: the absence is typed and never thrown", () => {
  it("no identity is an absence with reason no-identity", () => {
    for (const identity of [null, undefined]) {
      expect(tenantFromIdentityOrAbsent(identity)).toEqual({
        present: false,
        absence: { code: "TENANT_ABSENT", reason: "no-identity" },
      });
    }
  });

  it("no claim name present is no-organization-claim", () => {
    for (const identity of [{}, { subject: "user_1" }, { org_id: null, orgId: undefined }, { o: null }, { o: {} }]) {
      expect(tenantFromIdentityOrAbsent(identity)).toEqual({
        present: false,
        absence: { code: "TENANT_ABSENT", reason: "no-organization-claim" },
      });
    }
  });

  it("a present but invalid first claim is invalid-organization-claim", () => {
    for (const identity of [{ org_id: "" }, { org_id: 5 }, { org_id: "", orgId: "org_a1" }, { o: { id: 7 } }]) {
      expect(tenantFromIdentityOrAbsent(identity)).toEqual({
        present: false,
        absence: { code: "TENANT_ABSENT", reason: "invalid-organization-claim" },
      });
    }
  });

  it("a null claim is not present: it falls through like the consumer's ?? chain", () => {
    expect(tenantFromIdentityOrAbsent({ org_id: null, orgId: "org_a1" })).toEqual({
      present: true,
      tenantId: "org_a1",
    });
    expect(tenantFromIdentityOrAbsent({ org_id: undefined, orgId: null, o: { id: "org_b2" } })).toEqual({
      present: true,
      tenantId: "org_b2",
    });
  });

  it("the absence never echoes the claim value", () => {
    expect(JSON.stringify(tenantFromIdentityOrAbsent({ org_id: "acme-secret-slug" }))).not.toContain(
      "acme-secret-slug",
    );
  });
});

describe("the existing claim readers keep their behaviour (one reader, two modes)", () => {
  it("requireTenantFromIdentity still falls through an invalid org_id and still reads organizationId", () => {
    const door = "test:door";
    expect(requireTenantFromIdentity({ org_id: "", orgId: "org_a1" }, { door })).toBe("org_a1");
    expect(requireTenantFromIdentity({ org_id: 5, orgId: "org_a1" }, { door })).toBe("org_a1");
    expect(requireTenantFromIdentity({ organizationId: "org_a1" }, { door })).toBe("org_a1");
    expect(() => requireTenantFromIdentity({ o: { id: "org_a1" } }, { door })).toThrow();
  });

  it("resolveOrgFromClaim still reads organizationId and still falls through an invalid org_id", async () => {
    const row = { id: "org_a1", label: "a", active: true, allowedOrchestrators: [], scopes: [], orgKind: "client" };
    const lookups = { orgById: (id: string) => (id === "org_a1" ? row : null) as never };
    for (const claims of [{ organizationId: "org_a1" }, { org_id: "", orgId: "org_a1" }]) {
      const r = await resolveOrgFromClaim(claims, lookups);
      expect(r.ok, JSON.stringify(claims)).toBe(true);
    }
  });
});

describe("./tenant-from-identity subpath", () => {
  beforeAll(() => {
    const built = resolve(REPO_ROOT, "dist/tenant-from-identity.js");
    if (!existsSync(built) || !readFileSync(built, "utf-8").includes("tenantFromIdentityOrAbsent")) {
      execSync("npm run build", { cwd: REPO_ROOT, stdio: "ignore" });
    }
  }, 120_000);

  it("the exports map declares ./tenant-from-identity with import, require and default", () => {
    expect(PKG.exports["./tenant-from-identity"]).toEqual({
      import: { types: "./dist/tenant-from-identity.d.ts", default: "./dist/tenant-from-identity.js" },
      require: { types: "./dist/cjs/tenant-from-identity.d.ts", default: "./dist/cjs/tenant-from-identity.js" },
      default: "./dist/tenant-from-identity.js",
    });
  });

  it("the root and the subpath hand out the SAME function", async () => {
    const rootMod = (await import("../dist/index.js")) as Record<string, unknown>;
    const narrowMod = (await import("../dist/tenant-from-identity.js")) as Record<string, unknown>;
    expect(typeof narrowMod.tenantFromIdentityOrAbsent).toBe("function");
    expect(narrowMod.tenantFromIdentityOrAbsent).toBe(rootMod.tenantFromIdentityOrAbsent);
  });

  it("a narrow import bundles no @clerk module (usable from a Convex function bundle)", async () => {
    const r = await build({
      stdin: {
        contents: `import { tenantFromIdentityOrAbsent } from "@vantageos/cloud-identity/tenant-from-identity"; export const f = tenantFromIdentityOrAbsent;`,
        resolveDir: REPO_ROOT,
        loader: "js",
      },
      bundle: true,
      write: false,
      platform: "neutral",
      format: "esm",
      metafile: true,
      logLevel: "silent",
      mainFields: ["module", "main"],
      conditions: ["import"],
    });
    expect(Object.keys(r.metafile.inputs).filter((i) => i.includes("@clerk"))).toEqual([]);
  });
});
