import { execFileSync, execSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/**
 * 0.37.0: the package loads from CommonJS as well as from ESM.
 *
 * Before, every `exports` entry carried only `types` + `import`, so
 * `require("@vantageos/cloud-identity")` from a CommonJS consumer threw
 * ERR_PACKAGE_PATH_NOT_EXPORTED. The build now emits a second tree,
 * `dist/cjs/`, marked `{"type":"commonjs"}`, and each entry routes `import`
 * to `dist/` and `require` to `dist/cjs/`, each with its own declarations.
 *
 * Proven by REAL consumers, never by reading the map alone: a throwaway
 * directory whose `node_modules/@vantageos/cloud-identity` links to this
 * checkout, and a child `node` process that `require`s (and `import`s) the
 * root and every subpath through the published `exports` map.
 */

const REPO_ROOT = resolve(__dirname, "..");
const PKG = JSON.parse(readFileSync(resolve(REPO_ROOT, "package.json"), "utf-8")) as {
  exports: Record<string, unknown>;
};
const SUBPATHS = Object.keys(PKG.exports);

let consumer: string;

beforeAll(() => {
  if (!existsSync(resolve(REPO_ROOT, "dist/cjs/index.js")) || !existsSync(resolve(REPO_ROOT, "dist/index.js"))) {
    execSync("npm run build", { cwd: REPO_ROOT, stdio: "ignore" });
  }
  consumer = mkdtempSync(join(tmpdir(), "cloud-identity-consumer-"));
  mkdirSync(join(consumer, "node_modules", "@vantageos"), { recursive: true });
  symlinkSync(REPO_ROOT, join(consumer, "node_modules", "@vantageos", "cloud-identity"), "dir");
}, 120_000);

afterAll(() => {
  if (consumer) rmSync(consumer, { recursive: true, force: true });
});

function runNode(args: string[]): string {
  return execFileSync(process.execPath, args, { cwd: consumer, encoding: "utf-8" });
}

function specOf(subpath: string): string {
  return subpath === "." ? "@vantageos/cloud-identity" : `@vantageos/cloud-identity/${subpath.slice(2)}`;
}

describe("the exports map routes import and require separately", () => {
  it("every entry declares import and require, each with its own types and default, and a default fallback", () => {
    for (const subpath of SUBPATHS) {
      const entry = PKG.exports[subpath] as Record<string, Record<string, string> | string>;
      const imp = entry.import as Record<string, string>;
      const req = entry.require as Record<string, string>;
      expect(Object.keys(entry), subpath).toEqual(["import", "require", "default"]);
      expect(imp.types, subpath).toMatch(/^\.\/dist\/[a-z-]+\.d\.ts$/);
      expect(imp.default, subpath).toMatch(/^\.\/dist\/[a-z-]+\.js$/);
      expect(req.types, subpath).toBe(imp.types.replace("./dist/", "./dist/cjs/"));
      expect(req.default, subpath).toBe(imp.default.replace("./dist/", "./dist/cjs/"));
      expect(entry.default, subpath).toBe(imp.default);
      for (const file of [imp.types, imp.default, req.types, req.default]) {
        expect(existsSync(resolve(REPO_ROOT, file)), file).toBe(true);
      }
    }
  });

  it("dist/cjs is marked CommonJS so Node and TypeScript read its .js and .d.ts as CommonJS", () => {
    expect(JSON.parse(readFileSync(resolve(REPO_ROOT, "dist/cjs/package.json"), "utf-8"))).toEqual({
      type: "commonjs",
    });
  });
});

describe("a real CommonJS consumer and a real ESM consumer", () => {
  it("require() of the root and of every subpath returns a non-empty module", () => {
    const script = `
      const out = {};
      for (const s of ${JSON.stringify(SUBPATHS.map(specOf))}) out[s] = Object.keys(require(s)).length;
      process.stdout.write(JSON.stringify(out));
    `;
    const counts = JSON.parse(runNode(["-e", script])) as Record<string, number>;
    for (const subpath of SUBPATHS) expect(counts[specOf(subpath)], subpath).toBeGreaterThan(0);
  }, 60_000);

  it("import of the root and of every subpath returns the same export names as require", () => {
    const specs = JSON.stringify(SUBPATHS.map(specOf));
    const esm = JSON.parse(
      runNode([
        "--input-type=module",
        "-e",
        `const out = {}; for (const s of ${specs}) out[s] = Object.keys(await import(s)).filter((k) => k !== "default").sort(); process.stdout.write(JSON.stringify(out));`,
      ]),
    ) as Record<string, string[]>;
    const cjs = JSON.parse(
      runNode([
        "-e",
        `const out = {}; for (const s of ${specs}) out[s] = Object.keys(require(s)).filter((k) => k !== "__esModule").sort(); process.stdout.write(JSON.stringify(out));`,
      ]),
    ) as Record<string, string[]>;
    expect(cjs).toEqual(esm);
  }, 60_000);

  it("the CommonJS build decides as the ESM build does, both directions, for the new primitives", () => {
    const probe = (loader: string) => `
      const m = ${loader};
      const policy = { ladder: ["cloud-admin", "admin", "write", "read"], offLadder: ["workflow-trigger"], superscopes: ["cloud-admin"] };
      let mismatch = "none";
      try { m.requireWorkspaceMatchesToken({ workspaceId: "ws_a" }, { workspaceId: "ws_b" }); } catch (e) { mismatch = e.refusal.reason; }
      process.stdout.write(JSON.stringify({
        adminWrite: m.hasScopeGrant(["admin"], "write", policy),
        adminTrigger: m.hasScopeGrant(["admin"], "workflow-trigger", policy),
        same: m.requireWorkspaceMatchesToken({ workspaceId: "ws_a" }, { workspaceId: "ws_a" }),
        mismatch,
      }));
    `;
    const expected = { adminWrite: true, adminTrigger: false, same: "ws_a", mismatch: "workspace-mismatch" };
    expect(JSON.parse(runNode(["-e", probe(`require("@vantageos/cloud-identity")`)]))).toEqual(expected);
    expect(
      JSON.parse(runNode(["--input-type=module", "-e", probe(`await import("@vantageos/cloud-identity")`)])),
    ).toEqual(expected);
    const subpaths = `Object.assign({}, require("@vantageos/cloud-identity/role-policy"), require("@vantageos/cloud-identity/tenant-membership"))`;
    expect(JSON.parse(runNode(["-e", probe(subpaths)]))).toEqual(expected);
  }, 60_000);
});
