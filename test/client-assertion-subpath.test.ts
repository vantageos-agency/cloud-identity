import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";

/**
 * `./client-assertion` is a subpath ONLY. It imports `node:net` (BlockList) and
 * `node:dns/promises` for its SSRF guard, so re-exporting it from the root would make the
 * root unbundleable on a platform without Node built-ins (a Convex function, an edge worker).
 */
const REPO_ROOT = resolve(__dirname, "..");
const PKG = JSON.parse(readFileSync(resolve(REPO_ROOT, "package.json"), "utf-8"));

beforeAll(() => {
  const built = resolve(REPO_ROOT, "dist/client-assertion.js");
  if (!existsSync(built) || !readFileSync(built, "utf-8").includes("createClientAssertionVerifier")) {
    execSync("npx tsc", { cwd: REPO_ROOT, stdio: "ignore" });
  }
}, 60_000);

describe("./client-assertion subpath", () => {
  it("the exports map declares ./client-assertion -> dist/client-assertion.{js,d.ts}", () => {
    expect(PKG.exports["./client-assertion"]).toEqual({
      types: "./dist/client-assertion.d.ts",
      import: "./dist/client-assertion.js",
    });
  });

  it("the built subpath hands out the verifier, the jti store and the guard", async () => {
    const mod = await import("../dist/client-assertion.js");
    for (const name of [
      "createClientAssertionVerifier",
      "createJtiStore",
      "fetchGuardedJson",
      "resolveCimdDocument",
      "isPublicAddress",
      "isUrlShapedClientId",
      "isAllowedRedirectUri",
    ]) {
      expect(typeof (mod as Record<string, unknown>)[name], name).toBe("function");
    }
    expect(mod.JWT_BEARER_ASSERTION_TYPE).toBe(
      "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
    );
  });

  it("the root does NOT re-export it (the root stays free of node:net / node:dns)", async () => {
    const rootMod = (await import("../dist/index.js")) as Record<string, unknown>;
    expect(rootMod.createClientAssertionVerifier).toBeUndefined();
    expect(rootMod.isPublicAddress).toBeUndefined();
    const rootJs = readFileSync(resolve(REPO_ROOT, "dist/index.js"), "utf-8");
    expect(rootJs).not.toMatch(/client-assertion/);
  });
});
