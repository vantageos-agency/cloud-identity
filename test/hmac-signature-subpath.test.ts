import { execSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { build } from "esbuild";
import { beforeAll, describe, expect, it } from "vitest";

/** `./hmac-signature` is a narrow subpath: it bundles no @clerk module and no node:crypto. */
const REPO_ROOT = resolve(__dirname, "..");
const PKG = JSON.parse(readFileSync(resolve(REPO_ROOT, "package.json"), "utf-8"));

async function bundle(spec: string) {
  const r = await build({
    stdin: {
      contents: `import { verifyHmacSha256Signature as f } from "${spec}"; export { f };`,
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
  return {
    inputs: Object.keys(r.metafile.inputs),
    code: r.outputFiles[0].text,
  };
}

beforeAll(() => {
  execSync("npx tsc", { cwd: REPO_ROOT, stdio: "ignore" });
});

describe("./hmac-signature subpath", () => {
  it("the exports map declares ./hmac-signature -> dist/hmac-signature.{js,d.ts}", () => {
    expect(PKG.exports["./hmac-signature"]).toEqual({
      types: "./dist/hmac-signature.d.ts",
      import: "./dist/hmac-signature.js",
    });
  });

  it("a narrow import bundles 0 @clerk modules and no node:crypto", async () => {
    const narrow = await bundle("@vantageos/cloud-identity/hmac-signature");
    expect(narrow.inputs.filter((i) => i.includes("@clerk"))).toEqual([]);
    expect(narrow.code).not.toMatch(/node:crypto/);
  });

  it("the root and the subpath hand out the SAME function", async () => {
    const rootMod = await import("../dist/index.js");
    const narrowMod = await import("../dist/hmac-signature.js");
    expect(typeof narrowMod.verifyHmacSha256Signature).toBe("function");
    expect(narrowMod.verifyHmacSha256Signature).toBe(rootMod.verifyHmacSha256Signature);
  });
});
