import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { build } from "esbuild";
import { beforeAll, describe, expect, it } from "vitest";

/**
 * `requireTenantId` must be importable WITHOUT the root index. The root
 * re-exports `clerk-handshake`, which pulls `@clerk/backend` (a runtime
 * dependency since the Clerk handshake landed); a Convex function bundle that
 * imports only the tenant guard from the root ships 33 Clerk modules it never
 * calls. The fix is a narrow subpath, `./org-guard`, whose module graph stops
 * at `tenancy-domain` (types only). Measured, not assumed: both bundles are
 * built here with esbuild from the published `exports` map.
 */

const REPO_ROOT = resolve(__dirname, "..");
const PKG = JSON.parse(readFileSync(resolve(REPO_ROOT, "package.json"), "utf-8"));

async function bundle(spec: string) {
	const r = await build({
		stdin: {
			contents: `import { requireTenantId } from "${spec}"; export const f = requireTenantId;`,
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
	const inputs = Object.keys(r.metafile.inputs);
	return {
		bytes: r.outputFiles[0].contents.length,
		clerk: inputs.filter((i) => i.includes("@clerk")),
		inputs,
	};
}

beforeAll(() => {
	if (!existsSync(resolve(REPO_ROOT, "dist/org-guard.js"))) {
		execSync("npx tsc", { cwd: REPO_ROOT, stdio: "ignore" });
	}
});

describe("./org-guard subpath", () => {
	it("the exports map declares ./org-guard -> dist/org-guard.{js,d.ts}", () => {
		expect(PKG.exports["./org-guard"]).toEqual({
			types: "./dist/org-guard.d.ts",
			import: "./dist/org-guard.js",
		});
	});

	it("a narrow import of requireTenantId bundles no @clerk module", async () => {
		const narrow = await bundle("@vantageos/cloud-identity/org-guard");
		expect(narrow.clerk).toEqual([]);
		expect(narrow.inputs.every((i) => !/clerk-handshake/.test(i))).toBe(true);
	});

	it("the root import still resolves (no consumer breaks) and is the costly path the subpath avoids", async () => {
		const root = await bundle("@vantageos/cloud-identity");
		const narrow = await bundle("@vantageos/cloud-identity/org-guard");
		expect(root.clerk.length).toBeGreaterThan(0);
		expect(narrow.bytes).toBeLessThan(root.bytes);
	});

	it("both paths hand out the SAME function (behaviour unchanged)", async () => {
		const rootMod = await import("../dist/index.js");
		const narrowMod = await import("../dist/org-guard.js");
		expect(narrowMod.requireTenantId).toBe(rootMod.requireTenantId);
	});
});
